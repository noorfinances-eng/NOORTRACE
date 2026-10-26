// Famille annuaire/ des vecteurs de CT-3 (spec/CT-3-approbations.md, révision
// 0.3, annexe A.10, vérifications AN-1 à AN-10), appelée par
// scripts/vecteurs/generer-ct3.mjs.
//
// Les attendus sont posés par conception (sort, raison, entrée de chaque cas)
// et confrontés à la bibliothèque de la console de référence
// scripts/lib/console.mjs ; les textes, les condensés EIP-191 et les
// signatures sont calculés par ethers et scripts/lib/journal.mjs,
// indépendamment de console.mjs, puis confrontés à elle. Un écart arrête la
// génération. Les signatures sont celles des comptes de test de A.2 (RFC
// 6979) ; les formes non canoniques en sont dérivées sans clé.

import { Signature, getBytes, hashMessage, keccak256, recoverAddress, toUtf8Bytes } from "ethers";
import * as J from "../../lib/journal.mjs";
import * as K from "../../lib/console.mjs";

/** Constantes propres à la famille (A.10), écrites dans INDEX.md et dans les fichiers, pas dans constantes.json. */
export const ORIGINE = "https://console.assureur-demo.example";
export const EMETTEUR = "https://idp.assureur-demo.example";
export const ID = (nom) => `oidc ${EMETTEUR} ${nom}`;
export const ADMIN = ID("admin-1");
export const INSTANT_BASE_ANNUAIRE = "2026-11-10T08:00:00.000Z";
export const TTL_INSCRIPTION = 600000;
export const ETIQUETTE_NONCE = "noortrace/vecteurs/ct3/inscription/nonce/<k>";
export const NONCE = (k) => J.sha256(Buffer.from(`noortrace/vecteurs/ct3/inscription/nonce/${k}`, "utf8")).slice(2, 34);
const D = (hms) => `2026-11-10T${hms}Z`;
const plus = (ts, ms) => J.horodatage(J.msHorodatage(ts) + ms);
const N_SECP = K.N_SECP256K1;
const copie = (v) => JSON.parse(JSON.stringify(v));

/** Identités de la famille : approbateur-<n> détient le compte n (1, 2, 4), u.martin le compte 3. */
export const IDENTITE_COMPTE = { 1: ID("approbateur-1"), 2: ID("approbateur-2"), 3: ID("u.martin"), 4: ID("approbateur-4") };

export function familleAnnuaire(ctx) {
  const { COMPTES, ADR, ORG, ORG_ID, exiger, schemas, valider, DEMANDEUR, JOURNAL_ID, DEMANDE, MD } = ctx;
  const sigTexte = (compte, texte) => Signature.from(COMPTES[compte].signingKey.sign(hashMessage(toUtf8Bytes(texte)))).serialized;
  const sHaut = (sig) => sig.slice(0, 66) + (N_SECP - BigInt("0x" + sig.slice(66, 130))).toString(16).padStart(64, "0") + (sig.slice(130) === "1b" ? "1c" : "1b");
  const v01 = (sig) => sig.slice(0, 130) + (sig.slice(130) === "1b" ? "00" : "01");
  const champs = ({ identite, compte, adresse = ADR(compte), emis, k, origin = ORIGINE, org = ORG, org_id = ORG_ID }) => ({ origin, org, org_id, identity: identite, address: adresse, issued_at: emis, expires_at: plus(emis, TTL_INSCRIPTION), nonce: NONCE(k) });
  /** Texte d'EX-13.12, écrit ici sans console.mjs, puis confronté à messageInscription. */
  const texte = (f) => {
    const t = ["noortrace/inscription/v0", "Je lie cette adresse a mon identite pour approuver dans NOORTRACE. Ce message n'est pas un vote.", `Origine: ${f.origin}`, `Organisation: ${f.org}`, `Identifiant d'organisation: ${f.org_id}`, `Identite: ${f.identity}`, `Adresse: ${f.address}`, `Emis le: ${f.issued_at}`, `Expire le: ${f.expires_at}`, `Nonce: ${f.nonce}`].join("\n");
    exiger(K.messageInscription(f) === t, "messageInscription diffère du texte d'EX-13.12");
    return t;
  };
  /** Recouvrement par ethers d'une signature canonique sur un texte. */
  const recouvreTexte = (t, sig) => recoverAddress(hashMessage(toUtf8Bytes(t)), sig).toLowerCase();

  // -------------------------------------------------------------------------
  // Service simulé : appliquerOperation de console.mjs, nonces fixés.
  // -------------------------------------------------------------------------
  const vide = { version: 0, org: ORG, org_id: ORG_ID, console_origin: ORIGINE, registration_ttl_ms: TTL_INSCRIPTION, administrators: [ADMIN], revision: 0, updated_at: null, entries: [], operations: [] };
  exiger(valider(vide, "annuaire-approbateurs", null).length === 0, "annuaire vide non conforme");

  /**
   * Rejoue une suite de pas de conception sur un annuaire. Chaque pas :
   * { method, at, request (objet, ou fonction de l'état qui le rend), k
   * (nonce de preparer_inscription), reason (null si accepté par conception),
   * sign: compte (pour inscrire : signe le dernier défi préparé) }.
   */
  function rejouer(initial, pas) {
    let etat = { annuaire: copie(initial), defis: [] };
    let dernierMessage = null;
    const steps = [];
    for (const p of pas) {
      let request = typeof p.request === "function" ? p.request({ dernierMessage, etat }) : copie(p.request);
      const r = K.appliquerOperation(etat.annuaire, p.method, request, p.at, { defis: etat.defis, nonce: p.k === undefined ? null : NONCE(p.k), identifiant: "compteur" });
      exiger(r.accepted === (p.reason === null) && r.reason === p.reason, `pas ${p.method} ${p.at} : ${r.reason ?? "accepté"}, conception ${p.reason ?? "accepté"}`);
      if (p.method === "preparer_inscription" && r.accepted) {
        exiger(r.response.message === texte(r.response.fields), "texte du défi");
        dernierMessage = r.response.message;
      }
      if (p.method === "inscrire" && r.accepted) exiger(r.annuaire.entries.some((e) => e.addresses.some((a) => a.address === request.address && a.proof.message === request.message)), "preuve inscrite");
      etat = { annuaire: r.annuaire, defis: r.defis };
      steps.push({ method: p.method, at: p.at, request, challenges: p.method === "preparer_inscription" && p.k !== undefined ? [NONCE(p.k)] : [], expected: { accepted: r.accepted, reason: r.reason, response: r.response, revision: r.annuaire.revision, entries: K.resumeEntrees(r.annuaire) } });
    }
    return { annuaire: etat.annuaire, defis: etat.defis, steps };
  }
  /** Pas d'inscription : préparation puis inscription signée par le compte. */
  const inscription = (identite, compte, emis, k, { recu = plus(emis, 30000), reasonPrep = null, reason = null, signataire = compte } = {}) => {
    const out = [{ method: "preparer_inscription", at: emis, request: { session_identity: identite, address: ADR(compte) }, k, reason: reasonPrep }];
    if (reasonPrep === null) out.push({ method: "inscrire", at: recu, request: ({ dernierMessage }) => ({ session_identity: identite, address: ADR(compte), message: dernierMessage, signature: sigTexte(signataire, dernierMessage) }), reason });
    return out;
  };
  const valid = (entry, compte, at, by = ADMIN, reason = null) => ({ method: "valider", at, request: { session_identity: by, entry, address: ADR(compte) }, reason });
  const revoq = (entry, compte, at, by = ADMIN, motif = null, reason = null) => ({ method: "revoquer", at, request: { session_identity: by, entry, address: ADR(compte), reason: motif }, reason });
  const desact = (entry, at, by = ADMIN, motif = null, reason = null) => ({ method: "desactiver", at, request: { session_identity: by, entry, reason: motif }, reason });
  const react = (entry, at, by = ADMIN, motif = null, reason = null) => ({ method: "reactiver", at, request: { session_identity: by, entry, reason: motif }, reason });
  const lier = (entry, launched_by, at, by = ADMIN, reason = null, methode = "lier_demandeur") => ({ method: methode, at, request: { session_identity: by, entry, launched_by }, reason });

  // -------------------------------------------------------------------------
  // annuaires/ : vide, référence (exemple de 13.4), départs des cas
  // -------------------------------------------------------------------------
  const PAS_REFERENCE = [
    ...inscription(IDENTITE_COMPTE[1], 1, D("08:00:00.000"), 1),
    valid("apb-0001", 1, D("08:30:00.000")),
    ...inscription(IDENTITE_COMPTE[2], 2, D("09:00:00.000"), 2),
    ...inscription(IDENTITE_COMPTE[2], 4, D("09:20:00.000"), 4),
    valid("apb-0002", 2, D("09:40:00.000")),
    revoq("apb-0002", 4, D("09:41:00.000"), ADMIN, "Adresse non membre du jeu de l'organisation"),
    ...inscription(IDENTITE_COMPTE[3], 3, D("10:00:00.000"), 3),
    lier("apb-0003", DEMANDEUR, D("10:20:00.000")),
    valid("apb-0003", 3, D("10:30:00.000")),
  ];
  const ref = rejouer(vide, PAS_REFERENCE);
  // Les noms affichés sont des données du client, sans effet (EX-13.9) : posés après le rejeu.
  const reference = copie(ref.annuaire);
  reference.entries[0].display_name = "Approbateur 1";
  reference.entries[1].display_name = "Approbateur 2";
  reference.entries[2].display_name = "U. Martin";
  exiger(valider(reference, "annuaire-approbateurs", null).length === 0, "annuaire de référence non conforme");
  const exemple = /<!-- schema: annuaire-approbateurs -->\n```json\n([\s\S]*?)\n```/.exec(MD);
  exiger(exemple && J.egalJSON(JSON.parse(exemple[1]), reference), "annuaires/reference.json diffère de l'exemple de CT-3 13.4");
  const conforme = (doc) => valider(doc, "annuaire-approbateurs", null).length === 0;
  exiger(K.verifierAnnuaireExporte(reference, { conforme }).length === 0, "l'annuaire de référence a des écarts d'export");
  for (const e of reference.entries) for (const a of e.addresses) exiger(recouvreTexte(a.proof.message, a.proof.signature) === a.address, `preuve de ${a.address}`);

  // Départ des cas d'inscription : comptes 1 et 2 de la référence, compte 4 révoqué, puis entrée apb-0002 désactivée.
  const PAS_AVANT_INSCRIPTIONS = [...PAS_REFERENCE.slice(0, 8), desact("apb-0002", D("10:40:00.000"), ADMIN, "Départ de la personne")];
  const avantInscriptions = rejouer(vide, PAS_AVANT_INSCRIPTIONS).annuaire;
  // Départ des contrôles de vote : la référence, puis apb-0002 désactivée.
  const controles = rejouer(reference, [desact("apb-0002", D("10:40:00.000"), ADMIN, "Départ de la personne")]).annuaire;
  const annuaires = { "vide.json": vide, "reference.json": reference, "avant-inscriptions.json": avantInscriptions, "controles.json": controles };
  const descriptionsAnnuaires = {
    "vide.json": "Annuaire sans entrée ; administrateur admin-1.",
    "reference.json": "L'annuaire d'exemple de CT-3 13.4 : neuf opérations, comptes 1, 2 et 3 actifs, compte 4 révoqué dans l'entrée apb-0002, alias de demandeur lié à apb-0003.",
    "avant-inscriptions.json": "Les huit premières opérations de la référence (comptes 1 et 2 actifs, compte 4 révoqué), puis la désactivation d'apb-0002 : départ des cas d'inscriptions.json.",
    "controles.json": "La référence, puis la désactivation d'apb-0002 : départ des cas de controles-vote.json.",
  };
  for (const [f, a] of Object.entries(annuaires)) exiger(valider(a, "annuaire-approbateurs", null).length === 0, `annuaires/${f} non conforme`);

  // -------------------------------------------------------------------------
  // messages.json (AN-1, AN-2)
  // -------------------------------------------------------------------------
  const preuveDe = (compte) => reference.entries.flatMap((e) => e.addresses).find((a) => a.address === ADR(compte)).proof;
  const champsPreuve = (compte, identite) => ({ origin: ORIGINE, org: ORG, org_id: ORG_ID, identity: identite, address: ADR(compte), issued_at: preuveDe(compte).issued_at, expires_at: preuveDe(compte).expires_at, nonce: preuveDe(compte).nonce });
  const M1 = preuveDe(1).message;
  const lignes = M1.split("\n");
  const avecLigne = (i, l) => lignes.map((x, j) => (j === i ? l : x)).join("\n");
  const mesures = (t) => {
    const o = Buffer.from(t, "utf8");
    const m = { length: o.length, personal_sign_data: J.hex(o), eip191_digest: hashMessage(o), preimage_length: 1 + 25 + String(o.length).length + o.length };
    exiger(J.egalJSON(m, K.mesuresMessage(t)), "mesures d'un message");
    return m;
  };
  const casMessages = [];
  for (const compte of [1, 2, 3, 4]) {
    const identite = compte === 4 ? IDENTITE_COMPTE[2] : IDENTITE_COMPTE[compte];
    const f = champsPreuve(compte, identite);
    const t = texte(f);
    exiger(t === preuveDe(compte).message, `message du compte ${compte}`);
    exiger(J.egalJSON(K.analyserMessageInscription(t), f), "analyse d'un message valide");
    casMessages.push({ id: `message-compte-${compte}`, description: `Message d'inscription du compte ${compte} de l'annuaire de référence, construit depuis ses champs : texte exact, octets passés à personal_sign, condensé EIP-191 et longueur de la préimage.`, checks: ["AN-1", "AN-2"], fields: f, message: t, expected: { valid: true, ...mesures(t), fields: f } });
  }
  exiger(casMessages[0].expected.length === 516 && casMessages[0].expected.preimage_length === 545 && casMessages[0].expected.eip191_digest === "0xaf9b14a62489fc34643813436d932180470bbfa1cb197aea3de5fe54f871c5ef", "valeurs de l'exemple d'EX-13.12");
  const mauvais = [
    ["crlf", "Lignes séparées par CR LF au lieu de LF.", M1.replace(/\n/g, "\r\n")],
    ["lf-final", "Un LF final après la ligne du nonce.", M1 + "\n"],
    ["onze-lignes", "Une onzième ligne après la ligne du nonce.", M1 + "\nNote: rien"],
    ["premiere-ligne", "Première ligne changée d'un caractère (v1 au lieu de v0).", avecLigne(0, "noortrace/inscription/v1")],
    ["deuxieme-ligne", "Deuxième ligne changée d'un caractère (point final remplacé par un point d'exclamation).", avecLigne(1, lignes[1].slice(0, -1) + "!")],
    ["cle-en-minuscules", "Clé « origine: » en minuscules.", avecLigne(2, lignes[2].replace("Origine: ", "origine: "))],
    ["double-espace", "Deux espaces après « Origine: ».", avecLigne(2, lignes[2].replace("Origine: ", "Origine:  "))],
    ["caractere-accentue", "« Identité » accentué au lieu de « Identite » (octet non ASCII).", avecLigne(5, lignes[5].replace("Identite: ", "Identité: "))],
    ["adresse-eip55", "Adresse en casse EIP-55 au lieu de minuscules.", avecLigne(6, "Adresse: 0x70997970C51812dc3A010C7d01b50e0d17dc79C8")],
    ["nonce-31-chiffres", "Nonce de 31 chiffres.", avecLigne(9, lignes[9].slice(0, -1))],
    ["nonce-33-chiffres", "Nonce de 33 chiffres.", avecLigne(9, lignes[9] + "0")],
    ["instant-sans-millisecondes", "Instant d'émission sans millisecondes.", avecLigne(7, "Emis le: 2026-11-10T08:00:00Z")],
    ["identite-quatre-jetons", "Identité de quatre jetons (une espace de plus dans le sujet).", avecLigne(5, `Identite: ${IDENTITE_COMPTE[1]} bis`)],
    ["identite-courriel", "Identité qui n'est pas canonique : un courriel au lieu de « oidc <iss> <sub> ».", avecLigne(5, "Identite: approbateur-1@assureur-demo.example")],
    ["emetteur-avec-requete", "Émetteur avec « ? » : interdit dans <iss> (EX-13.7).", avecLigne(5, `Identite: oidc ${EMETTEUR}?x=1 approbateur-1`)],
  ];
  for (const [id, description, t] of mauvais) {
    let refuse = false;
    try {
      K.analyserMessageInscription(t);
    } catch (e) {
      refuse = e.code === "message_invalide";
    }
    exiger(refuse, `message ${id} accepté`);
    casMessages.push({ id, description: `${description} Refusé (message_invalide).`, checks: id.startsWith("identite") || id === "emetteur-avec-requete" ? ["AN-1", "AN-2"] : ["AN-2"], fields: null, message: t, expected: { valid: false, ...mesures(t), fields: null } });
  }
  const messages = { version: 0, cases: casMessages };
  exiger(valider(messages, "annuaire-approbateurs", "fichier_messages").length === 0, "messages.json non conforme");

  // -------------------------------------------------------------------------
  // inscriptions.json (AN-3, AN-4, AN-5, AN-7)
  // -------------------------------------------------------------------------
  const E0 = D("11:00:00.000");
  const R0 = D("11:00:30.000");
  const casInscriptions = [];
  let kSuivant = 5;
  /**
   * Un cas : `def` donne les champs du défi, `msg` ceux du message (par défaut
   * ceux du défi), `signataire` le compte qui signe, `forme` la transformation
   * de la signature, `requete` des changements de la requête.
   */
  function casInscription(id, description, checks, { identite, compte, defi = {}, msg = null, signataire = compte, forme = (s) => s, requete = {}, recu = R0, defis = null, used = false, texteFinal = null, reason, entry = null, presente = !["requete_invalide", "identite_invalide", "message_invalide", "nonce_inconnu", "nonce_deja_utilise"].includes(reason) }) {
    const k = kSuivant++;
    const fDefi = champs({ identite, compte, emis: E0, k, ...defi });
    const fMsg = msg ? { ...fDefi, ...msg } : fDefi;
    let t = texte(fMsg);
    if (texteFinal) t = texteFinal(t);
    const sigCanonique = sigTexte(signataire, t);
    const request = { session_identity: identite, address: ADR(compte), message: t, signature: forme(sigCanonique), ...requete };
    const challenges = defis ? defis(fDefi) : [{ fields: fDefi, used }];
    const r = K.verifierInscription(avantInscriptions, challenges, request, recu, { identifiant: "compteur" });
    const attendu = { accepted: reason === null, reason, entry: reason === null ? entry : null, signature: reason === null ? sigCanonique : null };
    exiger(J.egalJSON({ accepted: r.accepted, reason: r.reason, entry: r.entry, signature: r.signature }, attendu), `inscription ${id} : ${JSON.stringify(r)}, conception ${JSON.stringify(attendu)}`);
    if (reason === null) exiger(recouvreTexte(t, sigCanonique) === ADR(compte), `inscription ${id} : recouvrement par ethers`);
    // Le défi est marqué présenté dès le pas 4 (EX-13.15) : défi connu, non présenté, message bien formé.
    exiger(r.defis.some((d) => d.used && d.fields.nonce === fMsg.nonce) === (presente || used), `inscription ${id} : défi présenté`);
    casInscriptions.push({ id, description, checks, challenges, received_at: recu, request, expected: attendu });
  }
  const U = IDENTITE_COMPTE[3];
  const A1 = IDENTITE_COMPTE[1];
  const A2 = IDENTITE_COMPTE[2];
  const ORIGINE_AUTRE = "https://console.autre-demo.example";
  const ORG_AUTRE = { org: "autre-demo", org_id: keccak256(toUtf8Bytes("autre-demo")) };
  const crlf = (t) => t.replace(/\n/g, "\r\n");
  casInscription("cree-entree", "u.martin inscrit le compte 3 : acceptée, l'entrée apb-0003 est créée.", ["AN-3", "AN-4", "AN-7"], { identite: U, compte: 3, reason: null, entry: "apb-0003" });
  casInscription("complete-entree", "approbateur-1 inscrit le compte 3 : acceptée, l'adresse s'ajoute à l'entrée apb-0001, en attente.", ["AN-3", "AN-7"], { identite: A1, compte: 3, reason: null, entry: "apb-0001" });
  casInscription("s-haut", "Signature rendue avec s dans la moitié haute et v inversé : acceptée et gardée normalisée.", ["AN-4"], { identite: U, compte: 3, forme: sHaut, reason: null, entry: "apb-0003" });
  casInscription("v-0-ou-1", "Signature rendue avec v = 0 ou 1 : acceptée et gardée avec v = 27 ou 28.", ["AN-4"], { identite: U, compte: 3, forme: v01, reason: null, entry: "apb-0003" });
  casInscription("reception-a-emis-le", "Réception exactement à « Emis le » : acceptée (Emis le ≤ r).", ["AN-3"], { identite: U, compte: 3, recu: E0, reason: null, entry: "apb-0003" });
  casInscription("identite-invalide", "Identité de session qui n'est pas canonique (un courriel) : identite_invalide.", ["AN-1", "AN-3"], { identite: U, compte: 3, requete: { session_identity: DEMANDEUR }, reason: "identite_invalide" });
  casInscription("message-crlf", "Message aux lignes séparées par CR LF : message_invalide, le défi n'est pas présenté.", ["AN-2", "AN-3"], { identite: U, compte: 3, texteFinal: crlf, reason: "message_invalide" });
  casInscription("defi-remplace", "Un nouveau défi pour la même identité et la même adresse a remplacé celui du message : nonce_inconnu.", ["AN-3"], { identite: U, compte: 3, defis: (f) => [{ fields: { ...f, nonce: NONCE(99), issued_at: plus(E0, 60000), expires_at: plus(E0, 60000 + TTL_INSCRIPTION) }, used: false }], reason: "nonce_inconnu" });
  casInscription("nonce-deja-presente", "Défi déjà présenté une fois : nonce_deja_utilise.", ["AN-3"], { identite: U, compte: 3, used: true, reason: "nonce_deja_utilise" });
  casInscription("reception-a-expire-le", "Réception exactement à « Expire le » : inscription_expiree (r < Expire le exigé).", ["AN-3"], { identite: U, compte: 3, recu: plus(E0, TTL_INSCRIPTION), reason: "inscription_expiree" });
  casInscription("origine-differente", "Défi et message d'une autre origine que console_origin : origine_differente.", ["AN-3"], { identite: U, compte: 3, defi: { origin: ORIGINE_AUTRE }, reason: "origine_differente" });
  casInscription("organisation-differente", "Défi et message d'une autre organisation : organisation_differente.", ["AN-3"], { identite: U, compte: 3, defi: ORG_AUTRE, reason: "organisation_differente" });
  casInscription("identite-differente", "Message et défi au nom d'approbateur-1, requête de la session u.martin : identite_differente.", ["AN-3"], { identite: A1, compte: 3, requete: { session_identity: U }, reason: "identite_differente" });
  casInscription("adresse-differente", "Message et défi pour le compte 3, requête pour le compte 1 : adresse_differente.", ["AN-3"], { identite: U, compte: 3, requete: { address: ADR(1) }, reason: "adresse_differente" });
  casInscription("message-different-du-defi", "Message dont « Expire le » précède d'une minute celui du défi : message_invalide au pas 10.", ["AN-3"], { identite: U, compte: 3, msg: { expires_at: plus(E0, TTL_INSCRIPTION - 60000) }, reason: "message_invalide", presente: true });
  casInscription("autre-cle", "Message pour le compte 3 signé par la clé du compte 2 : signature_invalide.", ["AN-4"], { identite: U, compte: 3, signataire: 2, reason: "signature_invalide" });
  casInscription("v-29", "Signature de v = 29 : signature_invalide.", ["AN-4"], { identite: U, compte: 3, forme: (s) => s.slice(0, 130) + "1d", reason: "signature_invalide" });
  casInscription("v-37", "Signature de v = 37 (forme EIP-155) : signature_invalide.", ["AN-4"], { identite: U, compte: 3, forme: (s) => s.slice(0, 130) + (s.endsWith("1b") ? "25" : "26"), reason: "signature_invalide" });
  casInscription("longueur-64", "Signature compacte de 64 octets (EIP-2098) : signature_invalide.", ["AN-4"], { identite: U, compte: 3, forme: (s) => s.slice(0, 130), reason: "signature_invalide" });
  casInscription("identite-desactivee", "approbateur-2, dont l'entrée est désactivée, inscrit le compte 3 : identite_desactivee.", ["AN-3", "AN-7"], { identite: A2, compte: 3, reason: "identite_desactivee" });
  casInscription("adresse-deja-attribuee", "u.martin inscrit le compte 4, révoqué dans l'entrée apb-0002 : adresse_deja_attribuee (jamais réattribuée).", ["AN-3", "AN-7"], { identite: U, compte: 4, reason: "adresse_deja_attribuee" });
  // Paires de raisons voisines : la première dans l'ordre d'EX-13.15.
  casInscription("ordre-identite-message", "Identité non canonique et message en CR LF : identite_invalide d'abord.", ["AN-3"], { identite: U, compte: 3, requete: { session_identity: DEMANDEUR }, texteFinal: crlf, reason: "identite_invalide" });
  casInscription("ordre-message-nonce", "Message en CR LF et défi inconnu : message_invalide d'abord.", ["AN-3"], { identite: U, compte: 3, texteFinal: crlf, defis: () => [], reason: "message_invalide" });
  casInscription("ordre-nonce-expiration", "Défi inconnu et réception après l'expiration : nonce_inconnu d'abord.", ["AN-3"], { identite: U, compte: 3, defis: () => [], recu: plus(E0, TTL_INSCRIPTION + 1000), reason: "nonce_inconnu" });
  casInscription("ordre-presente-expiration", "Défi déjà présenté et réception après l'expiration : nonce_deja_utilise d'abord.", ["AN-3"], { identite: U, compte: 3, used: true, recu: plus(E0, TTL_INSCRIPTION + 1000), reason: "nonce_deja_utilise" });
  casInscription("ordre-expiration-origine", "Réception après l'expiration et autre origine : inscription_expiree d'abord ; le défi est présenté.", ["AN-3"], { identite: U, compte: 3, defi: { origin: ORIGINE_AUTRE }, recu: plus(E0, TTL_INSCRIPTION + 1000), reason: "inscription_expiree" });
  casInscription("ordre-origine-organisation", "Autre origine et autre organisation : origine_differente d'abord.", ["AN-3"], { identite: U, compte: 3, defi: { origin: ORIGINE_AUTRE, ...ORG_AUTRE }, reason: "origine_differente" });
  casInscription("ordre-organisation-identite", "Autre organisation et identité différente de la session : organisation_differente d'abord.", ["AN-3"], { identite: A1, compte: 3, defi: ORG_AUTRE, requete: { session_identity: U }, reason: "organisation_differente" });
  casInscription("ordre-identite-adresse", "Identité et adresse différentes de la requête : identite_differente d'abord.", ["AN-3"], { identite: A1, compte: 3, requete: { session_identity: U, address: ADR(1) }, reason: "identite_differente" });
  casInscription("ordre-adresse-message", "Adresse différente de la requête et message différent du défi : adresse_differente d'abord.", ["AN-3"], { identite: U, compte: 3, msg: { expires_at: plus(E0, TTL_INSCRIPTION - 60000) }, requete: { address: ADR(1) }, reason: "adresse_differente" });
  casInscription("ordre-message-signature", "Message différent du défi et signé par une autre clé : message_invalide d'abord.", ["AN-3"], { identite: U, compte: 3, msg: { expires_at: plus(E0, TTL_INSCRIPTION - 60000) }, signataire: 2, reason: "message_invalide", presente: true });
  casInscription("ordre-signature-desactivee", "Entrée désactivée et signature d'une autre clé : signature_invalide d'abord.", ["AN-3", "AN-4"], { identite: A2, compte: 3, signataire: 1, reason: "signature_invalide" });
  casInscription("ordre-desactivee-attribuee", "approbateur-2, entrée désactivée, inscrit le compte 4 déjà attribué : identite_desactivee d'abord.", ["AN-3", "AN-7"], { identite: A2, compte: 4, reason: "identite_desactivee" });
  const inscriptions = { version: 0, annuaire: "annuaires/avant-inscriptions.json", cases: casInscriptions };
  exiger(valider(inscriptions, "annuaire-approbateurs", "fichier_inscriptions").length === 0, `inscriptions.json non conforme : ${JSON.stringify(valider(inscriptions, "annuaire-approbateurs", "fichier_inscriptions").slice(0, 3))}`);
  // requete_invalide n'a pas de cas ici : une requête hors de requete_inscrire ne serait pas conforme à
  // $defs/fichier_inscriptions ; elle est exercée par la trace inscription-validation.
  for (const reason of ["identite_invalide", "message_invalide", "nonce_inconnu", "nonce_deja_utilise", "inscription_expiree", "origine_differente", "organisation_differente", "identite_differente", "adresse_differente", "signature_invalide", "identite_desactivee", "adresse_deja_attribuee"]) exiger(casInscriptions.some((c) => c.expected.reason === reason), `EX-A.13 : raison ${reason} sans cas`);

  // -------------------------------------------------------------------------
  // domaines.json (AN-5)
  // -------------------------------------------------------------------------
  const A0001 = { decision: "approuve", journal_id: JOURNAL_ID, org_id: ORG_ID, request_hash: DEMANDE(1), ticket: "apr-0001" };
  exiger(A0001.request_hash === "0x16a40a774991992347027ea9832fc2398743b19295fe6a80fbaee8d4c529ff16", "request_hash d'apr-0001");
  const sigVote = J.signerApprobation(COMPTES[1], J.objetApprobation(A0001));
  exiger(sigVote === "0x510f909a9e8a699a0a2a43669f38861ff8b1c8defaddd8b6fd7850b182eba5fb64fd39e4bd5ff45ef2ed0e5f0b458996a58cbb74c2cd5dd4685e23d5234eee591c", "signature du vote du compte 1 sur apr-0001");
  const sigInscription = preuveDe(1).signature;
  const recInsVote = recoverAddress(J.condenseEIP191Approbation(J.objetApprobation(A0001)), sigInscription).toLowerCase();
  const recVoteIns = recouvreTexte(M1, sigVote);
  exiger(recInsVote === "0xfac296ad1fc770d69ff4d1f69b67efbba7ae46f9" && recVoteIns === "0x8768051a828bb4301030920c9b69759b08e64bde", "adresses recouvrées d'EX-13.16");
  exiger(K.verifierSignature(getBytes(K.condenses(A0001).d_a), sigInscription, ADR(1)).recovered === recInsVote && K.verifierSignature(K.utf8(M1), sigVote, ADR(1)).recovered === recVoteIns, "console.mjs : domaines");
  const domaines = {
    version: 0,
    cases: [
      { id: "inscription-comme-vote", description: "La signature d'inscription du compte 1 (exemple d'EX-13.12) présentée comme vote approuve sur l'objet A d'apr-0001 : elle recouvre une autre adresse que le compte 1 (signature_invalide).", checks: ["AN-5"], kind: "inscription_comme_vote", A: A0001, message: null, signature: sigInscription, claimed_address: ADR(1), expected: { recovered: recInsVote, reason: "signature_invalide" } },
      { id: "vote-comme-inscription", description: "La signature du vote approuve du compte 1 sur apr-0001 (trace approuve-sans-contestation) présentée comme inscription sur le message d'exemple : elle recouvre une autre adresse (signature_invalide).", checks: ["AN-5"], kind: "vote_comme_inscription", A: null, message: M1, signature: sigVote, claimed_address: ADR(1), expected: { recovered: recVoteIns, reason: "signature_invalide" } },
    ],
  };
  exiger(valider(domaines, "annuaire-approbateurs", "fichier_domaines").length === 0, "domaines.json non conforme");

  // -------------------------------------------------------------------------
  // traces/ (AN-6, AN-7)
  // -------------------------------------------------------------------------
  const T = (hms) => `2026-11-10T${hms}Z`;
  const conceptionTraces = [
    ["annuaire-de-reference", "Les neuf opérations de l'annuaire d'exemple de 13.4, depuis l'annuaire vide, avec la préparation de chaque défi : l'état final est annuaires/reference.json (noms affichés mis à part).", ["AN-3", "AN-6", "AN-7"], "vide.json", PAS_REFERENCE],
    [
      "inscription-validation",
      "Défi, deux requêtes inscrire mal formées (membre inconnu : requete_invalide, avant l'identité non canonique), puis l'inscription et la validation par admin-1 : l'adresse passe d'en_attente à active ; c'est l'état sur lequel controles-vote.json autorise un vote.",
      ["AN-1", "AN-3", "AN-6"],
      "vide.json",
      [
        { method: "preparer_inscription", at: T("08:00:00.000"), request: { session_identity: A1, address: ADR(1) }, k: 11, reason: null },
        { method: "inscrire", at: T("08:00:10.000"), request: ({ dernierMessage }) => ({ session_identity: A1, address: ADR(1), message: dernierMessage, signature: sigTexte(1, dernierMessage), nonce: NONCE(11) }), reason: "requete_invalide" },
        { method: "inscrire", at: T("08:00:20.000"), request: ({ dernierMessage }) => ({ session_identity: DEMANDEUR, address: ADR(1), message: dernierMessage, signature: sigTexte(1, dernierMessage), nonce: NONCE(11) }), reason: "requete_invalide" },
        { method: "inscrire", at: T("08:00:30.000"), request: ({ dernierMessage }) => ({ session_identity: A1, address: ADR(1), message: dernierMessage, signature: sigTexte(1, dernierMessage) }), reason: null },
        valid("apb-0001", 1, T("08:05:00.000")),
      ],
    ],
    [
      "auto-validation",
      "admin-1 inscrit une adresse pour lui-même et tente de la valider : auto_validation ; approbateur-1, hors d'administrators, tente de la valider : non_administrateur ; un autre administrateur n'existe pas : l'adresse reste en attente.",
      ["AN-6"],
      "vide.json",
      [...inscription(ADMIN, 4, T("08:00:00.000"), 12), valid("apb-0001", 4, T("08:05:00.000"), ADMIN, "auto_validation"), ...inscription(A1, 1, T("08:10:00.000"), 13), valid("apb-0001", 4, T("08:15:00.000"), A1, "non_administrateur")],
    ],
    [
      "rotation",
      "approbateur-1 inscrit une deuxième adresse, validée : la première devient revoquee, cause remplacee, replaced_by la nouvelle ; une entrée n'a jamais deux adresses actives.",
      ["AN-6", "AN-7"],
      "vide.json",
      [...inscription(A1, 1, T("08:00:00.000"), 14), valid("apb-0001", 1, T("08:05:00.000")), ...inscription(A1, 2, T("09:00:00.000"), 15), valid("apb-0001", 2, T("09:05:00.000"))],
    ],
    [
      "revocation",
      "Révocation par un tiers refusée (revocation_non_autorisee), par la personne (cause personne), par un administrateur (cause administrateur), puis révocation répétée (etat_incompatible).",
      ["AN-6"],
      "reference.json",
      [revoq("apb-0001", 1, T("11:00:00.000"), U, null, "revocation_non_autorisee"), revoq("apb-0001", 1, T("11:01:00.000"), A1, "Clé perdue"), revoq("apb-0002", 2, T("11:02:00.000"), ADMIN, "Départ annoncé"), revoq("apb-0001", 1, T("11:03:00.000"), ADMIN, null, "etat_incompatible")],
    ],
    [
      "desactivation",
      "Désactivation d'une entrée : son adresse active est révoquée (cause desactivation), son défi en cours est effacé (nonce_inconnu), une préparation est refusée (identite_desactivee) ; réactivation sans adresse rétablie, puis nouvelle inscription validée ; désactivation et réactivation répétées refusées (etat_incompatible).",
      ["AN-6", "AN-7"],
      "vide.json",
      [
        ...inscription(A1, 1, T("08:00:00.000"), 16),
        valid("apb-0001", 1, T("08:05:00.000")),
        { method: "preparer_inscription", at: T("08:10:00.000"), request: { session_identity: A1, address: ADR(2) }, k: 17, reason: null },
        desact("apb-0001", T("08:11:00.000"), ADMIN, "Absence prolongée"),
        { method: "inscrire", at: T("08:12:00.000"), request: ({ dernierMessage }) => ({ session_identity: A1, address: ADR(2), message: dernierMessage, signature: sigTexte(2, dernierMessage) }), reason: "nonce_inconnu" },
        { method: "preparer_inscription", at: T("08:13:00.000"), request: { session_identity: A1, address: ADR(2) }, k: 18, reason: "identite_desactivee" },
        desact("apb-0001", T("08:14:00.000"), ADMIN, null, "etat_incompatible"),
        react("apb-0001", T("09:00:00.000"), ADMIN, "Retour"),
        react("apb-0001", T("09:01:00.000"), ADMIN, null, "etat_incompatible"),
        ...inscription(A1, 2, T("09:10:00.000"), 19),
        valid("apb-0001", 2, T("09:15:00.000")),
      ],
    ],
    ["adresse-jamais-reattribuee", "Le compte 4, révoqué dans l'entrée apb-0002, préparé par u.martin : adresse_deja_attribuee dès preparer_inscription ; la même adresse préparée par sa propre personne l'est aussi.", ["AN-7"], "reference.json", [{ method: "preparer_inscription", at: T("11:00:00.000"), request: { session_identity: U, address: ADR(4) }, k: 20, reason: "adresse_deja_attribuee" }, { method: "preparer_inscription", at: T("11:01:00.000"), request: { session_identity: A2, address: ADR(4) }, k: 21, reason: "adresse_deja_attribuee" }]],
    [
      "confiscation",
      "approbateur-2 prépare, sous sa propre session, l'inscription du compte 1, dont le détenteur signe sans le lire le texte qui nomme approbateur-2 : acceptée, en attente dans l'entrée apb-0001 d'approbateur-2 (EX-13.15 ne voit que la preuve de possession) ; approbateur-1, détenteur du compte 1, reçoit adresse_deja_attribuee ; admin-1 révoque l'adresse avec un motif ; approbateur-1 reçoit toujours adresse_deja_attribuee : l'adresse est confisquée, son détenteur change de clé (EX-13.10, EX-13.17).",
      ["AN-3", "AN-6", "AN-7"],
      "vide.json",
      [
        ...inscription(A2, 1, T("08:00:00.000"), 40),
        { method: "preparer_inscription", at: T("08:05:00.000"), request: { session_identity: A1, address: ADR(1) }, k: 41, reason: "adresse_deja_attribuee" },
        revoq("apb-0001", 1, T("08:10:00.000"), ADMIN, "Adresse inscrite au nom d'une autre personne (confiscation signalée)"),
        { method: "preparer_inscription", at: T("08:15:00.000"), request: { session_identity: A1, address: ADR(1) }, k: 42, reason: "adresse_deja_attribuee" },
      ],
    ],
    [
      "alias-demandeur",
      "lier_demandeur d'un nouvel alias, double liaison refusée (demandeur_deja_lie), delier_demandeur, valeur inconnue refusée (demandeur_inconnu) ; une identité de session avec « ? » dans l'émetteur est refusée (identite_invalide) ; une entrée inconnue aussi (entree_inconnue).",
      ["AN-1", "AN-6", "AN-7"],
      "reference.json",
      [
        lier("apb-0002", "u.dupont@assureur-demo.example", T("11:00:00.000")),
        lier("apb-0001", DEMANDEUR, T("11:01:00.000"), ADMIN, "demandeur_deja_lie"),
        lier("apb-0003", DEMANDEUR, T("11:02:00.000"), ADMIN, null, "delier_demandeur"),
        lier("apb-0003", "x.inconnu@assureur-demo.example", T("11:03:00.000"), ADMIN, "demandeur_inconnu", "delier_demandeur"),
        lier("apb-0003", DEMANDEUR, T("11:04:00.000"), `oidc ${EMETTEUR}?x=1 admin-1`, "identite_invalide"),
        lier("apb-9999", DEMANDEUR, T("11:05:00.000"), ADMIN, "entree_inconnue"),
      ],
    ],
  ];
  const traces = conceptionTraces.map(([id, description, checks, initial, pas]) => {
    const r = rejouer(annuaires[initial], pas);
    const doc = { version: 0, id, description, checks, initial: `annuaires/${initial}`, steps: r.steps };
    const erreurs = valider(doc, "annuaire-approbateurs", "trace_annuaire");
    exiger(erreurs.length === 0, `trace ${id} non conforme : ${JSON.stringify(erreurs.slice(0, 3))}`);
    if (id === "annuaire-de-reference") exiger(J.egalJSON(r.annuaire.entries.map((e) => ({ ...e, display_name: null })), reference.entries.map((e) => ({ ...e, display_name: null }))) && J.egalJSON(r.annuaire.operations, reference.operations), "trace de référence");
    return doc;
  });
  // Réponses acceptées conformes à console-service-v0.
  const defService = { preparer_inscription: "reponse_preparer_inscription", inscrire: "reponse_adresse", valider: "reponse_adresse", revoquer: "reponse_adresse", desactiver: "reponse_entree", reactiver: "reponse_entree", lier_demandeur: "reponse_entree", delier_demandeur: "reponse_entree" };
  for (const t of traces) for (const s of t.steps) if (s.expected.accepted) exiger(valider(s.expected.response, "console-service", defService[s.method]).length === 0, `trace ${t.id} : réponse ${s.method} non conforme`);

  // -------------------------------------------------------------------------
  // controles-vote.json (AN-8)
  // -------------------------------------------------------------------------
  const M123 = [ADR(1), ADR(2), ADR(3)].sort();
  const ticket = (o = {}) => ({ launched_by: DEMANDEUR, self_approval: "interdite", policy_requester_addresses: [ADR(3)], directory_requester_addresses: [ADR(3)], members: M123, ...o });
  const conceptionControles = [
    ["vote-autorise", "approbateur-1, adresse active compte 1, membre du jeu : vote autorisé.", "voter", A1, 1, ticket(), null],
    ["jeu-non-fige", "Jeu non figé : jeu_non_fige.", "voter", A1, 1, ticket({ members: null }), "jeu_non_fige"],
    ["identite-inconnue", "Identité sans entrée : identite_inconnue.", "voter", ID("approbateur-9"), 1, ticket(), "identite_inconnue"],
    ["identite-desactivee", "approbateur-2, dont l'entrée est désactivée : identite_desactivee.", "voter", A2, 2, ticket(), "identite_desactivee"],
    ["adresse-non-attribuee", "approbateur-1 avec le compte 2, qui n'est pas son adresse active : adresse_non_attribuee.", "voter", A1, 2, ticket(), "adresse_non_attribuee"],
    ["hors-jeu", "approbateur-1, compte 1 hors du jeu figé (comptes 2, 3, 4) : hors_jeu.", "voter", A1, 1, ticket({ members: [ADR(2), ADR(3), ADR(4)].sort() }), "hors_jeu"],
    ["session-du-demandeur", "u.martin, dont l'alias de demandeur est le launched_by du ticket, sous interdite : session_du_demandeur.", "voter", U, 3, ticket(), "session_du_demandeur"],
    ["session-du-demandeur-permise", "Le même vote sous self_approval permise : autorisé.", "voter", U, 3, ticket({ self_approval: "permise" }), null],
    ["ordre-jeu-identite", "Jeu non figé et identité inconnue : jeu_non_fige d'abord.", "voter", ID("approbateur-9"), 1, ticket({ members: null }), "jeu_non_fige"],
    ["ordre-desactivee-adresse", "Entrée désactivée et adresse non attribuée (compte 1) : identite_desactivee d'abord.", "voter", A2, 1, ticket(), "identite_desactivee"],
    ["ordre-adresse-hors-jeu", "Adresse non attribuée (compte 2) et hors du jeu (comptes 1, 3, 4) : adresse_non_attribuee d'abord.", "voter", A1, 2, ticket({ members: [ADR(1), ADR(3), ADR(4)].sort() }), "adresse_non_attribuee"],
    ["ordre-hors-jeu-demandeur", "Session du demandeur, compte 3 hors du jeu (comptes 1, 2, 4) : hors_jeu d'abord.", "voter", U, 3, ticket({ members: [ADR(1), ADR(2), ADR(4)].sort() }), "hors_jeu"],
    ["recusation-adresse-non-attribuee", "Récusation d'approbateur-1 pour le compte 3 : adresse_non_attribuee.", "recuser", A1, 3, ticket(), "adresse_non_attribuee"],
    ["recusation-session-du-demandeur", "Récusation par la session du demandeur, compte 3 membre du jeu : autorisée (la condition 6 ne vaut que pour un vote).", "recuser", U, 3, ticket(), null],
    ["separation-incomplete", "La politique ne déclare aucune adresse pour le demandeur, l'annuaire lui attribue le compte 3 : vote d'approbateur-1 autorisé, avertissement separation_incomplete (compte 3).", "voter", A1, 1, ticket({ policy_requester_addresses: [] }), null],
  ];
  const controlesVote = {
    version: 0,
    annuaire: "annuaires/controles.json",
    cases: conceptionControles.map(([id, description, action, session, compte, tk, reason]) => {
      const r = K.controleVote(controles, session, action, ADR(compte), tk);
      const manquantes = tk.directory_requester_addresses.filter((a) => !tk.policy_requester_addresses.includes(a)).sort();
      const attendu = { allowed: reason === null, reason, warnings: manquantes.length ? [{ code: "separation_incomplete", addresses: manquantes }] : [] };
      exiger(J.egalJSON(r, attendu), `contrôle ${id} : ${JSON.stringify(r)}, conception ${JSON.stringify(attendu)}`);
      return { id, description, checks: ["AN-8"], session_identity: session, action, address: ADR(compte), ticket: tk, expected: attendu };
    }),
  };
  exiger(valider(controlesVote, "annuaire-approbateurs", "fichier_controles_vote").length === 0, "controles-vote.json non conforme");
  for (const reason of ["jeu_non_fige", "identite_inconnue", "identite_desactivee", "adresse_non_attribuee", "hors_jeu", "session_du_demandeur"]) exiger(controlesVote.cases.some((c) => c.expected.reason === reason), `AN-8 : ${reason} sans cas`);

  // -------------------------------------------------------------------------
  // exports/ (AN-9)
  // -------------------------------------------------------------------------
  const variante = (f) => {
    const d = copie(reference);
    f(d);
    return d;
  };
  const p = (i, k) => `/entries/${i}/addresses/${k}`;
  // Recopie d'un nouveau réglage administrators (EX-13.37), puis une opération d'admin-2.
  const ADMIN2 = ID("admin-2");
  const recopie = K.recopierAdministrateurs(reference, [ADMIN, ADMIN2], D("10:35:00.000"));
  exiger(recopie.changed && recopie.annuaire.revision === 10 && J.egalJSON(recopie.annuaire.operations[9], { seq: 10, at: D("10:35:00.000"), op: "changer_administrateurs", by: "configuration", entry: null, address: null, launched_by: null, reason: null, administrators: { before: [ADMIN], after: [ADMIN, ADMIN2] } }), "recopie d'administrators");
  exiger(!K.recopierAdministrateurs(recopie.annuaire, [ADMIN, ADMIN2], D("10:36:00.000")).changed, "recopie d'une liste inchangée");
  const desactivation = K.appliquerOperation(recopie.annuaire, "desactiver", { session_identity: ADMIN2, entry: "apb-0002", reason: "Départ de la personne" }, D("10:40:00.000"));
  exiger(desactivation.accepted && desactivation.annuaire.revision === 11, "désactivation par admin-2");
  const administrateursRecopies = desactivation.annuaire;
  const conceptionExports = [
    ["reference.json", "L'annuaire de référence : aucun écart.", reference, []],
    [
      "preuve-autre-cle.json",
      "La preuve du compte 2 porte la signature, par la clé du compte 1, de son propre message : preuve_invalide ; le rejeu de l'inscription correspondante échoue (opération 3).",
      variante((d) => (d.entries[1].addresses[0].proof.signature = sigTexte(1, d.entries[1].addresses[0].proof.message))),
      [{ code: "preuve_invalide", pointer: `${p(1, 0)}/proof` }, { code: "operations_incoherentes", pointer: "/operations/2" }],
    ],
    [
      "preuve-identite-differente.json",
      "La preuve du compte 2 est un message, signé par le compte 2, au nom d'approbateur-1 : preuve_discordante ; le rejeu de l'inscription échoue (opération 3).",
      variante((d) => {
        const pr = d.entries[1].addresses[0].proof;
        pr.message = texte({ ...K.analyserMessageInscription(pr.message), identity: A1 });
        pr.signature = sigTexte(2, pr.message);
      }),
      [{ code: "preuve_discordante", pointer: `${p(1, 0)}/proof` }, { code: "operations_incoherentes", pointer: "/operations/2" }],
    ],
    [
      "deux-adresses-actives.json",
      "Le compte 4 de l'entrée apb-0002 est marqué actif à côté du compte 2 : deux_adresses_actives ; le rejeu donne un autre état (/entries).",
      variante((d) => Object.assign(d.entries[1].addresses[1], { state: "active", validated_at: D("09:40:00.000"), validated_by: ADMIN, revoked_at: null, revoked_by: null, revocation_cause: null, revocation_reason: null })),
      [{ code: "operations_incoherentes", pointer: "/entries" }, { code: "deux_adresses_actives", pointer: "/entries/1/addresses" }],
    ],
    [
      "adresse-dans-deux-entrees.json",
      "Le compte 1 figure aussi, révoqué, dans l'entrée apb-0003 : adresse_double ; sa preuve y nomme une autre identité (preuve_discordante) ; le rejeu donne un autre état.",
      variante((d) => d.entries[2].addresses.push({ ...copie(d.entries[0].addresses[0]), state: "revoquee", revoked_at: D("10:31:00.000"), revoked_by: ADMIN, revocation_cause: "administrateur", revocation_reason: null })),
      [{ code: "operations_incoherentes", pointer: "/entries" }, { code: "adresse_double", pointer: `${p(2, 1)}/address` }, { code: "preuve_discordante", pointer: `${p(2, 1)}/proof` }],
    ],
    [
      "identite-double.json",
      "L'entrée apb-0003 porte l'identité d'approbateur-1 : identite_double ; sa preuve nomme u.martin (preuve_discordante) ; le rejeu donne un autre état.",
      variante((d) => (d.entries[2].session_identity = A1)),
      [{ code: "operations_incoherentes", pointer: "/entries" }, { code: "preuve_discordante", pointer: `${p(2, 0)}/proof` }, { code: "identite_double", pointer: "/entries/2/session_identity" }],
    ],
    [
      "identifiant-double.json",
      "L'entrée apb-0003 porte l'identifiant apb-0002 : identifiant_double ; l'inscription de l'opération 7 ne trouve plus sa preuve et ne se rejoue pas.",
      variante((d) => (d.entries[2].id = "apb-0002")),
      [{ code: "identifiant_double", pointer: "/entries/2/id" }, { code: "operations_incoherentes", pointer: "/operations/6" }],
    ],
    [
      "auto-validation.json",
      "approbateur-1, ajouté aux administrateurs, a validé sa propre adresse : auto_validation ; l'opération 2 ne se rejoue pas.",
      variante((d) => {
        d.administrators.push(A1);
        d.entries[0].addresses[0].validated_by = A1;
        d.operations[1].by = A1;
      }),
      [{ code: "auto_validation", pointer: `${p(0, 0)}/validated_by` }, { code: "operations_incoherentes", pointer: "/operations/1" }],
    ],
    ["revision-faux.json", "revision vaut 8 pour neuf opérations : revision_incoherente.", variante((d) => (d.revision = 8)), [{ code: "revision_incoherente", pointer: "/revision" }]],
    [
      "operations-non-rejouees.json",
      "L'opération 6 révoque le compte 3 dans l'entrée apb-0002, qui ne l'a pas : elle ne se rejoue pas (adresse inconnue).",
      variante((d) => (d.operations[5].address = ADR(3))),
      [{ code: "operations_incoherentes", pointer: "/operations/5" }],
    ],
    ["schema.json", "Document sans le membre operations : non conforme au schéma, une seule erreur schema.", variante((d) => delete d.operations), [{ code: "schema", pointer: null }]],
    [
      "administrateurs-recopies.json",
      "Le réglage administrators passe de admin-1 à admin-1 et admin-2 : opération 10 changer_administrateurs (by configuration, before et after), puis admin-2 désactive apb-0002 (opération 11) : aucun écart ; le rejeu juge admin-2 administrateur à partir de l'opération 10 (EX-13.37).",
      administrateursRecopies,
      [],
    ],
    [
      "administrateurs-sans-operation.json",
      "administrators vaut admin-2 seul, sans opération changer_administrateurs : le rejeu part de cette liste, et la validation de l'opération 2 par admin-1 ne se rejoue pas.",
      variante((d) => (d.administrators = [ADMIN2])),
      [{ code: "operations_incoherentes", pointer: "/operations/1" }],
    ],
    [
      "administrateurs-differents-du-rejeu.json",
      "administrateurs-recopies.json dont administrators est ramené à admin-1 seul sans nouvelle opération : le rejeu aboutit à admin-1 et admin-2 (/administrators).",
      (() => {
        const d = copie(administrateursRecopies);
        d.administrators = [ADMIN];
        return d;
      })(),
      [{ code: "operations_incoherentes", pointer: "/administrators" }],
    ],
  ];
  const exportsAttendu = { version: 0, cases: [] };
  const fichiersExports = {};
  for (const [file, description, doc, errors] of conceptionExports) {
    const r = K.verifierAnnuaireExporte(doc, { conforme });
    exiger(J.egalJSON(r, errors), `export ${file} : ${JSON.stringify(r)}, conception ${JSON.stringify(errors)}`);
    if (errors[0]?.code !== "schema") exiger(conforme(doc), `export ${file} non conforme au schéma`);
    fichiersExports[file] = doc;
    exportsAttendu.cases.push({ file, description, checks: ["AN-9"], errors });
  }
  exiger(valider(exportsAttendu, "annuaire-approbateurs", "attendu_exports").length === 0, "exports/attendu.json non conforme");
  for (const code of ["schema", "identifiant_double", "revision_incoherente", "operations_incoherentes", "identite_double", "adresse_double", "deux_adresses_actives", "preuve_invalide", "preuve_discordante", "auto_validation"]) exiger(exportsAttendu.cases.some((c) => c.errors.some((e) => e.code === code)), `AN-9 : ${code} sans cas`);
  exiger(exportsAttendu.cases.some((c) => c.errors.length === 0 && fichiersExports[c.file].operations.some((o) => o.op === "changer_administrateurs")), "EX-13.37 : recopie d'administrators sans cas");

  // -------------------------------------------------------------------------
  // controles-canal.json (AN-10) : contrôle de l'identité de session par le
  // service sur le canal de la console (EX-12.14, EX-12.16, EX-12.19)
  // -------------------------------------------------------------------------
  const TICKET_CANAL = "apr-0001";
  const TICKET_INCONNU = "apr-0999";
  const voteCanal = (compte, session, ticket = TICKET_CANAL) => ({ ticket, approver: ADR(compte), decision: "approuve", signature: J.signerApprobation(COMPTES[compte], J.objetApprobation({ ...A0001, ticket })), reason: null, session_identity: session });
  const E12 = [ADR(1), ADR(2)].sort();
  const tkc = (o = {}) => ({ launched_by: DEMANDEUR, eligible: E12, ...o });
  const conceptionCanal = [
    ["consulter-eligible", "approbateur-1, adresse active compte 1, membre éligible du jeu figé : vue servie.", "consulter", { ticket: TICKET_CANAL, session_identity: A1 }, tkc(), null],
    ["consulter-administrateur", "admin-1, dans administrators, sans entrée : vue servie.", "consulter", { ticket: TICKET_CANAL, session_identity: ADMIN }, tkc(), null],
    ["consulter-demandeur", "u.martin, adresse active compte 3 que la politique déclare pour le demandeur (non éligible sous interdite) : session_non_autorisee.", "consulter", { ticket: TICKET_CANAL, session_identity: U }, tkc(), "session_non_autorisee"],
    ["consulter-demandeur-eligible", "u.martin, dont le compte 3 est éligible parce que la politique ne le déclare pas pour le demandeur : vue servie (la console oppose ensuite session_du_demandeur).", "consulter", { ticket: TICKET_CANAL, session_identity: U }, tkc({ eligible: [ADR(1), ADR(2), ADR(3)].sort() }), null],
    ["consulter-entree-desactivee", "approbateur-2, entrée désactivée (adresse active révoquée) : session_non_autorisee.", "consulter", { ticket: TICKET_CANAL, session_identity: A2 }, tkc(), "session_non_autorisee"],
    ["consulter-identite-inconnue", "Identité sans entrée et hors d'administrators : session_non_autorisee.", "consulter", { ticket: TICKET_CANAL, session_identity: ID("approbateur-9") }, tkc(), "session_non_autorisee"],
    ["consulter-identite-invalide", "Identité qui n'est pas canonique (un courriel) : identite_invalide, avant tout autre contrôle.", "consulter", { ticket: TICKET_CANAL, session_identity: "approbateur-1@assureur-demo.example" }, tkc(), "identite_invalide"],
    ["voter-adresse-active", "approbateur-1 vote avec le compte 1, son adresse active : passe.", "voter", voteCanal(1, A1), tkc(), null],
    ["voter-autre-adresse", "approbateur-1 présente le vote signé par le compte 2 : session_non_autorisee.", "voter", voteCanal(2, A1), tkc(), "session_non_autorisee"],
    ["voter-entree-desactivee", "approbateur-2, entrée désactivée, présente le vote du compte 2 : session_non_autorisee.", "voter", voteCanal(2, A2), tkc(), "session_non_autorisee"],
    ["recuser-adresse-active", "u.martin se récuse avec le compte 3, son adresse active : passe (le canal ne contrôle que l'adresse).", "recuser", { ticket: TICKET_CANAL, approver: ADR(3), session_identity: U }, tkc(), null],
    ["recuser-autre-adresse", "approbateur-1 récuse le compte 3 : session_non_autorisee.", "recuser", { ticket: TICKET_CANAL, approver: ADR(3), session_identity: A1 }, tkc(), "session_non_autorisee"],
    ["retirer-demandeur", "u.martin, dont l'entrée active porte l'alias u.martin@assureur-demo.example, retire avec by = launched_by : passe.", "retirer", { ticket: TICKET_CANAL, by: DEMANDEUR, reason: null, session_identity: U }, tkc(), null],
    ["retirer-administrateur", "admin-1 retire avec by = son identité de session : passe.", "retirer", { ticket: TICKET_CANAL, by: ADMIN, reason: "Demande annulée par l'organisation", session_identity: ADMIN }, tkc(), null],
    ["retirer-approbateur-par-alias", "approbateur-1, qui n'est pas le demandeur, retire avec by = launched_by : session_non_autorisee (le corps seul ne prouve rien).", "retirer", { ticket: TICKET_CANAL, by: DEMANDEUR, reason: null, session_identity: A1 }, tkc(), "session_non_autorisee"],
    ["retirer-administrateur-par-alias", "admin-1 retire avec by = launched_by au lieu de son identité : session_non_autorisee.", "retirer", { ticket: TICKET_CANAL, by: DEMANDEUR, reason: null, session_identity: ADMIN }, tkc(), "session_non_autorisee"],
    ["retirer-approbateur-par-identite", "approbateur-1, hors d'administrators, retire avec by = son identité : session_non_autorisee.", "retirer", { ticket: TICKET_CANAL, by: A1, reason: null, session_identity: A1 }, tkc(), "session_non_autorisee"],
    ["retirer-autre-demandeur", "u.martin retire, avec by = son alias, un ticket lancé par u.dupont@assureur-demo.example : session_non_autorisee.", "retirer", { ticket: TICKET_CANAL, by: DEMANDEUR, reason: null, session_identity: U }, tkc({ launched_by: "u.dupont@assureur-demo.example" }), "session_non_autorisee"],
    ["retirer-identite-invalide", "Identité de session non canonique (le courriel du demandeur) : identite_invalide.", "retirer", { ticket: TICKET_CANAL, by: DEMANDEUR, reason: null, session_identity: DEMANDEUR }, tkc(), "identite_invalide"],
    // Ticket inconnu dans l'organisation (ticket nul) : ordre d'EX-12.14 pour consulter et tickets, d'EX-12.19 pour les autres méthodes.
    ["consulter-ticket-inconnu", "approbateur-1, session de l'organisation, consulte un ticket inconnu : ticket_inconnu.", "consulter", { ticket: TICKET_INCONNU, session_identity: A1 }, null, "ticket_inconnu"],
    ["consulter-ticket-inconnu-non-eligible", "u.martin, entrée active de l'organisation, qui reçoit session_non_autorisee pour apr-0001 (cas consulter-demandeur), consulte un ticket inconnu : ticket_inconnu (point b avant le point c).", "consulter", { ticket: TICKET_INCONNU, session_identity: U }, null, "ticket_inconnu"],
    ["consulter-ticket-inconnu-hors-organisation", "Identité sans entrée et hors d'administrators, ticket inconnu : session_non_autorisee (point a avant le point b).", "consulter", { ticket: TICKET_INCONNU, session_identity: ID("approbateur-9") }, null, "session_non_autorisee"],
    ["consulter-ticket-inconnu-entree-desactivee", "approbateur-2, entrée désactivée, ticket inconnu : session_non_autorisee (point a).", "consulter", { ticket: TICKET_INCONNU, session_identity: A2 }, null, "session_non_autorisee"],
    ["consulter-ticket-inconnu-identite-invalide", "Identité non canonique, ticket inconnu : identite_invalide d'abord.", "consulter", { ticket: TICKET_INCONNU, session_identity: "approbateur-1@assureur-demo.example" }, null, "identite_invalide"],
    ["tickets-session-de-l-organisation", "approbateur-1, entrée active : la liste est servie.", "tickets", { session_identity: A1 }, null, null],
    ["tickets-administrateur", "admin-1, dans administrators, sans entrée : la liste est servie.", "tickets", { session_identity: ADMIN }, null, null],
    ["tickets-hors-organisation", "Identité sans entrée et hors d'administrators : session_non_autorisee.", "tickets", { session_identity: ID("approbateur-9") }, null, "session_non_autorisee"],
    ["tickets-entree-desactivee", "approbateur-2, entrée désactivée : session_non_autorisee.", "tickets", { session_identity: A2 }, null, "session_non_autorisee"],
    ["voter-ticket-inconnu", "approbateur-1 vote avec son adresse active pour un ticket inconnu : ticket_inconnu, après le contrôle d'adresse.", "voter", voteCanal(1, A1, TICKET_INCONNU), null, "ticket_inconnu"],
    ["voter-autre-adresse-ticket-inconnu", "approbateur-1 présente le vote du compte 2 pour un ticket inconnu : session_non_autorisee d'abord (le contrôle d'adresse ne dépend pas du ticket).", "voter", voteCanal(2, A1, TICKET_INCONNU), null, "session_non_autorisee"],
    ["retirer-ticket-inconnu", "approbateur-1, hors d'administrators, retire un ticket inconnu avec by = son identité : ticket_inconnu (le contrôle du retrait ne se fait que pour un ticket connu).", "retirer", { ticket: TICKET_INCONNU, by: A1, reason: null, session_identity: A1 }, null, "ticket_inconnu"],
  ];
  const defCanal = { tickets: ["console-service", "requete_tickets"], consulter: ["console-approbation", "requete_consulter"], voter: ["console-approbation", "requete_voter"], recuser: ["console-service", "requete_recuser"], retirer: ["console-service", "requete_retirer"] };
  const controlesCanal = {
    version: 0,
    annuaire: "annuaires/controles.json",
    cases: conceptionCanal.map(([id, description, method, request, ticket, reason]) => {
      const [schema, def] = defCanal[method];
      const erreurs = valider(request, schema, def);
      exiger(erreurs.length === 0, `controles-canal ${id} : requête non conforme ${JSON.stringify(erreurs.slice(0, 2))}`);
      const r = K.controleCanal(controles, method, request, ticket);
      exiger(r === reason, `controles-canal ${id} : ${r}, conception ${reason}`);
      return { id, description, checks: ["AN-10"], method, request, ticket, expected: { reason } };
    }),
  };
  for (const [m, r] of [["consulter", "ticket_inconnu"], ["tickets", null], ["tickets", "session_non_autorisee"], ["voter", "ticket_inconnu"], ["retirer", "ticket_inconnu"]]) exiger(controlesCanal.cases.some((c) => c.method === m && c.expected.reason === r), `AN-10 : ${m} ${r} sans cas`);
  exiger(controlesCanal.cases.some((c) => c.method === "consulter" && c.ticket === null && c.expected.reason === "session_non_autorisee"), "AN-10 : ordre session hors de l'organisation, ticket inconnu, sans cas");
  exiger(valider(controlesCanal, "annuaire-approbateurs", "fichier_controles_canal").length === 0, `controles-canal.json non conforme : ${JSON.stringify(valider(controlesCanal, "annuaire-approbateurs", "fichier_controles_canal").slice(0, 3))}`);

  return { annuaires, descriptionsAnnuaires, messages, inscriptions, domaines, traces, controlesVote, controlesCanal, fichiersExports, exportsAttendu, reference };
}
