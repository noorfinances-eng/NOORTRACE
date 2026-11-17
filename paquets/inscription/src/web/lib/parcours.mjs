// Mots du parcours d'inscription (complément du 2026-11-17, décision du porteur sur la présentation des écrans) :
// libellé en clair de chaque étape du dossier (CT-4 7.1) et de chaque état (EX-7.16), numérotation du parcours,
// avancement, prochaine action à faire, libellés des travaux (INTERFACES.md 3.3) et des erreurs (CT-4 7.11).
// Module pur, sans import : les pages du serveur et les composants de la page s'en servent, et les essais le
// chargent seul. Il ne décide rien : l'agent tranche (EX-7.23) ; il dit seulement en mots ce que le dossier porte.
// Aucune valeur n'est abrégée ni reformulée : le détail technique d'une étape rend les valeurs du dossier telles
// quelles.

/** Étapes du dossier (`steps[].step`) : titre court et phrase qui dit ce que l'étape fait. */
export const ETAPES = Object.freeze({
  jeu_approbateurs: { titre: "Créer le jeu d'approbateurs", phrase: "Déploie sur le registre le jeu d'approbateurs du client : la liste de ses approbateurs et leur seuil." },
  assignation: { titre: "Assigner le jeu à l'organisation", phrase: "Rattache ce jeu à l'organisation dans le registre." },
  lecture_jeu: { titre: "Relire le jeu", phrase: "Vérifie le jeu tel que le service d'approbation du client le lira. Aucune transaction n'est envoyée." },
  approvisionnement: { titre: "Approvisionner la clé de chaîne", phrase: "Verse à la clé de chaîne de quoi payer ses écritures sur le registre." },
  inscription: { titre: "Inscrire la clé d'enregistreur", phrase: "Les approbateurs signent la demande hors de cette application ; l'outil relaie ensuite la demande signée." },
  premiere_ancre: { titre: "Première ancre", phrase: "L'enregistreur du client ancre sa première période sur le registre." },
  premiere_cloture: { titre: "Première clôture", phrase: "Les approbateurs du client closent la première période." },
});

/** Étape 1 du parcours : la préparation du dossier, faite dès que le dossier existe (CT-4 7.5). */
export const ETAPE_PREPARATION = Object.freeze({ code: "preparation", titre: "Préparer le dossier", phrase: "Réunit dans le dossier d'inscription l'organisation, ses journaux, ses approbateurs et ses clés d'enregistreur." });

/**
 * États d'une étape (`steps[].state`, EX-7.16) : libellé de la pastille, explication, rang dans le parcours
 * (`faite`, `en-cours`, `a-faire`, `echec`), ton de la pastille et icône.
 */
export const ETATS_ETAPE = Object.freeze({
  a_faire: { libelle: "À faire", explication: "Rien n'a été envoyé.", rang: "a-faire", ton: "", icone: "tiret" },
  envoyee: { libelle: "Envoyée", explication: "La transaction est partie ; son reçu n'est pas encore là.", rang: "en-cours", ton: "info", icone: "horloge" },
  incluse: { libelle: "Incluse", explication: "La transaction est dans un bloc ; sa capture reste à faire.", rang: "en-cours", ton: "info", icone: "horloge" },
  capturee: { libelle: "Fait", explication: "Transaction incluse et capturée.", rang: "faite", ton: "succes", icone: "coche" },
  faite: { libelle: "Fait", explication: "Étape faite sans transaction.", rang: "faite", ton: "succes", icone: "coche" },
  echec: { libelle: "Échec", explication: "La transaction a été refusée par le contrat, ou la relecture la contredit.", rang: "echec", ton: "refus", icone: "croix" },
});

/** Étapes que la commande des étapes 2 à 5 conduit (CT-4 7.6). */
const ETAPES_CONDUITES = Object.freeze(["jeu_approbateurs", "assignation", "lecture_jeu", "approvisionnement"]);

const MOIS = Object.freeze(["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre"]);

/** Instant ISO (`AAAA-MM-JJThh:mm:ss.sssZ`) en clair, en UTC : « 12 novembre 2026 à 08:05 UTC » ; illisible : tel quel. */
export function dateLisible(iso) {
  if (iso === null || iso === undefined) return "";
  const m = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2})(?::[0-9]{2}(?:\.[0-9]{1,9})?)?Z$/.exec(String(iso));
  if (!m || Number(m[2]) < 1 || Number(m[2]) > 12) return String(iso);
  const jour = Number(m[3]);
  return `${jour === 1 ? "1er" : jour} ${MOIS[Number(m[2]) - 1]} ${m[1]} à ${m[4]}:${m[5]} UTC`;
}

/** Objet d'une étape, en clair : la clé de chaîne se dit par l'identifiant de sa clé d'enregistreur. */
function objetEnClair(e, dossier) {
  const cles = dossier.recorders ?? [];
  if (e.step === "approvisionnement") {
    const r = cles.find((x) => x.chain_key === e.subject);
    return r ? `Clé de chaîne de la clé d'enregistreur ${r.key_id}.` : "Clé de chaîne du dossier.";
  }
  if (e.step === "inscription") return `Clé d'enregistreur ${e.subject}.`;
  if (e.step === "premiere_ancre" || e.step === "premiere_cloture") {
    const j = (dossier.journals ?? []).find((x) => x.name === e.subject);
    return j ? `Journal ${j.name}.` : "";
  }
  return "";
}

/** Résultat d'une étape, en une phrase. */
function resultatEnClair(e) {
  switch (e.state) {
    case "capturee": return `Transaction incluse au bloc ${e.block_number} et capturée.`;
    case "faite": return "Fait sans transaction.";
    case "incluse": return `Transaction incluse au bloc ${e.block_number} ; sa capture reste à faire.`;
    case "envoyee": return "Transaction envoyée ; son reçu n'est pas encore arrivé.";
    case "echec": return "La transaction a été incluse mais refusée par le contrat, ou la relecture la contredit.";
    default: return "";
  }
}

/** Détail technique d'une étape : chaque valeur du dossier, telle quelle, avec le nom de son membre. */
function techniqueEtape(e) {
  const l = [
    { libelle: "Code de l'étape", membre: "step", valeur: e.step },
    { libelle: "Code de l'état", membre: "state", valeur: e.state },
    { libelle: "Objet", membre: "subject", valeur: e.subject },
  ];
  if (e.contract) l.push({ libelle: "Contrat créé", membre: "contract", valeur: e.contract });
  if (e.transaction_hash) l.push({ libelle: "Transaction", membre: "transaction_hash", valeur: e.transaction_hash });
  if (e.block_number !== null && e.block_number !== undefined) l.push({ libelle: "Bloc", membre: "block_number", valeur: String(e.block_number) });
  if (e.block_hash) l.push({ libelle: "Hachage du bloc", membre: "block_hash", valeur: e.block_hash });
  if (e.capture) l.push({ libelle: "Capture", membre: "capture", valeur: e.capture });
  if (e.error) {
    l.push({ libelle: "Code de l'erreur", membre: "error.code", valeur: e.error.code });
    l.push({ libelle: "Message de l'erreur", membre: "error.message", valeur: e.error.message });
  }
  if (e.updated_at) l.push({ libelle: "Instant exact", membre: "updated_at", valeur: e.updated_at });
  return l;
}

/**
 * Étapes du parcours, dans l'ordre : la préparation du dossier (étape 1), puis chaque étape du dossier. Chacune :
 * `{ numero, code, titre, phrase, objet, etat, libelle, explication, rang, ton, icone, resultat, quand, erreur,
 * technique }`. Un code que cette version ne connaît pas reste affiché tel quel, à faire.
 */
export function etapesDuParcours(dossier) {
  const preparation = {
    numero: 1, code: ETAPE_PREPARATION.code, titre: ETAPE_PREPARATION.titre, phrase: ETAPE_PREPARATION.phrase, objet: "",
    etat: "faite", libelle: ETATS_ETAPE.faite.libelle, explication: "Le dossier existe.", rang: "faite", ton: "succes", icone: "coche",
    resultat: "Dossier préparé.", quand: dossier.prepared_at ?? null, erreur: null,
    technique: [
      { libelle: "Préparé par", membre: "prepared_by", valeur: dossier.prepared_by ?? "" },
      { libelle: "Instant exact", membre: "prepared_at", valeur: dossier.prepared_at ?? "" },
      { libelle: "Source", membre: "source", valeur: dossier.source ?? "" },
    ].filter((x) => x.valeur !== ""),
  };
  const suite = (dossier.steps ?? []).map((e, k) => {
    const connue = ETAPES[e.step];
    const etat = ETATS_ETAPE[e.state];
    return {
      numero: k + 2,
      code: e.step,
      titre: connue ? connue.titre : `Étape ${e.step}`,
      phrase: connue ? connue.phrase : "Étape que cette version de l'outil ne sait pas décrire.",
      objet: connue ? objetEnClair(e, dossier) : "",
      etat: e.state,
      libelle: etat ? etat.libelle : `État ${e.state}`,
      explication: etat ? etat.explication : "État que cette version de l'outil ne sait pas décrire.",
      rang: etat ? etat.rang : "a-faire",
      ton: etat ? etat.ton : "",
      icone: etat ? etat.icone : "question",
      resultat: etat ? resultatEnClair(e) : "",
      quand: e.updated_at ?? null,
      erreur: e.state === "echec" ? { code: e.error?.code ?? "", message: e.error?.message ?? "", ...explicationErreur(e.error?.code ?? "") } : null,
      technique: techniqueEtape(e),
    };
  });
  return [preparation, ...suite];
}

/**
 * Avancement d'un dossier : `{ faites, total, echecs, enVol, etat, libelle, ton, icone, phrase }` ; `etat` vaut
 * `a_reprendre` (une étape en échec), `inscrit` (toutes faites) ou `en_cours`.
 */
export function avancement(dossier) {
  const l = etapesDuParcours(dossier);
  const faites = l.filter((e) => e.rang === "faite").length;
  const echecs = l.filter((e) => e.rang === "echec").length;
  const enVol = l.filter((e) => e.rang === "en-cours").length;
  const total = l.length;
  const phrase = `${faites} ${faites > 1 ? "étapes" : "étape"} sur ${total}`;
  if (echecs > 0) return { faites, total, echecs, enVol, etat: "a_reprendre", libelle: "À reprendre", ton: "refus", icone: "croix", phrase };
  if (faites === total) return { faites, total, echecs, enVol, etat: "inscrit", libelle: "Inscrit", ton: "succes", icone: "coche", phrase };
  return { faites, total, echecs, enVol, etat: "en_cours", libelle: "En cours", ton: "info", icone: "horloge", phrase };
}

/**
 * Prochaine action d'un client, d'après ce que l'interface lit (dossier, confirmations, demandes, périodes,
 * parties, travaux, paquet). Rend `{ code, titre, phrase, bouton, commande?, lien?, … }` : `commande` quand
 * l'action est un travail à remettre à l'agent, `lien` quand elle se fait sur un autre écran. L'agent refait
 * chaque contrôle : cette fonction guide, elle n'autorise rien.
 */
export function prochaineAction({ slug, dossier, confirmations = [], demandes = [], periodes = [], parties = [], travaux = [], paquet = null }) {
  const etapes = dossier.steps ?? [];
  const faite = (e) => ETATS_ETAPE[e.state]?.rang === "faite";
  const conduites = etapes.filter((e) => ETAPES_CONDUITES.includes(e.step));
  const restantes = conduites.filter((e) => !faite(e));
  if (restantes.length > 0) {
    // EX-7.26 : une confirmation hors bande, non consommée, pour chaque clé de chaîne dont l'approvisionnement reste à faire.
    const cles = etapes.filter((e) => e.step === "approvisionnement" && (e.state === "a_faire" || e.state === "echec"))
      .filter((e) => !confirmations.some((c) => c.operation === "approvisionnement" && c.objet?.cle_chaine === e.subject && !c.consommee_par))
      .map((e) => e.subject);
    if (cles.length > 0) {
      return {
        code: "consigner_confirmation",
        titre: "Consigner la confirmation hors bande du client",
        phrase: "Avant tout versement à une clé de chaîne, le client confirme l'opération par un autre canal que cette application : un appel, un courrier signé. Consignez cette confirmation ; l'outil pourra ensuite conduire les étapes.",
        bouton: "Consigner la confirmation",
        lien: `/clients/${slug}/confirmations`,
        cles,
      };
    }
    const dernier = 1 + conduites.length;
    const reprise = restantes.some((e) => e.state !== "a_faire");
    const enVol = restantes.some((e) => e.state === "envoyee" || e.state === "incluse");
    const intervalle = `les étapes 2 à ${dernier}`;
    return {
      code: "conduire_etapes",
      commande: "inscrire-client",
      titre: `${reprise ? "Reprendre" : "Conduire"} ${intervalle}`,
      phrase: enVol
        ? "Une transaction est partie sans que son issue soit enregistrée. L'outil relit d'abord l'état de la chaîne et reprend la transaction connue : jamais un nouvel envoi pour une étape déjà envoyée."
        : reprise
          ? "L'outil relit d'abord l'état de la chaîne, puis refait l'étape arrêtée et continue."
          : "L'outil crée le jeu d'approbateurs, l'assigne à l'organisation, le relit, puis approvisionne chaque clé de chaîne. Il s'arrête au premier refus et reprendra là où il s'est arrêté.",
      bouton: `${reprise ? "Reprendre" : "Conduire"} ${intervalle}`,
    };
  }
  const inscription = etapes.find((e) => e.step === "inscription" && !faite(e));
  if (inscription) {
    const keyId = inscription.subject;
    const preparee = demandes.some((d) => d.nom.startsWith(`demande-inscription-${keyId}-`));
    if (!preparee) {
      return {
        code: "preparer_demande",
        commande: "condense-inscription",
        keyId,
        titre: "Préparer la demande d'inscription",
        phrase: `L'outil prépare la demande d'inscription de la clé d'enregistreur ${keyId}. Il ne la signe pas : vous la remettrez aux approbateurs du client hors de cette application.`,
        bouton: "Préparer la demande",
      };
    }
    return {
      code: "relayer_demande",
      commande: "inscrire-cle",
      keyId,
      titre: "Faire signer la demande, puis la relayer",
      phrase: `La demande d'inscription de la clé ${keyId} est prête. Remettez-la aux approbateurs du client hors de cette application : ils la signent avec leur propre outil. Collez ensuite ici la demande signée ; l'outil la relaie au registre.`,
      bouton: "Relayer la demande signée",
    };
  }
  const premiere = etapes.find((e) => (e.step === "premiere_ancre" || e.step === "premiere_cloture") && !faite(e));
  if (premiere) {
    return {
      code: "attendre_premiere_periode",
      titre: "Attendre la première période du client",
      phrase: "La première ancre et la première clôture se font hors de cet outil : l'enregistreur du client ancre sa première période, puis ses approbateurs la closent. La fiche se met à jour quand le dossier les enregistre.",
      bouton: "Actualiser la fiche",
      lien: `/clients/${slug}`,
    };
  }
  const autre = etapes.find((e) => !faite(e));
  if (autre) {
    return {
      code: "etape_inconnue",
      titre: "Une étape reste à faire",
      phrase: "Le dossier porte une étape que cette version de l'outil ne sait pas conduire. Son détail technique la décrit.",
      bouton: "Actualiser la fiche",
      lien: `/clients/${slug}`,
    };
  }
  const reussi = (commande) => travaux.some((t) => t.commande === commande && t.etat === "fini" && (t.sortie?.result === "reussi" || t.sortie?.result === "deja_fait"));
  if (!paquet?.present && periodes.length > 0 && parties.length === 0) {
    return {
      code: "exporter",
      commande: "exporter",
      titre: "Exporter les parties du registre",
      phrase: "Toutes les étapes sont faites. L'outil écrit maintenant les parties du registre qui entrent dans le dossier de preuve du client.",
      bouton: "Exporter les parties",
    };
  }
  if (!paquet?.present && periodes.length > 0 && parties.length > 0 && !reussi("verifier")) {
    return {
      code: "verifier",
      commande: "verifier",
      titre: "Vérifier les parties du registre",
      phrase: "Les parties sont exportées. L'outil les contrôle comme le fera le vérificateur du client.",
      bouton: "Vérifier les parties",
    };
  }
  if (!paquet?.present) {
    return {
      code: "produire_paquet",
      titre: "Produire le paquet client",
      phrase: "L'inscription est faite. Le paquet réunit ce que le client doit recevoir pour configurer son service d'approbation et contrôler son inscription.",
      bouton: "Produire le paquet",
      lien: `/clients/${slug}/paquet`,
    };
  }
  return {
    code: "remettre_paquet",
    titre: "Remettre le paquet au client",
    phrase: "L'inscription est faite et le paquet est produit. Téléchargez-le et remettez-le au client.",
    bouton: "Ouvrir le paquet",
    lien: `/clients/${slug}/paquet`,
  };
}

/** Commandes des travaux (INTERFACES.md 3.3) : libellé en clair. */
export const COMMANDES = Object.freeze({
  "inscrire-client-preparer": "Préparer le dossier",
  "inscrire-client": "Conduire les étapes 2 à 5",
  approvisionner: "Approvisionner une clé de chaîne",
  "condense-inscription": "Préparer la demande d'inscription",
  "inscrire-cle": "Relayer la demande d'inscription signée",
  "condense-administration": "Préparer une demande d'administration du jeu",
  "administrer-jeu": "Relayer la demande d'administration signée",
  capturer: "Capturer une transaction",
  exporter: "Exporter les parties du registre",
  verifier: "Vérifier les parties",
  paquet: "Produire et contrôler le paquet client",
});

/** Libellé d'une commande ; inconnue : son code. */
export const libelleCommande = (commande) => COMMANDES[commande] ?? `Commande ${commande}`;

const RESULTATS = Object.freeze({
  reussi: { libelle: "Réussi", ton: "succes", icone: "coche", explication: "La commande a réussi." },
  deja_fait: { libelle: "Déjà fait", ton: "succes", icone: "coche", explication: "Il n'y avait plus rien à faire : l'état demandé est déjà atteint." },
  refuse: { libelle: "Refusé avant envoi", ton: "refus", icone: "croix", explication: "Un contrôle préalable a refusé : rien n'a été envoyé." },
  echoue: { libelle: "Échec", ton: "refus", icone: "croix", explication: "La commande a échoué après son envoi." },
  incertain: { libelle: "Issue inconnue", ton: "attente", icone: "question", explication: "L'issue n'est pas connue : rien n'est affirmé." },
  inutilisable: { libelle: "Inutilisable", ton: "", icone: "question", explication: "L'entrée est inutilisable : rien n'est affirmé." },
});

/**
 * État d'un travail (`etat`, et `sortie.result` s'il est fini) en mots : `{ code, libelle, ton, icone, explication,
 * termine }`.
 */
export function etatTravail(t) {
  if (!t) return { code: "", libelle: "", ton: "", icone: "tiret", explication: "", termine: false };
  if (t.etat === "en_attente") return { code: "en_attente", libelle: "En file d'attente", ton: "", icone: "horloge", explication: "L'agent exécute un travail à la fois ; celui-ci attend son tour.", termine: false };
  if (t.etat === "en_cours") return { code: "en_cours", libelle: "En cours", ton: "info", icone: "horloge", explication: "L'agent exécute le travail.", termine: false };
  if (t.etat === "refuse") return { code: "refuse", libelle: "Refusé par l'agent", ton: "refus", icone: "croix", explication: "L'agent a refusé le travail : rien n'a été envoyé.", termine: true };
  if (t.etat === "abandonne") return { code: "abandonne", libelle: "Abandonné", ton: "", icone: "tiret", explication: "L'agent s'est arrêté pendant le travail. Le dossier dit l'état réel : relancez l'action.", termine: true };
  if (t.etat === "fini") {
    const r = RESULTATS[t.sortie?.result];
    if (r) return { code: t.sortie.result, ...r, termine: true };
    return { code: String(t.sortie?.result ?? ""), libelle: `Fini (${t.sortie?.result ?? "sans résultat"})`, ton: "", icone: "question", explication: "", termine: true };
  }
  return { code: String(t.etat ?? ""), libelle: `État ${t.etat}`, ton: "", icone: "question", explication: "", termine: false };
}

const E = (phrase, quoiFaire) => Object.freeze({ phrase, quoiFaire });
const CERTIFICAT = E("La capture de la preuve du bloc n'a pas abouti.", "Relancez la capture par « Capturer une transaction ». Un certificat élagué par le nœud est perdu pour ce nœud.");
const CLE_OCCUPEE = E("La clé ne peut pas être inscrite : elle est déjà inscrite, révoquée, ou employée ailleurs.", "Demandez au client une nouvelle clé de chaîne. Une clé révoquée n'est jamais réinscrite.");
const SIGNATURES = E("Les signatures de la demande ne conviennent pas : signataire hors du jeu, signature non conforme, ou seuil non atteint.", "Faites signer la demande par d'autres approbateurs du jeu, puis relayez-la de nouveau.");
const PERIODE = E("Le manifeste de la période est refusé : malformé, déjà enregistré, ou hors de la suite du journal.", "Rien ne se corrige sur la chaîne : l'enregistreur du client refait le manifeste.");
const PAQUET = E("Le contrôle du paquet a refusé un fichier.", "Produisez le paquet de nouveau. Si le refus revient, lisez la sortie du travail : elle nomme le point du contrôle et le fichier.");
const RESEAU = E("Le registre que joint l'agent n'est pas celui du dossier.", "Vérifiez la configuration de l'agent (points du réseau, manifeste d'instance). Ne forcez jamais.");

/** Erreurs des travaux et des étapes (CT-4 7.11, EX-7.26, EX-7.30) : ce qui s'est passé, et quoi faire. */
const ERREURS = Object.freeze({
  confirmation_absente: E("Rien n'a été envoyé : confirmation hors bande absente.", "Consignez la confirmation du client (écran « Confirmations hors bande »), puis relancez l'action."),
  reference_refusee: E("La référence de clé est refusée.", "Donnez une référence que l'agent sait résoudre (fichier:, alias:). Une clé ne se donne jamais par sa valeur."),
  requete_invalide: E("Un champ n'a pas la forme attendue.", "Corrigez le champ que le message nomme, puis relancez."),
  agent_injoignable: E("L'agent ne répond pas.", "Vérifiez que l'agent d'inscription tourne sur ce poste, puis relancez."),
  session_absente: E("Votre session est fermée ou expirée.", "Reconnectez-vous, puis relancez l'action."),
  client_inconnu: E("Ce client n'existe pas dans les données de l'agent.", "Revenez à la liste des clients."),
  usage: E("La commande a reçu une option qu'elle n'attend pas.", "Corrigez la saisie, puis relancez."),
  entree_illisible: E("Un document donné est illisible ou n'a pas la forme attendue.", "Corrigez le document (demande, dossier), puis relancez."),
  instance_illisible: E("Le manifeste du registre est illisible ou a changé.", "Faites vérifier la configuration de l'agent, puis relancez."),
  reseau_non_developpement: E("Une clé de développement est employée hors du réseau de développement.", "Employez les clés de production que l'agent sait résoudre."),
  chaine_differente: RESEAU,
  jeu_validateurs_different: RESEAU,
  code_absent: RESEAU,
  noeud_injoignable: E("Le nœud du registre ne répond pas.", "Vérifiez que le nœud tourne et que l'agent joint un validateur, puis relancez."),
  noeud_suiveur: E("Le point joint est un nœud suiveur, pas un validateur.", "Faites régler l'agent sur un validateur, puis relancez."),
  organisation_existante: E("Une organisation de ce nom est déjà enregistrée avec un autre jeu.", "Choisissez un autre nom court. Changer le jeu d'une organisation existante se fait par l'administration du jeu."),
  organisation_inconnue: E("L'organisation n'est pas enregistrée dans le registre.", "Conduisez d'abord les étapes 2 à 5."),
  jeu_invalide: E("Le jeu d'approbateurs du dossier est refusé : membres, seuil ou administrateur.", "Corrigez la saisie et préparez le dossier de nouveau."),
  cle_invalide: E("Une clé du dossier n'a pas la classe de garde exigée.", "Demandez au client une clé gardée dans un module matériel."),
  compte_inattendu: E("Un compte de l'exploitant n'est pas celui de son rôle.", "Faites vérifier les comptes dans la configuration de l'agent."),
  pas_administrateur: E("Le signataire n'est pas l'administrateur attendu, ou la demande est périmée.", "Refaites la demande, puis faites-la signer par l'administrateur du jeu."),
  solde_insuffisant: E("Le compte qui envoie n'a pas de quoi payer la transaction.", "Approvisionnez la clé (« Approvisionner une clé de chaîne »), puis relancez."),
  provision_excessive: E("Le versement dépasserait la provision permise.", "Revoyez le budget journalier, puis relancez."),
  examen_requis: E("La consommation de la clé dépasse deux fois son budget.", "Examinez la consommation avec le client avant tout nouveau versement."),
  transaction_en_attente: E("Une transaction du même compte est partie sans issue connue.", "Reprenez cet envoi par « Capturer une transaction », rubrique « envoi sans issue ». Ne renvoyez rien."),
  nonce_incoherent: E("Les nœuds du registre ne sont pas d'accord sur le rang de la prochaine transaction.", "C'est passager : relancez quand les nœuds concordent."),
  condense_different: E("La demande ne correspond pas à ce que le registre attend : elle a été altérée, ou vise un autre contrat.", "Préparez la demande de nouveau. Ne faites pas signer l'ancienne."),
  signature_non_canonique: SIGNATURES,
  signataire_hors_jeu: SIGNATURES,
  signatures_insuffisantes: SIGNATURES,
  cle_deja_active: CLE_OCCUPEE,
  cle_revoquee: CLE_OCCUPEE,
  cle_ed25519_active: CLE_OCCUPEE,
  cle_chaine_autre_organisation: CLE_OCCUPEE,
  cle_inconnue: E("La clé n'est pas connue du registre.", "Inscrivez d'abord la clé d'enregistreur."),
  cle_chaine_non_inscrite: E("La clé de chaîne n'est pas encore inscrite.", "Inscrivez d'abord la clé d'enregistreur."),
  empreinte_squattee: E("L'empreinte a déjà été ancrée par un autre émetteur.", "Ne réessayez pas. Signalez-le au client."),
  ancre_manquante: E("L'ancre de la période n'est pas encore incluse et capturée.", "Attendez l'ancre, ou capturez sa transaction, puis relancez."),
  demande_existante: E("Une autre demande de clôture a déjà été relayée pour cette période.", "Ne refaites pas la demande : celle qui a été relayée fait foi."),
  demande_expiree: E("La demande a dépassé son échéance.", "Préparez une nouvelle demande. Ne faites pas signer l'ancienne."),
  periode_invalide: PERIODE,
  doublon: PERIODE,
  discontinuite_temporelle: PERIODE,
  discontinuite_sequence: PERIODE,
  transaction_refusee: E("Le nœud a refusé la transaction à l'envoi : rien n'est parti.", "Faites vérifier les frais dans la configuration, puis relancez."),
  transaction_annulee: E("La transaction a été incluse mais refusée par le contrat.", "Relancez l'action : l'outil relit d'abord l'état de la chaîne. Il ne renvoie jamais une transaction à l'identique."),
  recu_absent: E("Aucun reçu n'est arrivé dans le délai : l'issue de la transaction n'est pas connue.", "Reprenez cet envoi par « Capturer une transaction », rubrique « envoi sans issue ». Ne renvoyez rien."),
  certificat_indisponible: CERTIFICAT,
  certificat_elague: CERTIFICAT,
  certificat_invalide: CERTIFICAT,
  capture_incomplete: CERTIFICAT,
  dossier_inacheve: E("Le dossier n'est pas fini : une étape reste à faire.", "Terminez les étapes de l'inscription, puis produisez le paquet."),
  paquet_manifeste: PAQUET,
  paquet_fichiers: PAQUET,
  paquet_forme: PAQUET,
  paquet_organisation: PAQUET,
  paquet_jeu: PAQUET,
  paquet_captures: PAQUET,
  secret_present: E("Un secret figure dans un fichier du paquet : le paquet n'est pas remis.", "Ne remettez pas ce paquet. Faites examiner les fichiers nommés par la sortie du travail."),
});

/**
 * Explication d'un code d'erreur : `{ phrase, quoiFaire, connu }`. Un code inconnu reçoit une phrase générale ;
 * l'appelant affiche toujours le code et le message exacts dans le détail.
 */
export function explicationErreur(code) {
  const e = Object.hasOwn(ERREURS, code) ? ERREURS[code] : null;
  if (e) return { phrase: e.phrase, quoiFaire: e.quoiFaire, connu: true };
  return { phrase: "L'action a été refusée.", quoiFaire: "Lisez le message exact dans le détail technique, corrigez, puis relancez.", connu: false };
}

/** Saisie refusée dans la page (types d'EX-7.25) : ce qui est attendu, en clair, sans recopier la valeur. */
const SAISIES = Object.freeze({
  slug: "Le nom court n'a pas la bonne forme : de 1 à 64 lettres minuscules, chiffres ou tirets, sans espace ni accent.",
  nom_journal: "Un nom de journal n'a pas la bonne forme : de 1 à 64 lettres minuscules, chiffres ou tirets.",
  liste_noms_journal: "Un nom de journal n'a pas la bonne forme : de 1 à 64 lettres minuscules, chiffres ou tirets, un nom par ligne.",
  adresse: "Ce n'est pas une adresse : « 0x » suivi de 40 chiffres hexadécimaux.",
  liste_adresses: "Une des adresses n'a pas la bonne forme : « 0x » suivi de 40 chiffres hexadécimaux, une adresse par ligne.",
  hachage: "Ce n'est pas une empreinte : « 0x » suivi de 64 chiffres hexadécimaux.",
  cle_publique_ed25519: "Ce n'est pas une clé publique : « 0x » suivi de 64 chiffres hexadécimaux.",
  seuil: "Le seuil est un nombre entier de 1 à 64.",
  entier: "Un nombre entier est attendu.",
  montant: "Un nombre entier positif est attendu, en chiffres, sans espace.",
  reference_cle: "Ce n'est pas une référence de clé. Une clé se désigne par sa référence (fichier:, alias:), jamais par sa valeur.",
  texte: "Ce texte est refusé : il est vide, trop long, ou il a la forme d'une clé.",
  chemin: "Ce n'est pas un chemin relatif sous le répertoire du client.",
  document: "Ce n'est pas un document JSON lisible.",
  liste_documents: "Un tableau JSON de documents est attendu.",
  horodatage: "L'instant s'écrit AAAA-MM-JJThh:mm:ss.sssZ, en UTC.",
});

/** Phrase d'une saisie refusée, d'après le type déclaré du champ. */
export const explicationSaisie = (type) => SAISIES[type] ?? "Cette saisie n'a pas la forme attendue.";

/** Opérations du jeu d'un client (CT-4 6.6.2) : libellé en clair ; le nom de l'opération reste dans l'option. */
export const OPERATIONS_JEU = Object.freeze({
  "CuratorSet.addCurator": "Ajouter un approbateur",
  "CuratorSet.removeCurator": "Retirer un approbateur",
  "CuratorSet.setThreshold": "Changer le seuil",
  "CuratorSet.proposeAdmin": "Proposer un administrateur",
  "CuratorSet.acceptAdmin": "Accepter l'administration",
});

/** Opérations d'une confirmation hors bande (INTERFACES.md 3.5) : libellé en clair. */
export const OPERATIONS_CONFIRMATION = Object.freeze({
  approvisionnement: "Approvisionnement à l'inscription (étape « Approvisionner la clé de chaîne »)",
  approvisionner: "Approvisionnement en cours d'exploitation",
  "administrer-jeu": "Administration du jeu d'approbateurs",
});
