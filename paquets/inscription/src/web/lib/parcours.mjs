// Mots du parcours d'inscription : libellé courant de chaque étape du dossier (CT-4 7.1) et de chaque état
// (EX-7.16), numérotation du parcours, avancement, prochaine action écrite comme une consigne, libellés des travaux
// (INTERFACES.md 3.3) et des erreurs (CT-4 7.11), lexique des écrans.
//
// Complément du 2026-11-17, décision du porteur (présentation des écrans) : mots au lieu de codes. Complément du
// 2026-11-18, décision du porteur (langage des écrans) : l'outil parle à une personne de l'équipe qui n'est pas
// développeuse. Chaque étape a un nom courant en verbe et une phrase ; chaque état a un mot et une phrase ; chaque
// erreur dit ce qui s'est passé, si quelque chose a été envoyé ou dépensé, et quoi faire ; les codes et les valeurs
// exactes restent lisibles dans le détail replié des écrans.
//
// Module pur, sans import : les pages du serveur et les composants de la page s'en servent, et les essais le
// chargent seul. Il ne décide rien : l'agent tranche (EX-7.23) ; il dit seulement en mots ce que le dossier porte.
// Aucune valeur n'est abrégée ni reformulée : le détail technique d'une étape rend les valeurs du dossier telles
// quelles.

/** Étapes du dossier (`steps[].step`) : nom courant en verbe, et phrase qui dit ce que l'étape fait et pourquoi. */
export const ETAPES = Object.freeze({
  jeu_approbateurs: { titre: "Enregistrer les approbateurs", phrase: "Inscrit sur le registre public la liste des approbateurs du client et le nombre d'approbations requises." },
  assignation: { titre: "Rattacher les approbateurs au client", phrase: "Relie cette liste au client sur le registre public : à partir de là, le client y existe et ses approbateurs y sont reconnus." },
  lecture_jeu: { titre: "Contrôler les approbateurs", phrase: "Relit la liste sur le registre public, comme le service d'approbation du client la lira. Rien n'est écrit ni dépensé." },
  approvisionnement: { titre: "Alimenter le compte technique", phrase: "Verse des crédits d'écriture sur le compte technique de l'enregistreur du client, pour qu'il puisse payer ses écritures sur le registre public." },
  inscription: { titre: "Inscrire l'enregistreur", phrase: "Inscrit sur le registre public l'enregistreur du client et son compte technique. Les approbateurs du client signent d'abord un document, avec leur propre outil." },
  premiere_ancre: { titre: "Déposer la première preuve de date", phrase: "L'enregistreur du client dépose sur le registre public sa première preuve de date : la preuve que son journal existait à ce moment. Cela se fait chez le client, sans vous." },
  premiere_cloture: { titre: "Clore la première période", phrase: "Les approbateurs du client signent la clôture de la première période du journal, qui est alors inscrite pour de bon sur le registre public. Cela se fait chez le client, sans vous." },
});

/** Étape 1 du parcours : la préparation du dossier, faite dès que le dossier existe (CT-4 7.5). */
export const ETAPE_PREPARATION = Object.freeze({ code: "preparation", titre: "Préparer le dossier", phrase: "Réunit dans le dossier d'inscription ce que le client nous a transmis : son nom, ses journaux, ses approbateurs et son enregistreur. Rien n'est envoyé au registre public." });

/**
 * États d'une étape (`steps[].state`, EX-7.16) : mot de la pastille, phrase d'explication, rang dans le parcours
 * (`faite`, `en-cours`, `a-faire`, `echec`), ton de la pastille et icône.
 */
export const ETATS_ETAPE = Object.freeze({
  a_faire: { libelle: "À faire", explication: "Rien n'a encore été envoyé pour cette étape.", rang: "a-faire", ton: "", icone: "tiret" },
  envoyee: { libelle: "Envoyée", explication: "L'opération est partie vers le registre public ; sa réponse n'est pas encore arrivée.", rang: "en-cours", ton: "info", icone: "horloge" },
  incluse: { libelle: "Inscrite", explication: "Le registre public a inscrit l'opération ; il reste à ranger sa preuve dans le dossier.", rang: "en-cours", ton: "info", icone: "horloge" },
  capturee: { libelle: "Fait", explication: "L'opération est inscrite sur le registre public et sa preuve est rangée dans le dossier.", rang: "faite", ton: "succes", icone: "coche" },
  faite: { libelle: "Fait", explication: "Étape faite sans rien écrire sur le registre public.", rang: "faite", ton: "succes", icone: "coche" },
  echec: { libelle: "Échec", explication: "Le registre public a refusé l'opération, ou le contrôle fait juste après ne retrouve pas ce qui devait être inscrit.", rang: "echec", ton: "refus", icone: "croix" },
});

/** Étapes que la commande des étapes 2 à 5 conduit (CT-4 7.6). */
const ETAPES_CONDUITES = Object.freeze(["jeu_approbateurs", "assignation", "lecture_jeu", "approvisionnement"]);
// Étapes dont l'opération est envoyée par le service d'inscription lui-même : il a écrit l'envoi dans les captures
// du client avant de marquer l'étape `envoyee` (src/agent/envoi.mjs), et sait donc le reprendre par `capturer`.
// Les deux dernières étapes se font chez le client, avec ses propres outils : leur envoi n'est pas ici.
const ETAPES_ENVOYEES_D_ICI = Object.freeze(["jeu_approbateurs", "assignation", "approvisionnement", "inscription"]);
// Étapes que le client fait lui-même (CT-4 7.8 et 7.9) : « à faire » s'y dit « À faire par le client », pour que la
// personne ne les prenne pas pour les siennes.
const ETAPES_DU_CLIENT = Object.freeze(["premiere_ancre", "premiere_cloture"]);
const A_FAIRE_PAR_LE_CLIENT = Object.freeze({ libelle: "À faire par le client", explication: "Rien n'a encore été envoyé pour cette étape : c'est le client qui la fait, avec ses propres outils." });

/** Étapes du dossier que chaque commande fait avancer : sert à ne jamais dire « réussi » à côté d'une étape en échec. */
const ETAPES_DE_COMMANDE = Object.freeze({ "inscrire-client": ETAPES_CONDUITES, "inscrire-cle": Object.freeze(["inscription"]) });

const MOIS = Object.freeze(["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre"]);

/** Instant ISO (`AAAA-MM-JJThh:mm:ss.sssZ`) en clair, en UTC : « 12 novembre 2026 à 08:05 UTC » ; illisible : tel quel. */
export function dateLisible(iso) {
  if (iso === null || iso === undefined) return "";
  const m = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2})(?::[0-9]{2}(?:\.[0-9]{1,9})?)?Z$/.exec(String(iso));
  if (!m || Number(m[2]) < 1 || Number(m[2]) > 12) return String(iso);
  const jour = Number(m[3]);
  return `${jour === 1 ? "1er" : jour} ${MOIS[Number(m[2]) - 1]} ${m[1]} à ${m[4]}:${m[5]} UTC`;
}

/** Jour d'un instant ISO, en clair, en UTC : « 12 novembre 2026 » ; illisible : tel quel. */
export function jourLisible(iso) {
  const t = dateLisible(iso);
  const k = t.indexOf(" à ");
  return k > 0 ? t.slice(0, k) : t;
}

/** Nombre entier écrit en chiffres, avec une espace insécable entre les milliers ; autre chose : tel quel. */
export function nombreLisible(valeur) {
  const t = String(valeur ?? "");
  return /^[0-9]+$/.test(t) ? t.replace(/\B(?=([0-9]{3})+$)/g, " ") : t;
}

/**
 * Objet d'une étape, en clair : `{ texte, valeur }`, la valeur étant un nom qui vient du dossier (affiché tel
 * quel) ; le compte technique se dit par le nom de son enregistreur. Sans objet à dire : null.
 */
function objetEnClair(e, dossier) {
  const cles = dossier.recorders ?? [];
  if (e.step === "approvisionnement") {
    const r = cles.find((x) => x.chain_key === e.subject);
    return r ? { texte: "Compte technique de l'enregistreur", valeur: r.key_id } : { texte: "Compte technique", valeur: String(e.subject ?? "") };
  }
  if (e.step === "inscription") return { texte: "Enregistreur", valeur: String(e.subject ?? "") };
  if (e.step === "premiere_ancre" || e.step === "premiere_cloture") {
    const j = (dossier.journals ?? []).find((x) => x.name === e.subject);
    return j ? { texte: "Journal", valeur: j.name } : null;
  }
  return null;
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
 * `{ numero, code, titre, phrase, objet, etat, libelle, explication, rang, ton, icone, quand, erreur, technique,
 * developpee }`. `developpee` vaut vrai pour l'étape où l'on en est (la première qui n'est pas faite) et pour une
 * étape en échec : l'écran montre leur phrase sans rien ouvrir ; les autres tiennent en une ligne. Un code que
 * cette version ne connaît pas reste affiché tel quel, à faire.
 */
export function etapesDuParcours(dossier) {
  const preparation = {
    numero: 1, code: ETAPE_PREPARATION.code, titre: ETAPE_PREPARATION.titre, phrase: ETAPE_PREPARATION.phrase, objet: null,
    etat: "faite", libelle: ETATS_ETAPE.faite.libelle, explication: "Le dossier existe.", rang: "faite", ton: "succes", icone: "coche",
    quand: dossier.prepared_at ?? null, erreur: null,
    technique: [
      { libelle: "Préparé par", membre: "prepared_by", valeur: dossier.prepared_by ?? "" },
      { libelle: "Instant exact", membre: "prepared_at", valeur: dossier.prepared_at ?? "" },
      { libelle: "Source", membre: "source", valeur: dossier.source ?? "" },
    ].filter((x) => x.valeur !== ""),
    developpee: false,
  };
  const suite = (dossier.steps ?? []).map((e, k) => {
    const connue = ETAPES[e.step];
    const duClient = ETAPES_DU_CLIENT.includes(e.step) && e.state === "a_faire";
    const etat = duClient ? { ...ETATS_ETAPE.a_faire, ...A_FAIRE_PAR_LE_CLIENT } : ETATS_ETAPE[e.state];
    return {
      numero: k + 2,
      code: e.step,
      titre: connue ? connue.titre : `Étape ${e.step}`,
      phrase: connue ? connue.phrase : "Étape que cette version de l'outil ne sait pas décrire.",
      objet: connue ? objetEnClair(e, dossier) : null,
      etat: e.state,
      libelle: etat ? etat.libelle : `État ${e.state}`,
      explication: etat ? etat.explication : "État que cette version de l'outil ne sait pas décrire.",
      rang: etat ? etat.rang : "a-faire",
      ton: etat ? etat.ton : "",
      icone: etat ? etat.icone : "question",
      quand: e.updated_at ?? null,
      erreur: e.state === "echec" ? { code: e.error?.code ?? "", message: e.error?.message ?? "", ...explicationErreur(e.error?.code ?? "") } : null,
      technique: techniqueEtape(e),
      developpee: false,
    };
  });
  const tout = [preparation, ...suite];
  const courante = tout.find((e) => e.rang !== "faite");
  for (const e of tout) e.developpee = e === courante || e.rang === "echec";
  return tout;
}

/**
 * Avancement d'un dossier : `{ faites, total, echecs, enVol, etat, attente, libelle, ton, icone, phrase,
 * phraseFaites, resume }` ; `etat` vaut `a_reprendre` (une étape en échec), `inscrit` (toutes faites) ou
 * `en_cours`. `resume` est la phrase qui dit où en est le client. Une étiquette n'a qu'un sens (complément du
 * 2026-11-18) : « Réponse à aller chercher » quand un envoi parti d'ici attend que la personne aille chercher sa réponse
 * (`attente` : `reponse_a_chercher`) ; « En attente du registre » quand une étape envoyée par le client attend sa
 * réponse (`registre`) et « En attente chez le client » quand la suite se fait chez lui (`client`) : dans ces deux
 * cas, la personne n'a rien à faire.
 */
export function avancement(dossier) {
  const l = etapesDuParcours(dossier);
  const faites = l.filter((e) => e.rang === "faite").length;
  const echecs = l.filter((e) => e.rang === "echec").length;
  const enVol = l.filter((e) => e.rang === "en-cours").length;
  const total = l.length;
  const phrase = `${faites} ${faites > 1 ? "étapes" : "étape"} sur ${total}`;
  const commun = { faites, total, echecs, enVol, phrase, phraseFaites: `${phrase} ${faites > 1 ? "faites" : "faite"}` };
  if (echecs > 0) return { ...commun, etat: "a_reprendre", attente: null, libelle: "À reprendre", ton: "refus", icone: "croix", resume: "Une étape a échoué : reprenez-la pour continuer." };
  if (faites === total) return { ...commun, etat: "inscrit", attente: null, libelle: "Inscrit", ton: "succes", icone: "coche", resume: "Toutes les étapes sont faites : le client est inscrit." };
  // Le même envoi que celui dont `prochaineAction` fait sa consigne : l'étiquette et la consigne disent la même chose.
  const etapes = dossier.steps ?? [];
  const partie = etapes.find((x) => ["envoyee", "incluse"].includes(x.state) && x.transaction_hash);
  if (partie && ETAPES_ENVOYEES_D_ICI.includes(partie.step)) return { ...commun, etat: "en_cours", attente: "reponse_a_chercher", libelle: "Réponse à aller chercher", ton: "attente", icone: "alerte", resume: "Un envoi est resté sans réponse : une action vous attend." };
  if (partie) return { ...commun, etat: "en_cours", attente: "registre", libelle: "En attente du registre", ton: "info", icone: "horloge", resume: "Une étape envoyée par le client attend la réponse du registre public : vous n'avez rien à faire." };
  const suivante = etapes.find((e) => ETATS_ETAPE[e.state]?.rang !== "faite");
  if (enVol === 0 && suivante && ETAPES_DU_CLIENT.includes(suivante.step) && suivante.state === "a_faire") return { ...commun, etat: "en_cours", attente: "client", libelle: "En attente chez le client", ton: "info", icone: "horloge", resume: "La suite se fait chez le client : vous n'avez rien à faire." };
  return { ...commun, etat: "en_cours", attente: null, libelle: "En cours", ton: "info", icone: "horloge", resume: "L'inscription est en cours." };
}

/**
 * Prochaine action d'un client, d'après ce que l'interface lit (dossier, confirmations, demandes, périodes,
 * parties, travaux, paquet), écrite comme une consigne. Rend `{ code, surTitre, titre, phrase, aPreparer, apres,
 * bouton, commande?, lien?, … }` : `titre` dit quoi faire, `phrase` pourquoi, `aPreparer` ce qu'il faut avoir sous
 * la main, `apres` ce qui se passera après le clic ; `commande` quand l'action est un travail à remettre à
 * l'agent, `lien` quand elle se fait sur un autre écran. L'agent refait chaque contrôle : cette fonction guide,
 * elle n'autorise rien.
 *
 * Un envoi resté sans réponse passe avant tout (complément du 2026-11-18) : tant qu'une étape est `envoyee` ou
 * `incluse`, la consigne est d'aller chercher la réponse du registre public pour cet envoi, par la capture de la
 * transaction connue (EX-7.13 : jamais une nouvelle transaction ; le travail `capturer` ne fait que lire le registre),
 * ce qui ne demande aucune confirmation du client ; l'écran ne dit alors qu'une chose.
 * La reprise n'est proposée que pour une étape que le service d'inscription envoie lui-même (étapes 2, 3, 5 et 6) :
 * `capturer` avec `envoi` relit l'envoi qu'il a écrit pour une étape `envoyee`, avec `transaction` range la preuve
 * d'une étape `incluse`. Pour les deux dernières étapes, faites chez le client, la consigne reste neutre : attendre,
 * puis prévenir l'équipe technique.
 */
export function prochaineAction({ slug, dossier, confirmations = [], demandes = [], periodes = [], parties = [], travaux = [], paquet = null }) {
  const etapes = dossier.steps ?? [];
  const faite = (e) => ETATS_ETAPE[e.state]?.rang === "faite";
  const numero = (e) => etapes.indexOf(e) + 2;
  const surTitre = "Prochaine action";
  const depuis = (e) => (e.updated_at ? ` depuis le ${dateLisible(e.updated_at)}` : "");
  const partie = etapes.find((e) => (e.state === "envoyee" || e.state === "incluse") && e.transaction_hash);
  if (partie && !ETAPES_ENVOYEES_D_ICI.includes(partie.step)) {
    const n = numero(partie);
    return {
      code: "attendre_envoi",
      surTitre,
      etape: n,
      titre: partie.state === "envoyee" ? `Attendez la réponse du registre public pour l'étape ${n}` : `Attendez que la preuve de l'étape ${n} soit rangée dans le dossier`,
      phrase: `Cette étape se fait chez le client, avec ses propres outils : vous n'avez rien à lancer d'ici. ${partie.state === "envoyee" ? `Elle est notée « Envoyée »${depuis(partie)} et attend la réponse du registre public` : `Le registre public l'a inscrite${depuis(partie)}, mais sa preuve n'est pas encore rangée dans le dossier`}. Le client a fait sa part : si la fiche n'a pas changé à votre prochaine visite, prévenez l'équipe technique.`,
      aPreparer: "Rien à préparer.",
      apres: "Le bouton relit seulement la fiche : rien n'est envoyé, rien n'est dépensé. Cet outil ne sait pas combien de temps le registre public mettra à répondre.",
      bouton: "Actualiser la fiche",
      lien: `/clients/${slug}`,
    };
  }
  if (partie) {
    const n = numero(partie);
    const envoyee = partie.state === "envoyee";
    return {
      code: "reprendre_envoi",
      surTitre,
      commande: "capturer",
      etape: n,
      parametre: envoyee ? "envoi" : "transaction",
      valeur: partie.transaction_hash,
      titre: `Allez chercher la réponse du registre public pour l'étape ${n}`,
      phrase: envoyee
        ? "Une opération est partie vers le registre public, mais sa réponse n'est pas rangée dans le dossier. L'outil va chercher cette réponse et range la preuve de l'opération. Il ne renvoie jamais une opération déjà partie."
        : "Le registre public a inscrit l'opération, mais sa preuve n'est pas encore rangée dans le dossier. L'outil va la chercher et la range. Il ne renvoie jamais une opération déjà partie.",
      aPreparer: "Rien à préparer : l'outil sait quelle opération est partie.",
      // L'attente de la réponse est réglée dans le service d'inscription (`delai_s`, 120 secondes par défaut, comme
      // `--delai` de CT-4 7.3) : la consigne dit cette durée comme l'ordinaire, pas comme une promesse.
      apres: envoyee
        ? "Après le clic : l'outil va chercher la réponse du registre public et l'attend, quelques minutes d'ordinaire. S'il l'obtient, l'étape passe à « Fait » et la fiche vous donne la consigne suivante. Sinon, la fiche ne change pas : prévenez alors l'équipe technique, sans rien lancer d'autre."
        : "Après le clic : l'outil range la preuve, l'étape passe à « Fait » et la fiche vous donne la consigne suivante. Si la fiche ne change pas, prévenez l'équipe technique, sans rien lancer d'autre.",
      bouton: CHERCHER_LA_REPONSE.bouton,
      sousBouton: CHERCHER_LA_REPONSE.sousBouton,
    };
  }
  const conduites = etapes.filter((e) => ETAPES_CONDUITES.includes(e.step));
  const restantes = conduites.filter((e) => !faite(e));
  if (restantes.length > 0) {
    const cles = versementsSansConfirmation(dossier, confirmations);
    if (cles.length > 0) {
      return {
        code: "consigner_confirmation",
        surTitre,
        titre: "Notez la confirmation du client",
        phrase: "Avant que nous versions des crédits d'écriture sur son compte technique, le client doit confirmer l'opération par un autre moyen que cet outil : un appel au numéro de son contrat, un courrier signé. Sans cette confirmation notée ici, l'outil ne verse rien.",
        credits: CREDITS_EN_CLAIR,
        adresse: ADRESSE_A_CONFIRMER,
        aPreparer: "Ayez sous la main : le nom et la fonction de la personne qui a confirmé, le moyen employé, la date et l'heure, et la pièce qui en garde la trace (le courrier signé, ou votre compte rendu de l'appel).",
        apres: "Après le clic : vous arrivez sur l'écran des confirmations de ce client, où vous remplissez le formulaire. Rien n'est envoyé au registre public.",
        bouton: "Aller noter la confirmation",
        lien: `/clients/${slug}/confirmations`,
        cles,
      };
    }
    const dernier = 1 + conduites.length;
    const n = numero(restantes[0]);
    const jusqua = n === dernier ? `l'étape ${n}` : `les étapes ${n} à ${dernier}`;
    const commun = { code: "conduire_etapes", surTitre, commande: "inscrire-client", premiereEtape: n, derniereEtape: dernier };
    if (restantes.some((e) => e.state === "echec")) {
      return {
        ...commun,
        variante: "reprendre_echec",
        titre: `Reprenez à l'étape ${n}`,
        phrase: `L'outil vérifie d'abord ce qui est réellement inscrit sur le registre public, puis refait ${jusqua}. Les étapes déjà faites ne sont pas refaites.`,
        aPreparer: "Rien à préparer.",
        apres: "Après le clic : l'outil travaille seul et la fiche se met à jour. Refaire une étape coûte de nouveau des crédits d'écriture. Si l'étape échoue une deuxième fois, n'insistez pas : prévenez l'équipe technique.",
        bouton: `Reprendre à l'étape ${n}`,
      };
    }
    if (restantes.length < conduites.length) {
      return {
        ...commun,
        variante: "continuer",
        titre: `Continuez l'inscription à l'étape ${n}`,
        phrase: `Les étapes précédentes sont faites. L'outil fait maintenant ${jusqua}, sans refaire les autres.`,
        aPreparer: "Rien à préparer.",
        apres: "Après le clic : l'outil travaille seul et la fiche se met à jour. S'il rencontre un refus, il s'arrête et vous dit pourquoi. Chaque écriture sur le registre public coûte des crédits d'écriture.",
        bouton: `Continuer à l'étape ${n}`,
      };
    }
    return {
      ...commun,
      variante: "commencer",
      titre: "Lancez l'inscription sur le registre public",
      phrase: "La confirmation du client est notée. L'outil peut maintenant enregistrer les approbateurs, les rattacher au client, contrôler le résultat, puis alimenter le compte technique.",
      aPreparer: "Rien à préparer.",
      apres: `Après le clic : l'outil enchaîne les étapes 2 à ${dernier} sans vous et la fiche se met à jour. S'il rencontre un refus, il s'arrête, vous dit pourquoi, et reprendra là où il s'est arrêté. Chaque écriture sur le registre public coûte des crédits d'écriture.`,
      bouton: `Commencer les étapes 2 à ${dernier}`,
    };
  }
  const inscription = etapes.find((e) => e.step === "inscription" && !faite(e));
  if (inscription) {
    const keyId = inscription.subject;
    const preparee = demandes.some((d) => d.nom.startsWith(`demande-inscription-${keyId}-`));
    if (!preparee) {
      return {
        code: "preparer_demande",
        surTitre,
        commande: "condense-inscription",
        keyId,
        titre: "Préparez le document d'inscription de l'enregistreur",
        phrase: "Pour que l'enregistreur du client soit inscrit sur le registre public, les approbateurs du client doivent donner leur accord en signant un document. L'outil prépare ce document ; il ne le signe jamais.",
        aPreparer: "Rien à préparer : l'enregistreur est déjà choisi dans la liste ci-dessous.",
        apres: "Après le clic : le document apparaît plus bas sur cette fiche, sous « Documents à faire signer par le client », prêt à être remis à ses approbateurs. Rien n'est envoyé au registre public.",
        bouton: "Préparer le document",
      };
    }
    return {
      code: "relayer_demande",
      surTitre,
      commande: "inscrire-cle",
      keyId,
      titre: "Faites signer le document par les approbateurs du client, puis envoyez-le",
      phrase: "Le document d'inscription de l'enregistreur est prêt. Remettez-le aux approbateurs du client : ils le contrôlent et le signent avec leur propre outil, jamais dans celui-ci. Quand le client vous rend le document signé, envoyez-le ici.",
      aPreparer: "Ayez sous la main : le document signé, tel que le client vous l'a rendu.",
      apres: "Après le clic : l'outil contrôle les signatures, puis envoie le document signé au registre public, qui inscrit l'enregistreur. Cet envoi coûte des crédits d'écriture. Un document mal signé est refusé avant tout envoi.",
      bouton: PAR_NOTRE_COMPTE.bouton,
      sousBouton: PAR_NOTRE_COMPTE.sousBouton,
    };
  }
  const premiere = etapes.find((e) => (e.step === "premiere_ancre" || e.step === "premiere_cloture") && !faite(e));
  if (premiere) {
    return {
      code: "attendre_premiere_periode",
      surTitre,
      titre: "Attendez la première preuve de date du client",
      phrase: "Les deux dernières étapes se font chez le client, sans vous : son enregistreur dépose sa première preuve de date, puis ses approbateurs closent la première période du journal. Vous n'avez rien à lancer.",
      aPreparer: "Rien à préparer.",
      apres: "Cette fiche se met à jour quand ces deux étapes sont enregistrées dans le dossier. Cet outil ne sait pas quand le client les fera : si la fiche n'a pas changé à votre prochaine visite, demandez au client où il en est.",
      bouton: "Actualiser la fiche",
      lien: `/clients/${slug}`,
    };
  }
  const autre = etapes.find((e) => !faite(e));
  if (autre) {
    return {
      code: "etape_inconnue",
      surTitre,
      titre: "Prévenez l'équipe technique : une étape n'est pas connue de cet outil",
      phrase: "Le dossier porte une étape que cette version de l'outil ne sait ni décrire ni faire. Vous ne pouvez pas la terminer d'ici.",
      aPreparer: "Ayez sous la main : le détail de l'étape, lisible plus bas dans la liste des étapes.",
      apres: "Le bouton relit seulement la fiche.",
      bouton: "Actualiser la fiche",
      lien: `/clients/${slug}`,
    };
  }
  const reussi = (commande) => travaux.some((t) => t.commande === commande && t.etat === "fini" && (t.sortie?.result === "reussi" || t.sortie?.result === "deja_fait"));
  if (!paquet?.present && periodes.length > 0 && parties.length === 0) {
    return {
      code: "exporter",
      surTitre,
      commande: "exporter",
      titre: "Préparez les pièces du dossier de preuve",
      phrase: "Toutes les étapes sont faites. L'outil copie maintenant, depuis le registre public, les pièces qui entreront dans le dossier de preuve du client : l'ensemble des pièces qui prouvent ce qu'un agent logiciel a fait, et quand.",
      aPreparer: "Rien à préparer : gardez les choix proposés.",
      apres: "Après le clic : les pièces sont rangées avec le dossier du client. Rien n'est écrit sur le registre public, rien n'est dépensé.",
      bouton: "Préparer les pièces",
    };
  }
  if (!paquet?.present && periodes.length > 0 && parties.length > 0 && !reussi("verifier")) {
    return {
      code: "verifier",
      surTitre,
      commande: "verifier",
      titre: "Contrôlez les pièces du dossier de preuve",
      phrase: "Les pièces sont prêtes. L'outil les contrôle comme le fera l'outil de vérification du client, pour que le client ne reçoive rien de faux.",
      aPreparer: "Rien à préparer : gardez les choix proposés.",
      apres: "Après le clic : l'outil dit si chaque contrôle a réussi. Rien n'est écrit sur le registre public, rien n'est dépensé.",
      bouton: "Contrôler les pièces",
    };
  }
  if (!paquet?.present) {
    return {
      code: "produire_paquet",
      surTitre,
      titre: "Produisez le paquet du client",
      phrase: "L'inscription est faite. Le paquet réunit ce que le client doit recevoir pour régler son service d'approbation et son enregistreur, et pour contrôler lui-même son inscription.",
      aPreparer: "Ayez sous la main : le nom à inscrire comme producteur du paquet (le nom de notre société).",
      apres: "Après le clic : vous arrivez sur l'écran du paquet, où vous le produisez puis le téléchargez. Rien n'est envoyé au registre public.",
      bouton: "Aller produire le paquet",
      lien: `/clients/${slug}/paquet`,
    };
  }
  return {
    code: "remettre_paquet",
    surTitre: "Inscription terminée",
    titre: "Remettez le paquet au client",
    phrase: "L'inscription est faite et le paquet est produit. Si ce n'est pas déjà fait, téléchargez le paquet et remettez-le au client, avec son empreinte.",
    aPreparer: "Rien à préparer.",
    apres: "Après le clic : vous arrivez sur l'écran du paquet, où se trouvent le bouton de téléchargement et l'empreinte à donner au client.",
    bouton: "Voir le paquet à remettre",
    lien: `/clients/${slug}/paquet`,
  };
}

/**
 * Comptes techniques dont le versement de l'inscription reste à faire (étape `approvisionnement` à faire ou en
 * échec) sans confirmation du client prête à servir pour lui (EX-7.26 : une confirmation non consommée par
 * versement).
 */
function versementsSansConfirmation(dossier, confirmations) {
  return (dossier.steps ?? []).filter((e) => e.step === "approvisionnement" && (e.state === "a_faire" || e.state === "echec"))
    .filter((e) => !confirmations.some((c) => c.operation === "approvisionnement" && c.objet?.cle_chaine === e.subject && !c.consommee_par))
    .map((e) => e.subject);
}

/** Un document préparé (`demande-…`) que l'agent a relayé signé (`demande-<opération>-relayee-…`). */
const estRelayee = (x) => /^demande-(inscription|administration)-relayee-/.test(x.nom);

/**
 * Confirmations du client qu'on attend de noter maintenant (complément du 2026-11-18, troisième lecture des
 * écrans) : `[{ operation, cle_chaine }]` pour un versement de l'inscription qui reste à faire sans confirmation prête
 * à servir (la même règle que la consigne de la fiche), `[{ operation: "administrer-jeu", digest }]` pour un document
 * de changement des approbateurs préparé, ni envoyé ni remplacé par sa version signée, sans confirmation prête à
 * servir pour son empreinte. Liste vide : aucune confirmation n'est attendue (un nouveau versement, après
 * l'inscription, n'est pas prévisible d'ici ; il reste possible de le noter). L'agent refait son contrôle (EX-7.26).
 */
export function confirmationsAttendues({ dossier, confirmations = [], demandes = [] }) {
  const l = versementsSansConfirmation(dossier, confirmations).map((cle) => ({ operation: "approvisionnement", cle_chaine: cle }));
  const relayees = new Set(demandes.filter(estRelayee).map((x) => x.document?.digest));
  for (const x of demandes) {
    if (!x.nom.startsWith("demande-administration-") || estRelayee(x)) continue;
    const digest = x.document?.digest;
    if (typeof digest !== "string" || relayees.has(digest)) continue;
    if (confirmations.some((c) => !c.consommee_par && c.operation === "administrer-jeu" && c.objet?.digest === digest)) continue;
    l.push({ operation: "administrer-jeu", digest });
  }
  return l;
}

/**
 * Ce que sont les crédits d'écriture, pour que la personne sache l'expliquer au client (CT-4 EX-4.16 : ils ne
 * servent qu'à payer les écritures, ne se vendent, ne s'achètent ni ne s'échangent, et ne circulent que de notre
 * compte de paiement vers un compte approvisionné ; EX-4.19 : le compte technique de chaque enregistreur en reçoit).
 */
export const CREDITS_EN_CLAIR = "Les crédits d'écriture paient les écritures de l'enregistreur du client sur le registre public : chaque preuve de date, chaque clôture de période. Ils ne s'achètent pas et ne se vendent pas : c'est notre société qui les verse, depuis son compte de paiement.";
/**
 * Comment faire confirmer l'adresse du compte (CT-4 EX-7.26, EX-8.21 : la confirmation porte sur l'opération et son
 * objet, le compte entier, et une pièce en garde la trace) : par écrit et en entier, jamais dictée ni comparée en partie.
 */
export const ADRESSE_A_CONFIRMER = "Ne la dictez pas : 42 caractères ne se lisent pas à voix haute sans erreur. Envoyez-la au client par écrit, par un autre moyen que cet outil, et demandez-lui de vous répondre par écrit qu'elle est bien, en entier, celle du compte technique de son enregistreur. Gardez sa réponse avec la pièce de la confirmation.";

/**
 * Envoi d'un document signé (`inscrire-cle`, `administrer-jeu`) par notre compte d'envoi, le relayeur de
 * l'exploitant (CT-4 EX-7.3, OP-5) : c'est le cas habituel, et le bouton dit lui-même qui envoie ; la route reçoit
 * `relayeur: true`, comme avant (complément du 2026-11-18, troisième lecture des écrans). L'envoi par le compte
 * qu'une référence désigne, pour les essais, est une action à part, rangée, avec son champ.
 */
export const PAR_NOTRE_COMPTE = Object.freeze({
  bouton: "Envoyer par notre compte d'envoi",
  sousBouton: "C'est le cas habituel : notre société envoie le document signé au registre public et paie cet envoi.",
});
/**
 * Reprise d'un envoi resté sans réponse (travail `capturer`) : elle ne fait que lire le registre public (le reçu
 * de la transaction connue, sa preuve) et ranger cette preuve dans le dossier ; elle ne soumet aucune transaction
 * (EX-7.13, EX-7.16). Une seule formule pour ce geste, partout : aller chercher la réponse du registre public.
 */
export const CHERCHER_LA_REPONSE = Object.freeze({
  bouton: "Chercher la réponse",
  sousBouton: "Rien n'est renvoyé, rien n'est dépensé.",
});

/** Commandes des travaux (INTERFACES.md 3.3) : nom courant de l'action. */
export const COMMANDES = Object.freeze({
  "inscrire-client-preparer": "Préparer le dossier",
  "inscrire-client": "Faire les étapes 2 à 5",
  approvisionner: "Alimenter un compte technique",
  "condense-inscription": "Préparer le document d'inscription à faire signer",
  "inscrire-cle": "Envoyer le document d'inscription signé",
  "condense-administration": "Préparer un changement des approbateurs",
  "administrer-jeu": "Envoyer un changement des approbateurs signé",
  capturer: "Aller chercher la réponse du registre public",
  exporter: "Préparer les pièces du dossier de preuve",
  verifier: "Contrôler les pièces du dossier de preuve",
  paquet: "Produire le paquet du client",
});

/** Nom courant d'une commande ; inconnue : son code. */
export const libelleCommande = (commande) => COMMANDES[commande] ?? `Commande ${commande}`;

const RESULTATS = Object.freeze({
  reussi: { libelle: "Réussi", ton: "succes", icone: "coche", explication: "L'action est faite." },
  deja_fait: { libelle: "Déjà fait", ton: "succes", icone: "coche", explication: "Il n'y avait plus rien à faire : c'était déjà fait. Rien n'a été envoyé." },
  refuse: { libelle: "Refusé avant envoi", ton: "refus", icone: "croix", explication: "L'outil a contrôlé avant d'agir et s'est arrêté : rien n'a été envoyé, rien n'a été dépensé." },
  echoue: { libelle: "Échec", ton: "refus", icone: "croix", explication: "L'opération a été envoyée, mais elle n'a pas abouti." },
  incertain: { libelle: "Résultat pas encore connu", ton: "attente", icone: "question", explication: "L'opération est partie, mais la réponse du registre public n'est pas arrivée. Ne relancez pas l'action : allez chercher la réponse du registre public, depuis la fiche du client." },
  inutilisable: { libelle: "Impossible à exécuter", ton: "", icone: "question", explication: "L'outil n'a pas pu aller au bout et n'affirme rien. La fiche du client dit ce qui est réellement fait." },
});

/** Mot d'un travail d'ensemble fini « réussi » alors qu'une de ses étapes est en échec dans le dossier. */
const AVEC_ECHEC = Object.freeze({ libelle: "Terminé, avec une étape en échec", ton: "refus", icone: "croix", explication: "L'action est allée au bout, mais le dossier porte une étape en échec : c'est l'étape qui fait foi. Reprenez-la." });

/**
 * État d'un travail (`etat`, et `sortie.result` s'il est fini) en mots : `{ code, libelle, ton, icone, explication,
 * termine }`. Avec `dossier` et `dernier` (ce travail est le plus récent de sa commande) : un travail fini
 * « réussi » dont une étape est en échec dans le dossier se dit « Terminé, avec une étape en échec », pour que
 * l'écran ne dise jamais « réussi » à côté d'un échec.
 */
export function etatTravail(t, { dossier = null, dernier = false } = {}) {
  if (!t) return { code: "", libelle: "", ton: "", icone: "tiret", explication: "", termine: false };
  if (t.etat === "en_attente") return { code: "en_attente", libelle: "En attente de son tour", ton: "", icone: "horloge", explication: "Le service d'inscription fait une action à la fois : celle-ci attend la fin de la précédente. Vous n'avez rien à faire.", termine: false };
  if (t.etat === "en_cours") return { code: "en_cours", libelle: "En cours", ton: "info", icone: "horloge", explication: "Le service d'inscription exécute l'action. Laissez cette page ouverte : elle se met à jour toute seule.", termine: false };
  if (t.etat === "refuse") return { code: "refuse", libelle: "Refusé avant de commencer", ton: "refus", icone: "croix", explication: "Le service d'inscription a refusé l'action avant de commencer : rien n'a été envoyé, rien n'a été dépensé.", termine: true };
  if (t.etat === "abandonne") return { code: "abandonne", libelle: "Interrompu", ton: "", icone: "tiret", explication: "Le service d'inscription s'est arrêté pendant l'action. La fiche du client dit ce qui est réellement fait : relancez l'action.", termine: true };
  if (t.etat === "fini") {
    const r = RESULTATS[t.sortie?.result];
    if (r) {
      const reussi = t.sortie.result === "reussi" || t.sortie.result === "deja_fait";
      const siennes = ETAPES_DE_COMMANDE[t.commande] ?? [];
      if (reussi && dernier && dossier && (dossier.steps ?? []).some((e) => siennes.includes(e.step) && e.state === "echec")) return { code: t.sortie.result, ...AVEC_ECHEC, termine: true };
      return { code: t.sortie.result, ...r, termine: true };
    }
    return { code: String(t.sortie?.result ?? ""), libelle: `Fini (${t.sortie?.result ?? "sans résultat"})`, ton: "", icone: "question", explication: "", termine: true };
  }
  return { code: String(t.etat ?? ""), libelle: `État ${t.etat}`, ton: "", icone: "question", explication: "", termine: false };
}

/**
 * États des travaux d'un client, dans l'ordre donné (les plus récents d'abord) : le plus récent de chaque commande
 * est confronté au dossier (voir `etatTravail`).
 */
export function etatsTravaux(travaux, dossier) {
  const vues = new Set();
  return travaux.map((t) => {
    const dernier = !vues.has(t.commande);
    vues.add(t.commande);
    return etatTravail(t, { dossier, dernier });
  });
}

const RIEN = "Rien n'a été envoyé au registre public et rien n'a été dépensé.";
const VOIR_FICHE = "La liste des étapes, sur la fiche du client, dit ce qui est réellement fait.";
const PARTI = "L'opération est partie vers le registre public ; elle a pu coûter des crédits d'écriture.";
const PREUVE = "L'opération elle-même est partie ; seule sa preuve manque dans le dossier. Rien n'est à renvoyer.";
const PREVENIR = "Si cela se reproduit, prévenez l'équipe technique en lui donnant le détail ci-dessous.";
const REPRENDRE = "Ne renvoyez rien. Actualisez la fiche du client : elle vous propose d'aller chercher la réponse du registre public.";
const E = (phrase, effet, quoiFaire, plus = {}) => Object.freeze({ phrase, effet, quoiFaire, ...plus });
const CERTIFICAT = E("L'opération est inscrite, mais sa preuve n'a pas pu être rangée dans le dossier.", PREUVE, `${REPRENDRE} Si la preuve reste introuvable, prévenez l'équipe technique sans attendre : elle n'est gardée qu'un temps.`);
const CLE_OCCUPEE = E("Cet enregistreur ou son compte technique ne peut pas être inscrit : il l'est déjà, il a été retiré, ou il sert à un autre client.", RIEN, "Demandez au client la fiche d'un nouvel enregistreur, avec un nouveau compte technique. Un compte technique retiré ne se réinscrit jamais.");
const SIGNATURES = E("Les signatures du document ne conviennent pas : un signataire n'est pas un approbateur du client, une signature n'a pas la forme attendue, ou il n'y en a pas assez.", RIEN, "Demandez au client de faire signer le document par assez d'approbateurs de sa liste, puis envoyez de nouveau le document signé.");
const PERIODE = E("La période du journal est refusée : sa description est mal formée, elle est déjà enregistrée, ou elle ne suit pas la précédente.", RIEN, "Rien ne se corrige d'ici : prévenez le client, c'est son enregistreur qui doit refaire la description de la période.");
const PAQUET = E("Le contrôle du paquet a refusé un fichier.", "Le paquet n'est pas bon à remettre. Rien n'a été envoyé au registre public.", "Produisez le paquet de nouveau. Si le refus revient, ne remettez rien au client et prévenez l'équipe technique en lui donnant le détail ci-dessous.");
const RESEAU = E("Le registre que joint le service d'inscription n'est pas celui du dossier de ce client.", RIEN, "N'insistez pas et ne contournez rien : prévenez l'équipe technique, qui vérifiera les réglages du service d'inscription.");

/**
 * Erreurs des travaux et des étapes (CT-4 7.11, EX-7.26, EX-7.30) et refus de l'interface : ce qui s'est passé,
 * si quelque chose a été envoyé ou dépensé, et quoi faire. `fixe` : phrase que CT-4 fixe mot pour mot, affichée
 * telle quelle sous la phrase courante.
 */
const ERREURS = Object.freeze({
  confirmation_absente: E("Rien n'a été envoyé : il manque la confirmation du client pour cette opération.", RIEN, "Notez la confirmation du client sur l'écran « Confirmations du client », puis relancez l'action.", { fixe: "confirmation hors bande absente" }),
  reference_refusee: E("La référence donnée pour désigner un compte est refusée.", RIEN, "Laissez ce champ vide si l'équipe technique ne vous a pas donné de référence. Ne saisissez jamais une clé secrète : seulement la référence qu'on vous a donnée."),
  requete_invalide: E("Un champ du formulaire n'a pas la forme attendue.", RIEN, "Relisez les champs en suivant l'aide écrite sous chacun, corrigez, puis relancez. Le détail ci-dessous nomme le champ."),
  agent_injoignable: E("Le service d'inscription ne répond pas : votre action n'est pas partie.", RIEN, "Attendez une minute, puis recommencez. Si le service ne répond toujours pas, prévenez l'équipe technique : il doit être redémarré."),
  session_absente: E("Votre connexion à l'outil a pris fin : votre action n'est pas partie.", RIEN, "Reconnectez-vous, revenez sur cet écran, puis recommencez. Ce que vous aviez saisi dans le formulaire est à refaire."),
  client_inconnu: E("Ce client n'existe pas dans l'outil.", RIEN, "Revenez à la liste des clients et vérifiez le nom du client."),
  file_pleine: E("Trop d'actions attendent déjà leur tour : celle-ci n'a pas été prise.", RIEN, "Attendez que les actions en cours se terminent, puis recommencez."),
  travail_inconnu: E("L'outil ne retrouve pas cette action.", VOIR_FICHE, "Actualisez la fiche du client : son historique dit ce qui a été fait."),
  paquet_absent: E("Aucun paquet n'est produit pour ce client.", "Rien n'a été téléchargé.", "Produisez d'abord le paquet sur cet écran."),
  corps_trop_grand: E("Ce que vous envoyez est trop volumineux pour l'outil.", RIEN, "Vérifiez que vous avez collé le bon document, et lui seul, puis recommencez."),
  longueur_exigee: E("L'envoi n'a pas la forme que l'outil attend.", RIEN, `Rechargez la page, puis recommencez. ${PREVENIR}`),
  origine_refusee: E("L'outil a refusé cette action, qui ne vient pas de son adresse habituelle.", RIEN, "Ouvrez l'outil par son adresse habituelle, reconnectez-vous, puis recommencez."),
  hote_refuse: E("L'outil a refusé cette action, qui ne lui était pas adressée par son adresse habituelle.", RIEN, "Ouvrez l'outil par son adresse habituelle, reconnectez-vous, puis recommencez."),
  configuration: E("L'outil est mal réglé et ne peut pas répondre.", RIEN, "Prévenez l'équipe technique : vous ne pouvez rien corriger d'ici."),
  outil_injoignable: E("L'outil ne répond pas : votre action n'est sans doute pas partie.", VOIR_FICHE, "Vérifiez que votre poste est bien relié au réseau, rechargez la page, puis regardez la fiche du client avant de recommencer. Si cela dure, prévenez l'équipe technique."),
  suivi_interrompu: E("L'outil n'arrive plus à suivre l'action que vous avez lancée.", "L'action, elle, n'est pas annulée : le service d'inscription la poursuit.", "Reconnectez-vous si l'outil le demande, puis ouvrez la fiche du client : son historique dit comment l'action s'est terminée. Ne la relancez pas avant de l'avoir lu."),
  usage: E("L'action a reçu une indication qu'elle n'attend pas.", RIEN, `Corrigez la saisie en suivant l'aide écrite sous chaque champ, puis relancez. ${PREVENIR}`),
  entree_illisible: E("Un document donné est illisible ou n'a pas la forme attendue.", RIEN, "Vérifiez que vous avez collé le document en entier, sans rien y changer, puis relancez. S'il vient du client, demandez-lui de vous le renvoyer."),
  instance_illisible: E("La description du registre public, que le service d'inscription doit lire, est illisible ou a changé.", RIEN, "Prévenez l'équipe technique : vous ne pouvez rien corriger d'ici."),
  reseau_non_developpement: E("Un compte réservé aux essais est employé sur un registre qui n'est pas un registre d'essai.", RIEN, "N'employez pas les réglages d'essai pour un vrai client. Dans le doute, prévenez l'équipe technique."),
  chaine_differente: RESEAU,
  jeu_validateurs_different: RESEAU,
  code_absent: RESEAU,
  noeud_injoignable: E("Le registre public ne répond pas au service d'inscription.", VOIR_FICHE, "Attendez quelques minutes, puis relancez l'action : l'outil vérifie d'abord ce qui est déjà fait. Si le registre ne répond toujours pas, prévenez l'équipe technique."),
  noeud_suiveur: E("Le service d'inscription est branché sur un point d'accès du registre public qui ne convient pas pour écrire.", RIEN, "Prévenez l'équipe technique : vous ne pouvez rien corriger d'ici."),
  organisation_existante: E("Un client de ce nom court est déjà enregistré sur le registre public, avec d'autres approbateurs.", RIEN, "Choisissez un autre nom court et préparez un nouveau dossier. Pour changer les approbateurs d'un client déjà inscrit, c'est, sur sa fiche, « Actions rarement utiles », puis « Préparer un changement des approbateurs »."),
  organisation_inconnue: E("Ce client n'est pas encore enregistré sur le registre public.", RIEN, "Faites d'abord les étapes 2 à 5 de l'inscription."),
  jeu_invalide: E("La liste des approbateurs du dossier est refusée : une adresse, le nombre d'approbations requises ou le responsable des approbateurs ne convient pas.", RIEN, "Vérifiez ces informations avec le client, puis préparez un nouveau dossier avec les bonnes valeurs."),
  cle_invalide: E("L'enregistreur du client ou son compte technique n'est pas gardé de façon assez sûre pour un vrai client.", RIEN, "Demandez au client la fiche d'un enregistreur gardé comme nos règles l'exigent pour un vrai client ; l'équipe technique lui dira lesquelles."),
  compte_inattendu: E("Un de nos comptes n'est pas celui que le registre public attend pour ce rôle, ou le destinataire du versement n'est pas admis.", RIEN, "Prévenez l'équipe technique : les comptes du service d'inscription sont à vérifier."),
  pas_administrateur: E("Le signataire n'est pas la personne qui a le droit de faire ce changement, ou le document est périmé.", RIEN, "Préparez un nouveau document, puis faites-le signer par le responsable des approbateurs du client."),
  solde_insuffisant: E("Le compte qui devait envoyer l'opération n'a plus assez de crédits d'écriture.", RIEN, "S'il s'agit du compte technique du client, alimentez-le : sur la fiche du client, « Actions rarement utiles », puis « Alimenter un compte technique ». S'il s'agit d'un de nos comptes, prévenez l'équipe technique."),
  provision_excessive: E("Le versement demandé dépasse ce qui est permis pour un compte technique.", RIEN, "Laissez vide le budget d'écriture par jour, pour employer la valeur habituelle, puis relancez."),
  examen_requis: E("Ce compte technique dépense plus du double de son budget : l'outil refuse de l'alimenter sans examen.", RIEN, "Ne forcez rien. Prévenez l'équipe technique, qui examinera cette dépense avec le client avant tout nouveau versement."),
  transaction_en_attente: E("Une opération envoyée par le même compte attend encore la réponse du registre public.", "Rien de nouveau n'a été envoyé.", REPRENDRE),
  nonce_incoherent: E("Les points d'accès du registre public ne sont pas d'accord entre eux sur le rang de la prochaine opération.", RIEN, "C'est passager : attendez quelques minutes, puis relancez l'action."),
  condense_different: E("Le document signé ne correspond pas à ce que le registre public attend : il a été modifié, ou il vise autre chose.", RIEN, "Préparez un nouveau document et faites signer celui-là. Ne faites pas signer l'ancien."),
  signature_non_canonique: SIGNATURES,
  signataire_hors_jeu: SIGNATURES,
  signatures_insuffisantes: SIGNATURES,
  cle_deja_active: CLE_OCCUPEE,
  cle_revoquee: CLE_OCCUPEE,
  cle_ed25519_active: CLE_OCCUPEE,
  cle_chaine_autre_organisation: CLE_OCCUPEE,
  cle_inconnue: E("Cet enregistreur n'est pas connu du registre public.", RIEN, "Inscrivez d'abord l'enregistreur (étape « Inscrire l'enregistreur »)."),
  cle_chaine_non_inscrite: E("Le compte technique de l'enregistreur n'est pas encore inscrit sur le registre public.", RIEN, "Inscrivez d'abord l'enregistreur (étape « Inscrire l'enregistreur »)."),
  empreinte_squattee: E("Cette preuve de date a déjà été déposée par quelqu'un d'autre.", RIEN, "Ne réessayez pas. Prévenez le client et l'équipe technique."),
  ancre_manquante: E("La preuve de date de cette période n'est pas encore inscrite et rangée dans le dossier.", RIEN, "Attendez que l'enregistreur du client ait déposé sa preuve de date, puis relancez."),
  demande_existante: E("Un autre document de clôture a déjà été envoyé pour cette période.", RIEN, "Ne refaites pas le document : celui qui a été envoyé fait foi."),
  demande_expiree: E("Le document à faire signer a dépassé sa date limite.", RIEN, "Préparez un nouveau document et faites signer celui-là. Ne faites pas signer l'ancien."),
  periode_invalide: PERIODE,
  doublon: PERIODE,
  discontinuite_temporelle: PERIODE,
  discontinuite_sequence: PERIODE,
  transaction_refusee: E("Le registre public a refusé l'opération dès son envoi : elle n'est pas partie.", RIEN, "Relancez une fois. Si le refus revient, prévenez l'équipe technique : un réglage des frais d'écriture est à revoir."),
  transaction_annulee: E("L'opération a été envoyée, mais le registre public l'a refusée, ou le contrôle fait juste après ne retrouve pas ce qui devait être inscrit.", "Cet envoi a coûté des crédits d'écriture. L'outil vérifiera ce qui est réellement inscrit avant de refaire quoi que ce soit.", "Relancez l'action une fois. Si elle échoue de nouveau, n'insistez pas : prévenez l'équipe technique en lui donnant le détail de l'étape."),
  recu_absent: E("L'opération est partie, mais le registre public n'a pas répondu dans le délai : nous ne savons pas encore si elle est inscrite.", PARTI, REPRENDRE),
  certificat_indisponible: CERTIFICAT,
  certificat_elague: CERTIFICAT,
  certificat_invalide: CERTIFICAT,
  capture_incomplete: CERTIFICAT,
  dossier_inacheve: E("Le paquet ne peut pas être produit : une étape de l'inscription n'est pas faite.", RIEN, "Terminez les étapes sur la fiche du client, puis revenez produire le paquet."),
  paquet_manifeste: PAQUET,
  paquet_fichiers: PAQUET,
  paquet_forme: PAQUET,
  paquet_organisation: PAQUET,
  paquet_jeu: PAQUET,
  paquet_captures: PAQUET,
  secret_present: E("Un secret de notre équipe s'est glissé dans un fichier du paquet.", "Le paquet n'est pas bon à remettre. Rien n'a été envoyé au registre public.", "Ne remettez pas ce paquet au client. Prévenez tout de suite l'équipe technique en lui donnant le détail ci-dessous."),
});

/**
 * Explication d'un code d'erreur : `{ phrase, effet, quoiFaire, fixe, connu }`. Un code inconnu reçoit une
 * explication générale ; l'appelant affiche toujours le code et le message exacts dans le détail.
 */
export function explicationErreur(code) {
  const e = Object.hasOwn(ERREURS, code) ? ERREURS[code] : null;
  if (e) return { phrase: e.phrase, effet: e.effet, quoiFaire: e.quoiFaire, fixe: e.fixe ?? null, connu: true };
  return { phrase: "L'action n'a pas abouti, pour une raison que cet outil ne sait pas expliquer.", effet: VOIR_FICHE, quoiFaire: "Ne recommencez pas plusieurs fois de suite : prévenez l'équipe technique en lui donnant le détail ci-dessous.", fixe: null, connu: false };
}

const HEXA = "chiffres et lettres de a à f";
/** Saisie refusée dans la page (types d'EX-7.25) : ce qui ne va pas et quoi corriger, sans recopier la valeur. */
const SAISIES = Object.freeze({
  slug: "Le nom court n'a pas la bonne forme. Corrigez-le : de 1 à 64 caractères, seulement des lettres minuscules sans accent, des chiffres et des tirets, sans espace, sans tiret au début ni à la fin.",
  nom_journal: "Le nom du journal n'a pas la bonne forme. Corrigez-le : de 1 à 64 caractères, seulement des lettres minuscules sans accent, des chiffres et des tirets.",
  liste_noms_journal: "Un nom de journal n'a pas la bonne forme. Corrigez-le : de 1 à 64 caractères, seulement des lettres minuscules sans accent, des chiffres et des tirets ; un nom par ligne.",
  adresse: `Ce n'est pas une adresse de signature. Elle s'écrit « 0x » suivi de 40 caractères (${HEXA}). Copiez-la depuis le document du client au lieu de la retaper.`,
  liste_adresses: `Une des adresses n'a pas la bonne forme. Chacune s'écrit « 0x » suivi de 40 caractères (${HEXA}), une adresse par ligne. Copiez-les depuis le document du client au lieu de les retaper.`,
  hachage: `Ce n'est pas une empreinte. Elle s'écrit « 0x » suivi de 64 caractères (${HEXA}). Servez-vous du bouton qui la calcule, ou copiez-la sans la retaper.`,
  cle_publique_ed25519: `Ce n'est pas une clé publique d'enregistreur. Elle s'écrit « 0x » suivi de 64 caractères (${HEXA}).`,
  seuil: "Le nombre d'approbations requises est un nombre entier de 1 à 64, en chiffres.",
  entier: "Écrivez un nombre entier, en chiffres, sans espace.",
  montant: "Écrivez un nombre entier plus grand que zéro, en chiffres, sans espace ni point.",
  reference_cle: "Ce n'est pas une référence. Une référence commence par « fichier: » ou « alias: » ; ce n'est jamais une clé secrète. Si l'équipe technique ne vous en a pas donné, laissez ce champ vide.",
  texte: "Ce texte est refusé : il est vide, trop long, ou il ressemble à une clé secrète. Écrivez un texte court, en mots.",
  chemin: "Ce n'est pas un nom de fichier admis. Gardez le choix proposé, ou laissez le champ vide.",
  document: "Ce document est illisible. Collez-le en entier, de la première accolade « { » à la dernière « } », sans rien y changer.",
  liste_documents: "Ces fiches sont illisibles. Collez chaque fiche dans sa propre zone, en entier, sans rien y changer.",
  horodatage: "La date et l'heure n'ont pas la forme attendue. Servez-vous du champ « Date et heure » ou du bouton « Maintenant », qui l'écrivent pour vous.",
});

/** Phrase d'une saisie refusée, d'après le type déclaré du champ. */
export const explicationSaisie = (type) => SAISIES[type] ?? "Cette saisie n'a pas la forme attendue. Relisez l'aide écrite sous le champ.";

/**
 * Fiche d'un enregistreur refusée dans la page (complément du 2026-11-18, troisième lecture des écrans) : le champ
 * des fiches (`liste_documents`) a une zone par fiche, où l'on colle le contenu d'un fichier du client tel quel ;
 * une zone vide ou un texte qui n'est pas une fiche est refusé, sans rien envoyer, avec ce qu'il faut faire.
 */
const FICHES = Object.freeze({
  fiche_vide: "Cette zone est vide. Collez-y tout le contenu du fichier que le client vous a envoyé pour son enregistreur, sans rien y changer.",
  fiche_liste: "Cette zone contient une liste entre crochets « [ » et « ] », et non une seule fiche. Collez ici le contenu d'un seul fichier, tel que le client l'a envoyé ; pour une autre fiche, cliquez sur « Ajouter une autre fiche ».",
  fiche_illisible: "Ce texte n'est pas une fiche d'enregistreur, ou il en manque une partie. Ouvrez le fichier que le client vous a envoyé, copiez tout son contenu, du premier caractère « { » au dernier « } », et collez-le ici sans rien y changer. Si le fichier ne commence pas par « { », demandez au client de vous le renvoyer.",
});

/**
 * Pourquoi la première zone ne reste pas vide (une liste vide, que la route admet, est refusée dans la page) : le
 * service d'inscription n'inscrit au registre public que les enregistreurs du dossier (travail `condense-inscription`,
 * paramètre `key_id` d'un enregistreur du dossier), et un dossier préparé ne se prépare pas une seconde fois (CT-4
 * §7.1, pas 6 ; §7.5) : un client préparé sans fiche n'aurait jamais d'enregistreur inscrit par cet outil.
 */
const AU_MOINS_UNE = " Il faut au moins une fiche : l'outil n'inscrit au registre public que les enregistreurs dont la fiche est donnée ici, et il ne pourra plus en ajouter une fois le dossier préparé.";

/** Phrase d'une fiche refusée ; `retirable` : la zone peut être retirée (ce n'est pas la première). */
export const explicationFiche = (regle, retirable = false) => {
  const base = FICHES[regle] ?? FICHES.fiche_illisible;
  if (regle !== "fiche_vide") return base;
  return `${base}${retirable ? " Si vous n'avez pas d'autre fiche, cliquez sur « Retirer cette zone »." : AU_MOINS_UNE}`;
};

/** Opérations sur la liste des approbateurs d'un client (CT-4 6.6.2) : nom courant ; le nom de l'opération reste dans l'option. */
export const OPERATIONS_JEU = Object.freeze({
  "CuratorSet.addCurator": "Ajouter un approbateur",
  "CuratorSet.removeCurator": "Retirer un approbateur",
  "CuratorSet.setThreshold": "Changer le nombre d'approbations requises",
  "CuratorSet.proposeAdmin": "Proposer un nouveau responsable des approbateurs",
  "CuratorSet.acceptAdmin": "Accepter le rôle de responsable des approbateurs",
});

/** Opérations qu'une confirmation du client autorise (INTERFACES.md 3.5) : nom courant. */
export const OPERATIONS_CONFIRMATION = Object.freeze({
  approvisionnement: "Premier versement sur le compte technique (étape 5 de l'inscription)",
  approvisionner: "Nouveau versement sur le compte technique (client déjà inscrit)",
  "administrer-jeu": "Changement de la liste des approbateurs",
});

/**
 * Lexique des écrans : les mots de l'outil, chacun avec l'explication à donner la première fois. Les notions
 * partagées avec la console d'approbation et la page de vérification portent les mots du glossaire commun.
 */
export const LEXIQUE = Object.freeze([
  { terme: "registre public", explication: "un registre que personne ne peut modifier après coup" },
  { terme: "approbateur", explication: "une personne du client qui donne son accord en signant" },
  { terme: "signature", explication: "l'accord d'une personne, donné avec son propre outil de signature : il ne peut pas être imité" },
  { terme: "adresse de signature", explication: "ce qui désigne publiquement la personne qui signe : « 0x » suivi de 40 caractères ; ce n'est pas un secret" },
  { terme: "enregistreur", explication: "le logiciel qui note chaque action de l'agent logiciel du client au moment où elle a lieu" },
  { terme: "journal", explication: "la suite des actions enregistrées, dans l'ordre" },
  { terme: "preuve de date", explication: "une preuve, déposée sur le registre public, que le journal existait à cette date" },
  { terme: "empreinte", explication: "une suite de caractères qui identifie un document sans erreur possible : si un seul caractère du document change, l'empreinte change" },
  { terme: "compte technique", explication: "le compte de l'enregistreur du client sur le registre public : c'est lui qui paie ses écritures" },
  { terme: "crédits d'écriture", explication: "ce qui paie chaque écriture sur le registre public ; ils ne s'achètent ni ne se vendent" },
  { terme: "service d'inscription", explication: "le programme de notre serveur qui exécute les actions que vous lancez d'ici ; lui seul écrit sur le registre public" },
  { terme: "paquet du client", explication: "l'ensemble des fichiers que nous remettons au client à la fin de l'inscription" },
]);
