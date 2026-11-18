// /clients/<slug> : le dossier, ses étapes et leurs états (EX-7.16), les sorties des travaux, et les actions offertes
// selon l'état : pas 2 à 5, approvisionner, condensé d'inscription (la demande se remet aux approbateurs hors de
// l'application, EX-7.27), relais d'une demande signée, capture, export et vérification (pas 10), et administration
// du jeu (demande préparée, remise à l'administrateur du jeu hors de l'application, relais de la demande signée après
// la confirmation hors bande du client : CT-4 §8.5, EX-7.26).
//
// Présentation (complément du 2026-11-17, décision du porteur sur la présentation des écrans) : la fiche se lit
// comme un parcours guidé. En haut, le nom du client, son état et la prochaine action avec son bouton ; une étape
// en échec monte en bandeau. Puis les étapes dans l'ordre ; le détail technique de chaque étape (codes, objet,
// transaction, bloc, capture, erreur, instant exact) est replié et rend les valeurs du dossier telles quelles.
//
// Langage et longueur (complément du 2026-11-18, décision du porteur sur le langage des écrans) : la fiche répond
// d'abord à « où en est ce client, et que dois-je faire ». La prochaine action est une consigne : quoi faire,
// pourquoi, quoi avoir sous la main, ce qui se passe après le clic. Une étape faite ou à venir tient en une ligne ;
// seules l'étape où l'on en est et une étape en échec sont développées. Les actions qui ne servent pas dans l'état
// courant restent accessibles (INTERFACES.md 2.2) dans un bloc replié, chacune avec ce qu'elle fait et quand s'en
// servir ; l'historique est replié. Un travail « réussi » dont une étape est en échec ne se dit jamais « réussi ».
// Tant qu'un envoi est resté sans réponse, la consigne est d'aller chercher la réponse du registre public pour cet
// envoi, et l'écran ne dit que cela.
//
// Troisième lecture des écrans (même complément) : aucun choix n'est demandé pour envoyer un document signé ; le
// bouton dit qui envoie (« Envoyer par notre compte d'envoi », le cas habituel) et l'envoi par le compte qu'une
// référence désigne, pour les essais, est une action rangée, avec son champ ; ce que la route reçoit pour chacun ne
// change pas. L'adresse du compte technique et l'empreinte d'un document de changement se copient d'un bouton. À
// 1280 px, la fiche prend la largeur de l'écran et la consigne sans champ met son bouton à droite de ses phrases,
// pour que le bouton tienne dans le premier écran quelle que soit la police du poste.

import { notFound } from "next/navigation";
import { client, confirmations } from "../../../lib/donnees.mjs";
import { exigerSession, nature } from "../../../lib/page.mjs";
import { CHERCHER_LA_REPONSE, OPERATIONS_JEU, PAR_NOTRE_COMPTE, avancement, dateLisible, etapesDuParcours, etatsTravaux, explicationErreur, jourLisible, libelleCommande, nombreLisible, prochaineAction } from "../../../lib/parcours.mjs";
import CopierTexte, { CopierValeur } from "../../../composants/CopierTexte.js";
import FormulaireTravail from "../../../composants/FormulaireTravail.js";
import Icone from "../../../composants/Icone.js";
import Lexique from "../../../composants/Lexique.js";
import Pastille from "../../../composants/Pastille.js";
import Valeur from "../../../composants/Valeur.js";

export const dynamic = "force-dynamic";

const OPERATIONS = Object.entries(OPERATIONS_JEU).map(([o, libelle]) => ({ valeur: o, libelle: `${libelle} (${o})` }));
const NOMS_DEMANDE = { inscription: "Document d'inscription d'un enregistreur", administration_jeu: "Document de changement des approbateurs", revocation: "Document de retrait d'un enregistreur", cloture: "Document de clôture d'une période" };
/** Codes d'erreur après lesquels « Aller chercher la réponse du registre public » est l'action à faire. */
const ENVOI_A_REPRENDRE = new Set(["transaction_en_attente", "recu_absent", "certificat_indisponible", "certificat_elague", "certificat_invalide", "capture_incomplete"]);

/** Une demande que l'agent a relayée (`demande-inscription-relayee-…`, `demande-administration-relayee-…`). */
const estRelayee = (x) => /^demande-(inscription|administration)-relayee-/.test(x.nom);

/** Le document signé à coller, pour l'envoi d'une inscription ou d'un changement des approbateurs. */
const DOCUMENT_INSCRIPTION = { nom: "demande", libelle: "Document signé", type: "document", aide: "Collez ici, en entier et sans rien y changer, le texte que le client vous a rendu après signature : il commence par « { » et finit par « } »." };
const DOCUMENT_ADMINISTRATION = { nom: "demande", libelle: "Document signé", type: "document", aide: "Collez ici, en entier et sans rien y changer, le texte du document signé par le responsable des approbateurs du client." };
/** Une référence d'essai, refusée vide par la page : l'action ne part pas sans elle. */
const REFERENCE_REQUISE = "Écrivez ici la référence que l'équipe technique vous a donnée. Si vous n'en avez pas, servez-vous du bouton « Envoyer par notre compte d'envoi ». Rien n'a été envoyé.";
/** Identifiant de l'élément qui affiche le texte exact d'un document (sélectionné si la copie est refusée). */
const idTexte = (nom) => `texte-${nom.replace(/[^A-Za-z0-9-]/g, "-")}`;

/**
 * Les actions de la fiche : nom, ce que l'action fait, quand s'en servir, et le formulaire de son travail. `cle`
 * distingue deux actions d'une même commande : l'envoi d'un document signé par notre compte d'envoi (le relayeur de
 * l'exploitant, seul admis pour un vrai client : CT-4 EX-7.3, OP-5 ; la route reçoit `relayeur: true`) et son envoi
 * par le compte qu'une référence désigne, pour les essais (la route reçoit la référence seule).
 */
function actions({ d, c, action, etapes }) {
  const cles = d.recorders.map((r) => ({ valeur: r.chain_key, libelle: `${r.key_id} · ${r.chain_key}` }));
  const keyIds = d.recorders.map((r) => ({ valeur: r.key_id, libelle: r.key_id }));
  const periodes = c.periodes.map((p) => ({ valeur: p, libelle: p }));
  const parties = c.parties.map((p) => ({ valeur: p, libelle: p }));
  // Les envois dont « Aller chercher la réponse du registre public » peut lire la réponse : l'étape se choisit, son identifiant ne se recopie pas.
  const enVol = (etat) => etapes.filter((e) => e.etat === etat).map((e) => ({ valeur: e.technique.find((x) => x.membre === "transaction_hash")?.valeur ?? "", libelle: `Étape ${e.numero} : ${e.titre}` })).filter((x) => x.valeur !== "");
  const choix = (liste, parDefaut = true) => (liste.length > 0 ? { options: [...liste, { valeur: "", libelle: "Aucune" }], defaut: parDefaut ? liste[0].valeur : "" } : {});
  const envoyees = enVol("envoyee");
  const inscrites = enVol("incluse");
  const l = [
    {
      commande: "inscrire-client", cle: "inscrire-client", groupe: "Inscription", titre: libelleCommande("inscrire-client"),
      quoi: "Fait, dans l'ordre, celles des étapes 2 à 5 qui restent : enregistrer les approbateurs, les rattacher au client, les contrôler, alimenter le compte technique. Une étape déjà faite n'est pas refaite.",
      quand: "Quand la prochaine action, en haut de la fiche, vous le propose. Ici, seulement si l'équipe technique vous le demande.",
      bouton: action.code === "conduire_etapes" ? action.bouton : libelleCommande("inscrire-client"), champs: [],
    },
    {
      commande: "condense-inscription", cle: "condense-inscription", groupe: "Inscription", titre: libelleCommande("condense-inscription"),
      quoi: "Prépare le document d'inscription d'un enregistreur, à faire signer par les approbateurs du client. L'outil ne le signe jamais. Rien n'est envoyé au registre public.",
      quand: "Quand le client a plusieurs enregistreurs, pour préparer le document de chacun ; ou pour refaire un document perdu ou modifié.",
      bouton: "Préparer le document",
      champs: [{ nom: "key_id", libelle: "Enregistreur concerné", type: "texte", options: keyIds, donnees: true, defaut: action.keyId, aide: "L'enregistreur du client dont vous demandez l'inscription." }],
    },
    {
      commande: "inscrire-cle", cle: "inscrire-cle", groupe: "Inscription", titre: libelleCommande("inscrire-cle"),
      quoi: "Envoie au registre public, par notre compte d'envoi, un document d'inscription que les approbateurs du client ont signé avec leur propre outil. L'envoi coûte des crédits d'écriture, que notre société paie.",
      quand: "Quand le client vous rend le document signé d'un autre enregistreur que celui de la prochaine action.",
      ...PAR_NOTRE_COMPTE,
      fixe: { relayeur: true },
      champs: [DOCUMENT_INSCRIPTION],
    },
    {
      commande: "inscrire-cle", cle: "inscrire-cle-reference", groupe: "Inscription", titre: "Envoyer le document d'inscription signé par le compte désigné par une référence (essais seulement)",
      quoi: "Envoie au registre public un document d'inscription signé, non par notre compte d'envoi, mais par le compte que désigne une référence donnée par l'équipe technique. Cela ne sert qu'aux essais. L'envoi coûte des crédits d'écriture.",
      quand: "Seulement pour un essai, quand l'équipe technique vous donne une référence. Pour un vrai client, servez-vous du bouton « Envoyer par notre compte d'envoi ».",
      bouton: "Envoyer par le compte désigné",
      champs: [
        DOCUMENT_INSCRIPTION,
        { nom: "cle_chaine", libelle: "Référence du compte technique du client", type: "reference_cle", obligatoire: REFERENCE_REQUISE, exemple: "alias:compte-technique-du-client", aide: "L'équipe technique vous la donne. Une référence dit où une clé est rangée (elle commence par « fichier: » ou « alias: ») ; ce n'est jamais la clé secrète elle-même." },
      ],
    },
    {
      commande: "capturer", cle: "capturer", groupe: "Après un envoi resté sans réponse", titre: libelleCommande("capturer"),
      quoi: "Va chercher la réponse du registre public pour une opération déjà partie, puis range sa preuve dans le dossier. Rien n'est renvoyé, rien n'est dépensé.",
      quand: "Quand un message de l'outil vous envoie ici. Si une étape reste « Envoyée » ou « Inscrite », la consigne du haut de la fiche le fait pour vous.",
      ...CHERCHER_LA_REPONSE,
      champs: [
        { nom: "envoi", libelle: "Étape restée « Envoyée »", type: "hachage", facultatif: true, ...choix(envoyees), aide: envoyees.length > 0 ? "L'étape dont l'envoi attend la réponse du registre public. L'outil connaît son identifiant : vous n'avez rien à recopier." : "Aucune étape n'est « Envoyée » pour l'instant. Laissez vide, sauf si l'équipe technique vous donne un identifiant d'envoi à coller ici." },
        { nom: "transaction", libelle: "Étape restée « Inscrite »", type: "hachage", facultatif: true, ...choix(inscrites, envoyees.length === 0), aide: inscrites.length > 0 ? "L'étape inscrite sur le registre public dont la preuve reste à ranger dans le dossier. Si vous avez choisi une étape au champ précédent, choisissez ici « Aucune »." : "Aucune étape n'est « Inscrite » sans sa preuve pour l'instant. Laissez vide, sauf si l'équipe technique vous donne un identifiant à coller ici." },
      ],
    },
    {
      commande: "approvisionner", cle: "approvisionner", groupe: "Après l'inscription", titre: libelleCommande("approvisionner"),
      quoi: "Verse de nouveau des crédits d'écriture sur un compte technique qui n'en a presque plus. Le client doit d'abord confirmer ce versement par un autre moyen que cet outil, et vous devez avoir noté sa confirmation.",
      quand: "Après l'inscription, quand l'équipe technique signale qu'un compte technique va manquer de crédits, ou quand un message de l'outil vous envoie ici.",
      bouton: "Alimenter le compte",
      champs: [
        { nom: "cle_chaine", libelle: "Compte technique à alimenter", type: "adresse", options: cles, donnees: true, aide: "Le compte technique de l'enregistreur du client qui recevra le versement." },
        { nom: "budget_jour", libelle: "Budget d'écriture par jour", type: "montant", facultatif: true, exemple: "10800000", aide: "Laissez vide : l'outil reprend le budget du dossier. N'écrivez une autre valeur que si l'équipe technique vous la donne." },
      ],
    },
    {
      commande: "condense-administration", cle: "condense-administration", groupe: "Changer les approbateurs du client", titre: libelleCommande("condense-administration"),
      quoi: "Prépare un document de changement de la liste des approbateurs : ajouter ou retirer une personne, changer le nombre d'approbations requises, changer de responsable. Le document est à faire signer par le responsable des approbateurs du client.",
      quand: "Seulement si le client vous le demande par écrit, une fois ses approbateurs enregistrés.",
      bouton: "Préparer le document",
      champs: [
        { nom: "op", libelle: "Changement demandé", type: "texte", options: OPERATIONS, aide: "Ce que le client vous a demandé par écrit." },
        { nom: "arg_adresse", parametre: "arg", libelle: "Adresse de signature de la personne concernée", type: "adresse", facultatif: true, aide: "Pour ajouter ou retirer un approbateur, ou proposer un nouveau responsable. Le client vous la donne par écrit ; copiez-la sans la retaper." },
        { nom: "arg_seuil", parametre: "arg", libelle: "Nouveau nombre d'approbations requises", type: "entier", facultatif: true, aide: "Seulement pour changer ce nombre. Un nombre entier, en chiffres." },
      ],
    },
    {
      commande: "administrer-jeu", cle: "administrer-jeu", groupe: "Changer les approbateurs du client", titre: libelleCommande("administrer-jeu"),
      quoi: "Envoie au registre public, par notre compte d'envoi, le changement que le responsable des approbateurs du client a signé ; il prend effet aussitôt. Le client doit l'avoir confirmé par un autre moyen que cet outil, et vous devez avoir noté sa confirmation.",
      quand: "Quand le client vous rend le document de changement signé.",
      ...PAR_NOTRE_COMPTE,
      fixe: { relayeur: true },
      champs: [DOCUMENT_ADMINISTRATION],
    },
    {
      commande: "administrer-jeu", cle: "administrer-jeu-reference", groupe: "Changer les approbateurs du client", titre: "Envoyer un changement des approbateurs signé par le compte désigné par une référence (essais seulement)",
      quoi: "Envoie au registre public le changement signé, non par notre compte d'envoi, mais par le compte que désigne une référence donnée par l'équipe technique. Cela ne sert qu'aux essais. Le client doit l'avoir confirmé par un autre moyen que cet outil, et vous devez avoir noté sa confirmation.",
      quand: "Seulement pour un essai, quand l'équipe technique vous donne une référence. Pour un vrai client, servez-vous du bouton « Envoyer par notre compte d'envoi ».",
      bouton: "Envoyer par le compte désigné",
      champs: [
        DOCUMENT_ADMINISTRATION,
        { nom: "expediteur", libelle: "Référence du compte qui envoie", type: "reference_cle", obligatoire: REFERENCE_REQUISE, exemple: "alias:compte-d-essai", aide: "L'équipe technique vous la donne. Une référence dit où une clé est rangée ; ce n'est jamais la clé secrète elle-même." },
      ],
    },
  ];
  if (periodes.length > 0) {
    l.push({
      commande: "exporter", cle: "exporter", groupe: "Dossier de preuve", titre: libelleCommande("exporter"),
      quoi: "Copie, depuis le registre public, les pièces qui entrent dans le dossier de preuve du client. Rien n'est écrit sur le registre public.",
      quand: "Quand la prochaine action vous le propose, ou pour une période suivante du journal.",
      bouton: "Préparer les pièces",
      champs: [
        { nom: "manifeste", libelle: "Période du journal", type: "chemin", options: periodes, donnees: true, aide: "La période dont vous préparez les pièces. Gardez le choix proposé s'il n'y en a qu'une." },
        { nom: "cles", libelle: "Fichier des signataires", type: "chemin", facultatif: true, exemple: "cles.json", aide: "Laissez vide : l'outil prend les signataires du dossier. Ne remplissez ce champ que si l'équipe technique vous donne un nom de fichier." },
      ],
    });
  }
  if (parties.length > 0) {
    l.push({
      commande: "verifier", cle: "verifier", groupe: "Dossier de preuve", titre: libelleCommande("verifier"),
      quoi: "Contrôle les pièces préparées, comme le fera l'outil de vérification du client. Rien n'est écrit sur le registre public.",
      quand: "Quand la prochaine action vous le propose, après avoir préparé les pièces.",
      bouton: "Contrôler les pièces",
      champs: [
        { nom: "parties", libelle: "Pièces à contrôler", type: "chemin", options: parties, donnees: true, aide: "Gardez le choix proposé s'il n'y en a qu'un." },
        { nom: "manifeste", libelle: "Période du journal", type: "chemin", options: periodes, donnees: true, aide: "La période de ces pièces." },
        { nom: "ancres", libelle: "Liste des références de confiance", type: "chemin", facultatif: true, exemple: "ancres.json", aide: "Laissez vide : l'outil prend la liste que notre société publie. Ne remplissez ce champ que si l'équipe technique vous donne un nom de fichier." },
      ],
    });
  }
  return l;
}

/** Une étape du parcours : une ligne (rond, nom, état, date) ; développée, sa phrase et son état en clair ; le détail technique replié. */
function Etape({ e }) {
  const texte = <>{e.phrase}{e.objet ? <> {e.objet.texte} <Valeur>{e.objet.valeur}</Valeur>.</> : null}</>;
  return (
    <li className={`nt-etape nt-etape-${e.rang}`} data-etape={e.code} data-etat={e.etat} data-developpee={e.developpee ? "oui" : "non"} aria-current={e.developpee && e.rang !== "echec" ? "step" : undefined}>
      <span className="nt-etape-rond">
        {e.rang === "faite" ? <Icone nom="coche" /> : e.rang === "echec" ? <Icone nom="croix" /> : e.rang === "en-cours" ? <Icone nom="point" /> : e.numero}
      </span>
      <div className="nt-etape-corps">
        <div className="ins-etape-ligne">
          <p className="nt-etape-titre">
            <span><span className="nt-masque">Étape {e.numero} : </span>{e.titre}</span>
            {/* Une étape faite se dit par la coche de son rond et par « Fait le … », sur la même ligne. */}
            {e.rang === "faite"
              ? <span className="nt-attenue nt-petit" data-etape-faite="">{e.libelle}{e.quand ? <> le <time dateTime={e.quand}>{jourLisible(e.quand)}</time></> : null}</span>
              : <Pastille ton={e.ton} icone={e.icone}>{e.libelle}</Pastille>}
          </p>
          {e.developpee ? null : (
            <details className="ins-detail" data-detail-etape={e.code}>
              <summary>Détail<span className="nt-masque"> de l'étape {e.numero}</span></summary>
              <div className="ins-detail-corps nt-pile">
                <p>{texte}</p>
                <p>{e.explication}</p>
                <dl className="nt-definitions">
                  {e.technique.map((x) => (
                    <div className="ins-contenu" key={x.membre}>
                      <dt>{x.libelle}</dt>
                      <dd><span className="nt-fixe">{x.valeur}</span></dd>
                    </div>
                  ))}
                </dl>
              </div>
            </details>
          )}
        </div>
        {e.developpee ? (
          <>
            <p className="nt-etape-texte">{texte}</p>
            <p className="nt-etape-texte ins-resultat">
              {e.erreur ? "Cette étape a échoué : ce qui s'est passé et ce qu'il faut faire sont dits en haut de la fiche." : e.explication}
              {e.rang !== "a-faire" && e.quand ? <> Le <time dateTime={e.quand}>{dateLisible(e.quand)}</time>.</> : null}
            </p>
            <details className="ins-detail" data-detail-etape={e.code}>
              <summary>{e.erreur ? "Détail à transmettre à l'équipe technique" : "Détail technique"}<span className="nt-masque"> de l'étape {e.numero}</span></summary>
              <dl className="nt-definitions ins-detail-corps">
                {e.technique.map((x) => (
                  <div className="ins-contenu" key={x.membre}>
                    <dt>{x.libelle}</dt>
                    <dd><span className="nt-fixe">{x.valeur}</span></dd>
                  </div>
                ))}
              </dl>
            </details>
          </>
        ) : null}
      </div>
    </li>
  );
}

/** Une action de la fiche, repliée : ce qu'elle fait, quand s'en servir, son formulaire. */
function Action({ x, slug }) {
  return (
    <details className="nt-detail" data-action={x.cle}>
      <summary>{x.titre}</summary>
      <div className="nt-detail-corps">
        <p><strong>Ce que fait cette action :</strong> {x.quoi}</p>
        <p><strong>Quand s'en servir :</strong> {x.quand}</p>
        <FormulaireTravail commande={x.commande} slug={slug} champs={x.champs} fixe={x.fixe ?? {}} bouton={x.bouton} sousBouton={x.sousBouton ?? null} principal={false} />
      </div>
    </details>
  );
}

export default async function PageClient({ params }) {
  await exigerSession();
  const { slug } = await params;
  const c = client(slug);
  if (!c) notFound();
  const d = c.dossier;
  const registre = confirmations(slug);
  const etapes = etapesDuParcours(d);
  const a = avancement(d);
  const action = prochaineAction({ ...c, confirmations: registre });
  const production = nature() === "production";
  const toutes = actions({ d, c, action, etapes });
  // L'action de la consigne. Aller chercher la réponse d'un envoi : l'envoi est connu, la personne n'a rien à choisir
  // ni à recopier. Envoyer le document signé : par notre compte d'envoi, que le bouton nomme.
  const principale = action.code === "reprendre_envoi"
    ? { commande: "capturer", cle: "capturer", champs: [], fixe: { [action.parametre]: action.valeur } }
    : action.commande ? toutes.find((x) => x.cle === action.commande) : null;
  // Sans champ, le bouton de la consigne se met à droite de ses phrases sur un écran large (premier écran).
  const enColonnes = !principale || principale.champs.length === 0;
  const echecs = etapes.filter((e) => e.rang === "echec");
  const etats = etatsTravaux(c.travaux, d);
  const dernier = c.travaux[0] ?? null;
  const etatDernier = dernier ? etats[0] : null;
  const codeDernier = dernier?.motif?.code ?? dernier?.sortie?.error?.code ?? "";
  // Le dernier travail n'a pas abouti et aucune étape en échec ne le dit déjà : son explication monte en bandeau.
  // Quand ce refus renvoie à la reprise d'un envoi et que la consigne est justement de le reprendre (ou de
  // l'attendre), le bandeau se tait : l'écran ne dit qu'une chose.
  const consigneSurEnvoi = (action.code === "reprendre_envoi" || action.code === "attendre_envoi") && ENVOI_A_REPRENDRE.has(codeDernier);
  const dernierRefuse = echecs.length === 0 && dernier && etatDernier.termine && etatDernier.ton !== "succes" && etatDernier.code !== "abandonne" && codeDernier !== "" && !consigneSurEnvoi;
  // Hors de la consigne, « Aller chercher la réponse du registre public » n'est proposé qu'après une erreur qui y renvoie
  // alors qu'aucune étape du dossier ne porte cet envoi (sinon la consigne le fait déjà : l'écran ne dit qu'une chose).
  const envoiAReprendre = action.code !== "reprendre_envoi" && action.code !== "attendre_envoi" && (ENVOI_A_REPRENDRE.has(codeDernier) || echecs.some((e) => ENVOI_A_REPRENDRE.has(e.erreur.code)));
  const autres = toutes.filter((x) => x !== principale);
  const utiles = autres.filter((x) => x.commande === "capturer" && envoiAReprendre);
  const rares = autres.filter((x) => !utiles.includes(x));
  const groupes = [...new Set(rares.map((x) => x.groupe))];
  const essai = !production;
  const disponibles = registre.filter((x) => !x.consommee_par).length;
  // Ce que la fiche dit des confirmations : combien sont notées, et à quoi elles ont servi. Le versement d'un
  // compte technique consomme sa confirmation (CT-4 EX-7.26) : une confirmation utilisée reste comptée, avec le
  // jour du versement qu'elle a autorisé. Un versement fait sans aucune confirmation notée ici n'est pas normal
  // (le service d'inscription l'exige avant tout versement) : la fiche le dit au lieu de se taire.
  const versements = d.steps.filter((e) => e.step === "approvisionnement");
  const verse = versements.some((e) => e.state === "capturee" || e.state === "faite");
  const utilisees = registre.length - disponibles;
  const jourVersement = (x) => {
    const e = versements.find((v) => v.subject === x.objet?.cle_chaine && v.state === "capturee");
    return x.operation === "approvisionnement" && e?.updated_at ? jourLisible(e.updated_at) : null;
  };
  const seule = registre.length === 1 ? registre[0] : null;
  const phraseConfirmations = registre.length === 0
    ? (verse ? "aucune notée ici, alors que le versement est fait : ce n'est pas normal, prévenez l'équipe technique" : "aucune notée")
    : seule
      ? (seule.consommee_par ? `1 notée, ${jourVersement(seule) ? `utilisée pour le versement du ${jourVersement(seule)}` : "déjà utilisée"}` : "1 notée, prête à servir")
      : `${registre.length} notées : ${[disponibles > 0 ? `${disponibles} ${disponibles > 1 ? "prêtes" : "prête"} à servir` : null, utilisees > 0 ? `${utilisees} déjà ${utilisees > 1 ? "utilisées" : "utilisée"}` : null].filter(Boolean).join(", ")}`;
  const nomTire = /^o-[0-9a-f]{32}$/.test(slug);
  const explicationDernier = dernierRefuse ? explicationErreur(codeDernier) : null;
  // La demande préparée qui attend les signatures du client, pour l'action « faites signer, puis envoyez ».
  const aRemettre = action.code === "relayer_demande" ? c.demandes.find((x) => x.nom.startsWith(`demande-inscription-${action.keyId}-`) && !estRelayee(x)) ?? null : null;
  const montrerDemandes = c.demandes.length > 0 || action.code === "preparer_demande" || action.code === "relayer_demande";
  const nomEnregistreur = (adresse) => d.recorders.find((x) => x.chain_key === adresse)?.key_id ?? null;
  const etapeReprise = action.code === "reprendre_envoi" ? etapes.find((e) => e.numero === action.etape) ?? null : null;
  return (
    <main className="nt-page ins-page-fiche">
      <a className="nt-fil" href="/clients"><Icone nom="retour" />Tous les clients</a>
      <header className="nt-entete">
        <div className="nt-entete-texte">
          <p className="nt-sur-titre">Client{essai ? " · mode essai" : ""}</p>
          <h1 data-valeur="">{slug}</h1>
          <p className="nt-sous-titre">
            Inscription sur le registre public, un registre que personne ne peut modifier après coup : {a.phraseFaites}. {a.resume}
          </p>
          <progress className="nt-jauge ins-jauge" value={a.faites} max={a.total} aria-label={a.phraseFaites} />
        </div>
        <div className="nt-entete-etat">
          <Pastille ton={a.ton} icone={a.icone} grande data-etat-client={a.etat}>{a.libelle}</Pastille>
        </div>
      </header>

      {echecs.map((e) => (
        <div className="nt-bandeau nt-bandeau-erreur" role="alert" key={e.numero} data-etape-en-echec={e.code}>
          <Icone nom="alerte" />
          <div className="nt-bandeau-texte">
            <p className="nt-bandeau-titre">L'étape {e.numero} a échoué : {e.titre}</p>
            <p>{e.erreur.phrase} {e.erreur.effet} La marche à suivre est juste en dessous.</p>
          </div>
        </div>
      ))}
      {dernierRefuse ? (
        <div className="nt-bandeau nt-bandeau-erreur" role="alert" data-derniere-action={codeDernier}>
          <Icone nom="alerte" />
          <div className="nt-bandeau-texte">
            <p className="nt-bandeau-titre">La dernière action n'a pas abouti : {libelleCommande(dernier.commande)} ({etatDernier.libelle.toLowerCase()})</p>
            <p>{explicationDernier.phrase} {explicationDernier.effet}</p>
            <p><strong>Que faire :</strong> {explicationDernier.quoiFaire}</p>
          </div>
        </div>
      ) : null}

      <section className="nt-essentiel" data-prochaine-action={action.code} aria-labelledby="prochaine-titre">
        <div className="ins-consigne-tete">
          <p className="nt-sur-titre">{action.surTitre}</p>
          <h2 className="nt-essentiel-phrase" id="prochaine-titre">{action.titre}</h2>
        </div>
        <div className="ins-consigne-corps" data-en-colonnes={enColonnes ? "" : undefined}>
          <div className="ins-consigne">
            <p className="ins-essentiel-texte">{action.phrase}</p>
            {action.cles ? (
              <dl className="nt-faits">
                {action.cles.map((cle) => (
                  <div className="nt-fait ins-fait-large" key={cle}>
                    <dt>Ce que le client doit confirmer</dt>
                    <dd>
                      <span className="ins-ligne">le versement de <span data-valeur="">{nombreLisible(d.funding.amount_wei)}</span> crédits d'écriture sur le compte technique{nomEnregistreur(cle) ? <> de son enregistreur <Valeur>{nomEnregistreur(cle)}</Valeur></> : null}</span>
                      <span className="ins-ligne">l'adresse de ce compte : <CopierValeur valeur={cle} forme="adresse" libelle="Copier l'adresse" /></span>
                    </dd>
                  </div>
                ))}
              </dl>
            ) : null}
            {action.keyId ? (
              <dl className="nt-faits">
                <div className="nt-fait"><dt>Enregistreur concerné</dt><dd><Valeur>{action.keyId}</Valeur></dd></div>
                <div className="nt-fait"><dt>Signatures à réunir</dt><dd>{d.approvers.threshold} sur {d.approvers.members.length} {d.approvers.members.length > 1 ? "approbateurs" : "approbateur"}</dd></div>
              </dl>
            ) : null}
            {etapeReprise ? (
              <dl className="nt-faits">
                <div className="nt-fait ins-fait-large"><dt>Réponse à aller chercher</dt><dd>celle de l'étape {etapeReprise.numero}, « {etapeReprise.titre} »</dd></div>
              </dl>
            ) : null}
            {aRemettre ? (
              <p className="ins-essentiel-texte" data-demande-a-remettre="">
                <strong>D'abord :</strong> copiez le document et envoyez-le au client (<a href="#demandes-titre">voir son texte</a>). <CopierTexte texte={JSON.stringify(aRemettre.document, null, 2)} libelle="Copier le document" cible={idTexte(aRemettre.nom)} faite="Copié : collez-le dans votre message au client." />
              </p>
            ) : null}
            <p className="ins-essentiel-texte" data-a-preparer="">{aRemettre ? <><strong>Ensuite :</strong> </> : null}{action.aPreparer}</p>
          </div>
          {principale ? (
            <FormulaireTravail commande={principale.commande} slug={slug} champs={principale.champs} fixe={principale.fixe ?? {}} bouton={action.bouton} sousBouton={action.sousBouton ?? null} classe="ins-consigne-formulaire" />
          ) : (
            <div className="nt-actions ins-consigne-lien">
              <a className={action.code === "attendre_premiere_periode" || action.code === "attendre_envoi" || action.code === "etape_inconnue" ? "nt-bouton" : "nt-bouton nt-bouton-principal"} href={action.lien}>{action.bouton}</a>
            </div>
          )}
        </div>
        <p className="ins-essentiel-texte nt-attenue nt-petit" data-apres-clic="">{action.apres}</p>
        {action.cles ? (
          <dl className="nt-definitions ins-pour-expliquer" data-pour-expliquer="">
            <dt>Si le client demande ce que sont ces crédits</dt>
            <dd data-credits-en-clair=""><span>{action.credits} Le montant suit le budget d'écriture de l'enregistreur, <span data-valeur="">{nombreLisible(d.funding.daily_budget_gas)}</span> crédits par jour ; si le compte en a déjà, l'outil ne verse que la différence.</span></dd>
            <dt>Pour lui faire confirmer l'adresse</dt>
            <dd data-adresse-a-confirmer="">{action.adresse}</dd>
          </dl>
        ) : null}
      </section>

      {utiles.length > 0 ? (
        <section className="nt-pile" aria-labelledby="utiles-titre" data-actions-utiles="">
          <h2 id="utiles-titre">Autre action utile maintenant</h2>
          {utiles.map((x) => <Action key={x.cle} x={x} slug={slug} />)}
        </section>
      ) : null}

      <div className="ins-fiche">
        <section className="nt-carte" aria-labelledby="etapes-titre">
          <div className="nt-carte-titre">
            <h2 id="etapes-titre">Les étapes de l'inscription</h2>
            <span className="nt-carte-note">{a.phraseFaites}</span>
          </div>
          <ol className="nt-etapes ins-etapes">
            {etapes.map((e) => <Etape key={e.numero} e={e} />)}
          </ol>
        </section>

        <div className="nt-pile nt-pile-large">
          <section className="nt-carte" aria-labelledby="pieces-titre">
            <h2 id="pieces-titre">Confirmations et paquet</h2>
            <ul className="ins-liste">
              <li>
                <a href={`/clients/${slug}/confirmations`}>Confirmations du client</a>
                <span className="nt-attenue nt-petit" data-confirmations-notees={registre.length} data-anomalie={registre.length === 0 && verse ? "versement_sans_confirmation" : undefined}>{phraseConfirmations}</span>
              </li>
              <li>
                <a href={`/clients/${slug}/paquet`}>Paquet du client</a>
                <span className="nt-attenue nt-petit">{c.paquet.present ? "produit : à remettre au client avec son empreinte" : "pas encore produit"}</span>
              </li>
            </ul>
          </section>

          <section className="nt-carte" aria-labelledby="org-titre">
            <h2 id="org-titre">Le client en bref</h2>
            <dl className="nt-definitions">
              <dt>Registre</dt><dd>{essai ? "Registre d'essai" : "Registre réel"}</dd>
              <dt>Approbateurs</dt><dd>{d.approvers.threshold} {d.approvers.threshold > 1 ? "approbations requises" : "approbation requise"}, sur {d.approvers.members.length} {d.approvers.members.length > 1 ? "approbateurs" : "approbateur"}</dd>
              <dt>{d.journals.length > 1 ? "Journaux" : "Journal"}</dt><dd>{d.journals.map((j) => <Valeur key={j.name}>{j.name}</Valeur>)}</dd>
              <dt>{d.recorders.length > 1 ? "Enregistreurs" : "Enregistreur"}</dt><dd>{d.recorders.length === 0 ? "Aucun" : d.recorders.map((r) => <Valeur key={r.key_id}>{r.key_id}</Valeur>)}</dd>
              <dt>Dossier préparé</dt><dd><span>le <time dateTime={d.prepared_at}>{dateLisible(d.prepared_at)}</time></span></dd>
            </dl>
            {nomTire ? <p className="nt-attenue nt-petit" data-nom-tire="">Ce nom ne dit pas qui est le client : notez la correspondance dans votre fichier des clients.</p> : null}
            <details className="ins-detail" data-detail-organisation>
              <summary>Détail technique</summary>
              <dl className="nt-definitions ins-detail-corps">
                <dt>Identifiant du client sur le registre public</dt><dd><span className="nt-fixe">{d.organisation.org_id}</span></dd>
                <dt>Identifiants du registre</dt><dd><span className="nt-fixe">{d.instance.bft_chain_id}</span><span className="nt-fixe">{d.instance.evm_chain_id}</span></dd>
                <dt>Genèse (SHA-256)</dt><dd><span className="nt-fixe">{d.instance.genesis_sha256}</span></dd>
                {d.instance.manifest_sha256 ? <div className="ins-contenu"><dt>Manifeste du registre (SHA-256)</dt><dd><span className="nt-fixe">{d.instance.manifest_sha256}</span></dd></div> : null}
                <dt>Jeu de validateurs</dt><dd><span className="nt-fixe">{d.instance.validator_set_hash}</span></dd>
                <dt>Contrats du registre</dt>
                <dd>{Object.entries(d.instance.contracts).map(([k, v]) => <span className="ins-ligne" key={k}><span className="nt-fixe nt-attenue">{k}</span> <span className="nt-fixe">{v}</span></span>)}</dd>
                <dt>Adresses de signature des approbateurs</dt><dd>{d.approvers.members.map((m) => <span className="nt-fixe ins-ligne" key={m}>{m}</span>)}</dd>
                <dt>Responsable des approbateurs (clé de gouvernance)</dt><dd><span className="nt-fixe">{d.approvers.set_admin}</span></dd>
                {d.journals.map((j) => <div className="ins-contenu" key={j.name}><dt>Journal <span className="nt-fixe">{j.name}</span></dt><dd><span className="nt-fixe">{j.journal_id}</span></dd></div>)}
                {d.recorders.map((r) => (
                  <div className="ins-contenu" key={r.key_id}>
                    <dt>Enregistreur <span className="nt-fixe">{r.key_id}</span></dt>
                    <dd>
                      <span className="ins-ligne"><span className="nt-attenue">clé publique</span> <span className="nt-fixe">{r.public_key}</span></span>
                      <span className="ins-ligne"><span className="nt-attenue">compte technique (clé de chaîne)</span> <span className="nt-fixe">{r.chain_key}</span></span>
                      <span className="ins-ligne"><span className="nt-attenue">classes de garde</span> <span className="nt-fixe">{r.custody_class}</span> <span className="nt-fixe">{r.chain_key_class}</span></span>
                    </dd>
                  </div>
                ))}
                <dt>Notre compte de paiement (trésorerie)</dt><dd><span className="nt-fixe">{d.funding.funder}</span></dd>
                <dt>Versement par compte technique</dt><dd><span><span className="nt-fixe">{d.funding.amount_wei}</span> wei, pour un budget de <span className="nt-fixe">{d.funding.daily_budget_gas}</span> gaz par jour</span></dd>
                <dt>Préparé par</dt><dd><span className="nt-fixe">{d.prepared_by}</span></dd>
              </dl>
            </details>
          </section>
        </div>
      </div>

      {montrerDemandes ? (
        <section className="nt-carte" aria-labelledby="demandes-titre">
          <div className="nt-carte-titre">
            <h2 id="demandes-titre">Documents à faire signer par le client</h2>
            <span className="nt-carte-note">l'outil les prépare et les envoie ; il ne les signe jamais</span>
          </div>
          {c.demandes.length === 0 ? <p className="nt-attenue">Aucun document à faire signer pour l'instant. Un document à faire signer est un texte que le client fait signer par ses approbateurs, avec leur propre outil.</p> : (
            <ul className="ins-liste">
              {c.demandes.map((x) => {
                const n = Array.isArray(x.document?.signatures) ? x.document.signatures.length : 0;
                const requises = x.document?.signer_set?.threshold;
                const relayee = estRelayee(x);
                // Une demande préparée dont le condensé est celui d'une demande relayée n'est plus à faire signer.
                const suivie = !relayee && typeof x.document?.digest === "string" && c.demandes.some((y) => estRelayee(y) && y.document?.digest === x.document.digest);
                const texte = JSON.stringify(x.document, null, 2);
                return (
                  <li key={x.nom} data-demande={x.nom}>
                    <div className="ins-ligne-tete">
                      <strong>{NOMS_DEMANDE[x.document?.operation] ?? "Document à faire signer"}</strong>
                      {relayee ? <Pastille ton="succes" icone="coche">Signé et envoyé</Pastille> : suivie ? <Pastille icone="coche">Remplacé par sa version signée</Pastille> : <Pastille ton="attente" icone="horloge">À faire signer par le client</Pastille>}
                    </div>
                    <p className="nt-attenue nt-petit">
                      {x.document?.prepared_at ? <>Préparé le <time dateTime={x.document.prepared_at}>{dateLisible(x.document.prepared_at)}</time>. </> : null}
                      {n === 0 ? "Aucune signature" : `${n} ${n > 1 ? "signatures" : "signature"}`}{Number.isSafeInteger(requises) ? `, sur ${requises} ${requises > 1 ? "requises" : "requise"}.` : "."}
                      {relayee ? " C'est la version signée, telle qu'elle est partie au registre public." : suivie ? " C'est le texte d'avant signature : rien à en faire." : " Envoyez ce texte au client : ses approbateurs le contrôlent et le signent avec leur propre outil, puis le client vous le renvoie signé."}
                    </p>
                    {!relayee && !suivie ? <CopierTexte texte={texte} libelle="Copier le document" cible={idTexte(x.nom)} faite="Copié : collez-le dans votre message au client." data-copier-demande="" /> : null}
                    {x.document?.operation === "administration_jeu" && !relayee && !suivie && typeof x.document?.digest === "string" ? (
                      <p className="nt-petit" data-empreinte-document="">
                        <span className="ins-ligne">Son empreinte, à reporter telle quelle sur la confirmation du client :</span>
                        <CopierValeur valeur={x.document.digest} forme="empreinte" libelle="Copier l'empreinte" />
                      </p>
                    ) : null}
                    <details className="ins-detail">
                      <summary>Texte exact du document</summary>
                      <div className="ins-detail-corps nt-pile">
                        <p>Fichier <span className="nt-fixe">{x.nom}</span></p>
                        <pre className="nt-pre" id={idTexte(x.nom)}>{texte}</pre>
                      </div>
                    </details>
                  </li>
                );
              })}
            </ul>
          )}
        </section>
      ) : null}

      <details className="nt-detail" data-actions-rares="">
        <summary>Actions rarement utiles<span className="nt-detail-note">{rares.length} actions ; la bonne est déjà proposée en haut</span></summary>
        <div className="nt-detail-corps nt-pile">
          <p>Vous n'avez normalement pas besoin de ces actions : l'outil propose la bonne en haut de la fiche. Elles servent quand un message de l'outil vous y envoie, ou quand l'équipe technique vous le demande. Chacune dit ce qu'elle fait et quand s'en servir ; le service d'inscription refait tous ses contrôles avant d'agir.</p>
          {groupes.map((g) => (
            <div className="nt-pile" key={g}>
              <h3 className="ins-groupe">{g}</h3>
              {rares.filter((x) => x.groupe === g).map((x) => <Action key={x.cle} x={x} slug={slug} />)}
            </div>
          ))}
        </div>
      </details>

      <details className="nt-detail" data-historique="">
        <summary>
          Historique des actions lancées depuis cet outil
          <span className="nt-detail-note">
            {c.travaux.length === 0 ? "aucune ; ce qui est fait se lit dans les étapes, plus haut" : <>{c.travaux.length} {c.travaux.length > 1 ? "actions" : "action"} ; la dernière : {libelleCommande(dernier.commande)} ({etatDernier.libelle.toLowerCase()}), le <time dateTime={dernier.recu_a} data-derniere-action-date="">{dateLisible(dernier.recu_a)}</time></>}
          </span>
        </summary>
        <div className="nt-detail-corps nt-pile">
          <p className="nt-attenue" data-historique-contenu="">Cet historique garde les actions lancées depuis cet outil pour ce client, les plus récentes d'abord. Il ne dit pas où en est le client : cela se lit dans « Les étapes de l'inscription », plus haut.</p>
          {c.travaux.length === 0 ? <p className="nt-attenue">Aucune action n'a été lancée depuis cet outil pour ce client.</p> : (
            <ul className="ins-liste">
              {c.travaux.map((t, k) => {
                const e = etats[k];
                const code = t.motif?.code ?? t.sortie?.error?.code ?? null;
                return (
                  <li key={t.id} data-travail={t.id}>
                    <div className="ins-ligne-tete">
                      <strong>{libelleCommande(t.commande)}</strong>
                      <Pastille ton={e.ton} icone={e.icone}>{e.libelle}</Pastille>
                    </div>
                    <p className="nt-attenue nt-petit">
                      Le <time dateTime={t.recu_a}>{dateLisible(t.recu_a)}</time>, lancée par <Valeur>{t.exploitant}</Valeur>.
                      {code ? ` ${explicationErreur(code).phrase}` : ` ${e.explication}`}
                    </p>
                    <details className="ins-detail">
                      <summary>Détail technique</summary>
                      <div className="ins-detail-corps nt-pile">
                        <dl className="nt-definitions">
                          <dt>Travail</dt><dd><span className="nt-fixe">{t.id}</span></dd>
                          <dt>Commande</dt><dd><span className="nt-fixe">{t.commande}</span></dd>
                          <dt>État</dt><dd><span className="nt-fixe">{t.etat}</span></dd>
                          <dt>Reçu</dt><dd><span className="nt-fixe">{t.recu_a}</span></dd>
                        </dl>
                        <pre className="nt-pre">{JSON.stringify(t.sortie ?? t.motif ?? null, null, 2)}</pre>
                      </div>
                    </details>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </details>
      <Lexique />
    </main>
  );
}
