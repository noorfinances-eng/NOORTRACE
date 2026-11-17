// /clients/<slug> : le dossier, ses étapes et leurs états (EX-7.16), les sorties des travaux, et les actions offertes
// selon l'état : pas 2 à 5, approvisionner, condensé d'inscription (la demande se remet aux approbateurs hors de
// l'application, EX-7.27), relais d'une demande signée, capture, export et vérification (pas 10), et administration
// du jeu (demande préparée, remise à l'administrateur du jeu hors de l'application, relais de la demande signée après
// la confirmation hors bande du client : CT-4 §8.5, EX-7.26).
//
// Présentation (complément du 2026-11-17, décision du porteur sur la présentation des écrans) : la fiche se lit
// comme un parcours guidé. En haut, le nom du client, son état et la prochaine action avec son bouton ; une étape
// en échec monte en bandeau, avec la conduite à tenir. Puis les étapes dans l'ordre, chacune avec la phrase qui dit
// ce qu'elle fait et son résultat ; le détail technique de chaque étape (codes, objet, transaction, bloc, capture,
// erreur, instant exact) est replié et rend les valeurs du dossier telles quelles. Les autres actions, les demandes
// de signature et l'historique des travaux suivent, repliés. Aucune action offerte auparavant n'est retirée.

import { notFound } from "next/navigation";
import { client, confirmations } from "../../../lib/donnees.mjs";
import { exigerSession, nature } from "../../../lib/page.mjs";
import { OPERATIONS_JEU, avancement, dateLisible, etapesDuParcours, etatTravail, explicationErreur, libelleCommande, prochaineAction } from "../../../lib/parcours.mjs";
import FormulaireTravail from "../../../composants/FormulaireTravail.js";
import Icone from "../../../composants/Icone.js";
import Pastille from "../../../composants/Pastille.js";

export const dynamic = "force-dynamic";

const NON_OUI = [{ valeur: "", libelle: "non" }, { valeur: "oui", libelle: "oui" }];
const OPERATIONS = Object.entries(OPERATIONS_JEU).map(([o, libelle]) => ({ valeur: o, libelle: `${libelle} (${o})` }));
const RELAYEUR = { nom: "relayeur", libelle: "Relayer par le relayeur de l'exploitant", type: "texte", options: NON_OUI, oui: true, facultatif: true, aide: "« oui » : le relayeur de l'exploitant envoie la transaction ; laissez alors la référence vide." };

/** Une demande que l'agent a relayée (`demande-inscription-relayee-…`, `demande-administration-relayee-…`). */
const estRelayee = (x) => /^demande-(inscription|administration)-relayee-/.test(x.nom);

/** Les actions de la fiche : titre, phrase et formulaire du travail de chaque commande. */
function actions({ slug, d, c, action }) {
  const cles = d.recorders.map((r) => ({ valeur: r.chain_key, libelle: `${r.key_id} · ${r.chain_key}` }));
  const keyIds = d.recorders.map((r) => ({ valeur: r.key_id, libelle: r.key_id }));
  const periodes = c.periodes.map((p) => ({ valeur: p, libelle: p }));
  const parties = c.parties.map((p) => ({ valeur: p, libelle: p }));
  const l = [
    {
      commande: "inscrire-client", groupe: "Inscription", titre: action.code === "conduire_etapes" ? action.titre : "Conduire les étapes 2 à 5",
      phrase: "Crée le jeu d'approbateurs, l'assigne à l'organisation, le relit, puis approvisionne chaque clé de chaîne. Une étape déjà faite n'est pas refaite.",
      bouton: action.code === "conduire_etapes" ? action.bouton : "Conduire les étapes 2 à 5", champs: [],
    },
    {
      commande: "condense-inscription", groupe: "Inscription", titre: "Préparer la demande d'inscription",
      phrase: "Prépare la demande d'inscription d'une clé d'enregistreur. L'outil ne la signe pas : elle se remet aux approbateurs hors de cette application.",
      bouton: "Préparer la demande",
      champs: [{ nom: "key_id", libelle: "Clé d'enregistreur", type: "texte", options: keyIds, defaut: action.keyId, aide: "La clé dont l'inscription est demandée." }],
    },
    {
      commande: "inscrire-cle", groupe: "Inscription", titre: "Relayer une demande d'inscription signée",
      phrase: "Relaie au registre la demande que les approbateurs ont signée hors de cette application.",
      bouton: "Relayer la demande signée",
      champs: [
        { nom: "demande", libelle: "Demande signée", type: "document", aide: "Collez ici le document JSON de la demande, tel que les approbateurs vous l'ont rendu, signatures comprises." },
        { nom: "cle_chaine", libelle: "Référence de la clé de chaîne qui envoie", type: "reference_cle", facultatif: true, exemple: "alias:chaine-du-client", aide: "Une référence que l'agent sait résoudre (fichier:, alias:), jamais la clé elle-même. Refusée en production. Laissez vide avec le relayeur." },
        RELAYEUR,
      ],
    },
    {
      commande: "approvisionner", groupe: "Exploitation courante", titre: "Approvisionner une clé de chaîne",
      phrase: "Verse à une clé de chaîne de quoi payer ses écritures. Le client doit avoir confirmé ce versement hors bande.",
      bouton: "Approvisionner la clé",
      champs: [
        { nom: "cle_chaine", libelle: "Clé de chaîne du dossier", type: "adresse", options: cles, aide: "La clé qui recevra le versement." },
        { nom: "budget_jour", libelle: "Budget journalier, en gaz", type: "montant", facultatif: true, exemple: "10800000", aide: "Laissez vide pour le budget du dossier." },
      ],
    },
    {
      commande: "capturer", groupe: "Exploitation courante", titre: "Capturer une transaction ou reprendre un envoi",
      phrase: "Enregistre la preuve d'une transaction incluse, ou reprend un envoi dont l'issue n'est pas connue. Rien n'est renvoyé.",
      bouton: "Capturer",
      champs: [
        { nom: "transaction", libelle: "Hachage d'une transaction incluse", type: "hachage", facultatif: true, aide: "« 0x » suivi de 64 chiffres hexadécimaux. Remplissez ce champ ou le suivant." },
        { nom: "envoi", libelle: "Hachage d'un envoi sans issue", type: "hachage", facultatif: true, aide: "Pour un envoi parti dont le reçu n'est jamais arrivé." },
      ],
    },
    {
      commande: "condense-administration", groupe: "Administration du jeu d'approbateurs", titre: "Préparer une demande d'administration du jeu",
      phrase: "Prépare un changement du jeu d'approbateurs. La demande se remet à l'administrateur du jeu hors de cette application.",
      bouton: "Préparer la demande",
      champs: [
        { nom: "op", libelle: "Opération", type: "texte", options: OPERATIONS, aide: "Le changement demandé." },
        { nom: "arg_adresse", parametre: "arg", libelle: "Adresse du membre ou de l'administrateur proposé", type: "adresse", facultatif: true, aide: "Pour ajouter ou retirer un approbateur, ou proposer un administrateur." },
        { nom: "arg_seuil", parametre: "arg", libelle: "Nouveau seuil", type: "entier", facultatif: true, aide: "Un nombre entier, pour changer le seuil." },
      ],
    },
    {
      commande: "administrer-jeu", groupe: "Administration du jeu d'approbateurs", titre: "Relayer une demande d'administration signée",
      phrase: "Relaie la demande que l'administrateur du jeu a signée. Le client doit avoir confirmé ce changement hors bande.",
      bouton: "Relayer la demande signée",
      champs: [
        { nom: "demande", libelle: "Demande signée", type: "document", aide: "Collez ici le document JSON de la demande d'administration, signé par l'administrateur du jeu." },
        { nom: "expediteur", libelle: "Référence de la clé qui envoie", type: "reference_cle", facultatif: true, exemple: "fichier:/chemin/vers/expediteur.cle", aide: "Une référence, jamais la clé elle-même. Laissez vide avec le relayeur." },
        RELAYEUR,
      ],
    },
  ];
  if (periodes.length > 0) {
    l.push({
      commande: "exporter", groupe: "Première période", titre: "Exporter les parties du registre",
      phrase: "Écrit les parties du registre qui entrent dans le dossier de preuve du client.",
      bouton: "Exporter les parties",
      champs: [
        { nom: "manifeste", libelle: "Manifeste de la période", type: "chemin", options: periodes, aide: "La période à exporter." },
        { nom: "cles", libelle: "Fichier des clés qui signent", type: "chemin", facultatif: true, exemple: "cles.json", aide: "Chemin relatif au répertoire du client. Laissez vide pour les clés du dossier." },
      ],
    });
  }
  if (parties.length > 0) {
    l.push({
      commande: "verifier", groupe: "Première période", titre: "Vérifier les parties du registre",
      phrase: "Contrôle les parties exportées comme le fera le vérificateur du client.",
      bouton: "Vérifier les parties",
      champs: [
        { nom: "parties", libelle: "Parties", type: "chemin", options: parties, aide: "Les parties à contrôler." },
        { nom: "manifeste", libelle: "Manifeste de la période", type: "chemin", options: periodes, aide: "La période de ces parties." },
        { nom: "ancres", libelle: "Fichier d'ancres", type: "chemin", facultatif: true, exemple: "ancres.json", aide: "Chemin relatif au répertoire du client. Laissez vide pour l'ancre publiée par l'exploitant." },
      ],
    });
  }
  return l;
}

/** Une étape du parcours : rond, titre et pastille, phrase, résultat, détail technique replié. */
function Etape({ e }) {
  return (
    <li className={`nt-etape nt-etape-${e.rang}`} data-etape={e.code} data-etat={e.etat} aria-current={e.rang === "en-cours" ? "step" : undefined}>
      <span className="nt-etape-rond">
        {e.rang === "faite" ? <Icone nom="coche" /> : e.rang === "echec" ? <Icone nom="croix" /> : e.rang === "en-cours" ? <Icone nom="point" /> : e.numero}
      </span>
      <div className="nt-etape-corps">
        <p className="nt-etape-titre">
          <span><span className="nt-masque">Étape {e.numero} : </span>{e.titre}</span>
          <Pastille ton={e.ton} icone={e.icone}>{e.libelle}</Pastille>
        </p>
        <p className="nt-etape-texte">{e.phrase}{e.objet ? ` ${e.objet}` : ""}</p>
        {e.resultat ? (
          <p className="nt-etape-texte ins-resultat">
            {e.resultat}{e.quand ? <> Le <time dateTime={e.quand}>{dateLisible(e.quand)}</time>.</> : null}
          </p>
        ) : null}
        {e.erreur ? <p className="nt-etape-texte ins-resultat">{e.erreur.quoiFaire}</p> : null}
        {e.technique.length > 0 ? (
          <details className="ins-detail" data-detail-etape={e.code}>
            <summary>Détail technique<span className="nt-masque"> de l'étape {e.numero}</span></summary>
            <dl className="nt-definitions ins-detail-corps">
              {e.technique.map((x) => (
                <div className="ins-contenu" key={x.membre}>
                  <dt>{x.libelle}</dt>
                  <dd><span className="nt-fixe">{x.valeur}</span></dd>
                </div>
              ))}
            </dl>
          </details>
        ) : null}
      </div>
    </li>
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
  const toutes = actions({ slug, d, c, action });
  const principale = action.commande ? toutes.find((x) => x.commande === action.commande) : null;
  const autres = toutes.filter((x) => x !== principale);
  const groupes = [...new Set(autres.map((x) => x.groupe))];
  const echecs = etapes.filter((e) => e.rang === "echec");
  const dernier = c.travaux[0] ?? null;
  const etatDernier = dernier ? etatTravail(dernier) : null;
  const dernierRefuse = echecs.length === 0 && dernier && etatDernier.termine && etatDernier.ton === "refus";
  const codeDernier = dernier?.motif?.code ?? dernier?.sortie?.error?.code ?? "";
  const essai = nature() !== "production";
  const disponibles = registre.filter((x) => !x.consommee_par).length;
  return (
    <main className="nt-page">
      <a className="nt-fil" href="/clients"><Icone nom="retour" />Tous les clients</a>
      <header className="nt-entete">
        <div className="nt-entete-texte">
          <p className="nt-sur-titre">Client</p>
          <h1>{slug}</h1>
          <p className="nt-sous-titre">
            {a.etat === "inscrit" ? "Inscription faite" : "Inscription en cours"} sur le {essai ? "réseau d'essai" : "registre"} : {a.phrase} faites.
          </p>
          <progress className="nt-jauge ins-jauge" value={a.faites} max={a.total} aria-label={`${a.phrase} faites`} />
        </div>
        <div className="nt-entete-etat">
          <Pastille ton={a.ton} icone={a.icone} grande data-etat-client={a.etat}>{a.libelle}</Pastille>
        </div>
      </header>

      {echecs.map((e) => (
        <div className="nt-bandeau nt-bandeau-erreur" role="alert" key={e.numero}>
          <Icone nom="alerte" />
          <div className="nt-bandeau-texte">
            <p className="nt-bandeau-titre">Étape {e.numero} en échec : {e.titre}</p>
            <p>{e.erreur.phrase} {e.erreur.quoiFaire}</p>
          </div>
        </div>
      ))}
      {dernierRefuse ? (
        <div className="nt-bandeau nt-bandeau-erreur" role="alert">
          <Icone nom="alerte" />
          <div className="nt-bandeau-texte">
            <p className="nt-bandeau-titre">La dernière action n'a pas abouti : {libelleCommande(dernier.commande)} ({etatDernier.libelle.toLowerCase()})</p>
            <p>{explicationErreur(codeDernier).phrase} {explicationErreur(codeDernier).quoiFaire}</p>
          </div>
        </div>
      ) : null}

      <section className="nt-essentiel" data-prochaine-action={action.code} aria-labelledby="prochaine-titre">
        <p className="nt-sur-titre">Prochaine action</p>
        <h2 className="nt-essentiel-phrase" id="prochaine-titre">{action.titre}</h2>
        <p className="ins-essentiel-texte">{action.phrase}</p>
        {action.cles ? (
          <dl className="nt-faits">
            {action.cles.map((cle) => {
              const r = d.recorders.find((x) => x.chain_key === cle);
              return (
                <div className="nt-fait" key={cle}>
                  <dt>Confirmation attendue pour</dt>
                  <dd>la clé de chaîne {r ? <>de <span className="nt-fixe">{r.key_id}</span></> : null} <span className="nt-fixe nt-attenue">{cle}</span></dd>
                </div>
              );
            })}
          </dl>
        ) : null}
        {action.code === "relayer_demande" ? <p><a href="#demandes-titre">Voir la demande à remettre aux approbateurs</a></p> : null}
        {principale ? (
          <FormulaireTravail commande={principale.commande} slug={slug} champs={principale.champs} bouton={action.bouton} />
        ) : (
          <div className="nt-actions">
            <a className={action.code === "attendre_premiere_periode" || action.code === "etape_inconnue" ? "nt-bouton" : "nt-bouton nt-bouton-principal"} href={action.lien}>{action.bouton}</a>
          </div>
        )}
      </section>

      <div className="ins-fiche">
        <section className="nt-carte" aria-labelledby="etapes-titre">
          <div className="nt-carte-titre">
            <h2 id="etapes-titre">Étapes de l'inscription</h2>
            <span className="nt-carte-note">{a.phrase} faites</span>
          </div>
          <ol className="nt-etapes">
            {etapes.map((e) => <Etape key={e.numero} e={e} />)}
          </ol>
        </section>

        <div className="nt-pile nt-pile-large">
          <section className="nt-carte" aria-labelledby="org-titre">
            <h2 id="org-titre">Organisation</h2>
            <dl className="nt-definitions">
              <dt>Réseau</dt><dd>{essai ? "Réseau d'essai" : "Registre de production"}</dd>
              <dt>Approbateurs</dt><dd>{d.approvers.threshold} {d.approvers.threshold > 1 ? "approbations" : "approbation"} sur {d.approvers.members.length} {d.approvers.members.length > 1 ? "membres" : "membre"}</dd>
              <dt>{d.journals.length > 1 ? "Journaux" : "Journal"}</dt><dd>{d.journals.map((j) => <span className="nt-fixe" key={j.name}>{j.name}</span>)}</dd>
              <dt>{d.recorders.length > 1 ? "Clés d'enregistreur" : "Clé d'enregistreur"}</dt><dd>{d.recorders.length === 0 ? "Aucune" : d.recorders.map((r) => <span className="nt-fixe" key={r.key_id}>{r.key_id}</span>)}</dd>
              <dt>Dossier préparé</dt><dd><span>le <time dateTime={d.prepared_at}>{dateLisible(d.prepared_at)}</time></span></dd>
            </dl>
            <details className="ins-detail" data-detail-organisation>
              <summary>Détail technique</summary>
              <dl className="nt-definitions ins-detail-corps">
                <dt>Identifiant de l'organisation</dt><dd><span className="nt-fixe">{d.organisation.org_id}</span></dd>
                <dt>Réseau</dt><dd><span className="nt-fixe">{d.instance.bft_chain_id}</span><span className="nt-fixe">{d.instance.evm_chain_id}</span></dd>
                <dt>Genèse (SHA-256)</dt><dd><span className="nt-fixe">{d.instance.genesis_sha256}</span></dd>
                {d.instance.manifest_sha256 ? <div className="ins-contenu"><dt>Manifeste du registre (SHA-256)</dt><dd><span className="nt-fixe">{d.instance.manifest_sha256}</span></dd></div> : null}
                <dt>Jeu de validateurs</dt><dd><span className="nt-fixe">{d.instance.validator_set_hash}</span></dd>
                <dt>Contrats du registre</dt>
                <dd>{Object.entries(d.instance.contracts).map(([k, v]) => <span className="ins-ligne" key={k}><span className="nt-fixe nt-attenue">{k}</span> <span className="nt-fixe">{v}</span></span>)}</dd>
                <dt>Adresses des approbateurs</dt><dd>{d.approvers.members.map((m) => <span className="nt-fixe ins-ligne" key={m}>{m}</span>)}</dd>
                <dt>Clé de gouvernance</dt><dd><span className="nt-fixe">{d.approvers.set_admin}</span></dd>
                {d.journals.map((j) => <div className="ins-contenu" key={j.name}><dt>Journal <span className="nt-fixe">{j.name}</span></dt><dd><span className="nt-fixe">{j.journal_id}</span></dd></div>)}
                {d.recorders.map((r) => (
                  <div className="ins-contenu" key={r.key_id}>
                    <dt>Clé <span className="nt-fixe">{r.key_id}</span></dt>
                    <dd>
                      <span className="ins-ligne"><span className="nt-attenue">clé publique</span> <span className="nt-fixe">{r.public_key}</span></span>
                      <span className="ins-ligne"><span className="nt-attenue">clé de chaîne</span> <span className="nt-fixe">{r.chain_key}</span></span>
                      <span className="ins-ligne"><span className="nt-attenue">classes de garde</span> <span className="nt-fixe">{r.custody_class}</span> <span className="nt-fixe">{r.chain_key_class}</span></span>
                    </dd>
                  </div>
                ))}
                <dt>Trésorerie</dt><dd><span className="nt-fixe">{d.funding.funder}</span></dd>
                <dt>Provision par clé</dt><dd><span><span className="nt-fixe">{d.funding.amount_wei}</span> wei, pour un budget de <span className="nt-fixe">{d.funding.daily_budget_gas}</span> gaz par jour</span></dd>
                <dt>Préparé par</dt><dd><span className="nt-fixe">{d.prepared_by}</span></dd>
              </dl>
            </details>
          </section>

          <section className="nt-carte" aria-labelledby="pieces-titre">
            <h2 id="pieces-titre">Pièces du client</h2>
            <ul className="ins-liste">
              <li>
                <a href={`/clients/${slug}/confirmations`}>Confirmations hors bande</a>
                <span className="nt-attenue nt-petit">{registre.length === 0 ? "aucune consignée" : `${registre.length} ${registre.length > 1 ? "consignées" : "consignée"}, dont ${disponibles} ${disponibles > 1 ? "disponibles" : "disponible"}`}</span>
              </li>
              <li>
                <a href={`/clients/${slug}/paquet`}>Paquet client</a>
                <span className="nt-attenue nt-petit">{c.paquet.present ? "produit" : "pas encore produit"}</span>
              </li>
            </ul>
          </section>
        </div>
      </div>

      <section className="nt-pile" aria-labelledby="autres-titre">
        <h2 id="autres-titre">Autres actions</h2>
        <p className="nt-attenue">La prochaine action est en haut de la fiche. Les autres restent disponibles ici ; l'agent refait tous ses contrôles avant d'agir.</p>
        {groupes.map((g) => (
          <div className="nt-pile" key={g}>
            <h3 className="ins-groupe">{g}</h3>
            {autres.filter((x) => x.groupe === g).map((x) => (
              <details className="nt-detail" key={x.commande} data-action={x.commande}>
                <summary>{x.titre}</summary>
                <div className="nt-detail-corps">
                  <p className="nt-attenue">{x.phrase}</p>
                  <FormulaireTravail commande={x.commande} slug={slug} champs={x.champs} bouton={x.bouton} principal={false} />
                </div>
              </details>
            ))}
          </div>
        ))}
      </section>

      <section className="nt-carte" aria-labelledby="demandes-titre">
        <div className="nt-carte-titre">
          <h2 id="demandes-titre">Demandes de signature</h2>
          <span className="nt-carte-note">l'outil les prépare et les relaie ; il ne les signe jamais</span>
        </div>
        {c.demandes.length === 0 ? <p className="nt-attenue">Aucune demande de signature.</p> : (
          <ul className="ins-liste">
            {c.demandes.map((x) => {
              const n = Array.isArray(x.document?.signatures) ? x.document.signatures.length : 0;
              const relayee = estRelayee(x);
              // Une demande préparée dont le condensé est celui d'une demande relayée n'est plus à faire signer.
              const suivie = !relayee && typeof x.document?.digest === "string" && c.demandes.some((y) => estRelayee(y) && y.document?.digest === x.document.digest);
              return (
                <li key={x.nom} data-demande={x.nom}>
                  <div className="ins-ligne-tete">
                    <span className="nt-fixe">{x.nom}</span>
                    {relayee ? <Pastille ton="succes" icone="coche">Relayée</Pastille> : suivie ? <Pastille icone="coche">Préparée, depuis relayée</Pastille> : <Pastille ton="attente" icone="horloge">À faire signer hors de l'application</Pastille>}
                  </div>
                  <p className="nt-attenue nt-petit">
                    {x.document?.prepared_at ? <>Préparée le <time dateTime={x.document.prepared_at}>{dateLisible(x.document.prepared_at)}</time>. </> : null}
                    {n === 0 ? "Aucune signature." : `${n} ${n > 1 ? "signatures" : "signature"}.`}
                  </p>
                  <details className="ins-detail">
                    <summary>Document de la demande</summary>
                    <pre className="nt-pre ins-detail-corps">{JSON.stringify(x.document, null, 2)}</pre>
                  </details>
                </li>
              );
            })}
          </ul>
        )}
      </section>

      <section className="nt-carte" aria-labelledby="travaux-titre">
        <div className="nt-carte-titre">
          <h2 id="travaux-titre">Historique des actions</h2>
          <span className="nt-carte-note">les plus récentes d'abord</span>
        </div>
        {c.travaux.length === 0 ? <p className="nt-attenue">Aucune action pour l'instant.</p> : (
          <ul className="ins-liste">
            {c.travaux.map((t) => {
              const e = etatTravail(t);
              const code = t.motif?.code ?? t.sortie?.error?.code ?? null;
              return (
                <li key={t.id} data-travail={t.id}>
                  <div className="ins-ligne-tete">
                    <strong>{libelleCommande(t.commande)}</strong>
                    <Pastille ton={e.ton} icone={e.icone}>{e.libelle}</Pastille>
                  </div>
                  <p className="nt-attenue nt-petit">
                    Le <time dateTime={t.recu_a}>{dateLisible(t.recu_a)}</time>, par <span className="nt-fixe">{t.exploitant}</span>.
                    {code ? ` ${explicationErreur(code).phrase}` : ""}
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
      </section>
    </main>
  );
}
