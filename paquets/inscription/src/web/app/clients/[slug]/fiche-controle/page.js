// /clients/<slug>/fiche-controle : la fiche de contrôle des adresses des approbateurs (CT-4 EX-7.8 et EX-7.26,
// complément du 2026-11-25, décision du porteur sur l'outil d'inscription ; INTERFACES.md 2.2, 2.7), page imprimable
// du même contenu que le fichier texte servi par GET /api/clients/<slug>/fiche-controle, avec l'empreinte de ce
// fichier. Produite depuis le dossier et les noms des approbateurs notés (note interne, saisis par l'exploitant d'après ce
// que le client a écrit ; un nom qui manque se lit « — (le client complète le nom) ») ; le nom interne du client n'y
// entre jamais. Chaque version produite est gardée par l'agent : la page les liste, la plus récente d'abord.
//
// Ce qui engage se lit sans rien ouvrir : chaque adresse en entier, le nombre d'approbations requises, l'empreinte de
// la fiche, l'état de sa confirmation (à faire confirmer ; confirmée par le client ; ne vaut plus, le dossier ayant
// changé ; adresses enregistrées). Rien ne part d'ici : la confirmation se note sur l'écran des confirmations.

import { notFound } from "next/navigation";
import { client, confirmations } from "../../../../lib/donnees.mjs";
import { exigerSession } from "../../../../lib/page.mjs";
import { lignesFiche, nomFichierFiche, NOM_A_COMPLETER, TITRE_FICHE } from "../../../../../commun/fiche-controle.mjs";
import { PASTILLES, PIECE_FICHE, POURQUOI_LA_FICHE, confirmationPerimee, dateLisible, ficheSansConfirmation, nomDuCompte } from "../../../../lib/parcours.mjs";
import { NomsApprobateurs } from "../../../../composants/NoteInterne.js";
import { CopierValeur } from "../../../../composants/CopierTexte.js";
import Icone from "../../../../composants/Icone.js";
import Imprimer from "../../../../composants/Imprimer.js";
import Lexique from "../../../../composants/Lexique.js";
import Pastille from "../../../../composants/Pastille.js";
import Valeur from "../../../../composants/Valeur.js";

export const dynamic = "force-dynamic";

export default async function PageFicheControle({ params }) {
  await exigerSession();
  const { slug } = await params;
  const c = client(slug);
  if (!c) notFound();
  const d = c.dossier;
  const registre = confirmations(slug);
  const lignes = lignesFiche(d, c.fiche.noms);
  const versions = c.fiche.versions;
  const courante = versions.find((x) => x.courante) ?? null;
  const versionDe = (sha) => versions.find((x) => x.fiche_sha256 === sha) ?? null;
  const etapeJeu = (d.steps ?? []).find((e) => e.step === "jeu_approbateurs");
  const enregistrees = Boolean(etapeJeu) && etapeJeu.state !== "a_faire" && etapeJeu.state !== "echec";
  const aConfirmer = !enregistrees && ficheSansConfirmation(d, registre, c.fiche);
  const valables = registre.filter((x) => x.operation === "jeu_approbateurs" && x.objet?.fiche_sha256 === c.fiche.sha256);
  const perimees = registre.filter((x) => confirmationPerimee(x, c.fiche));
  const etat = enregistrees ? "fiche_adresses_enregistrees" : aConfirmer ? "fiche_a_confirmer" : "fiche_confirmee";
  const p = PASTILLES[etat];
  const approbateurs = lignes.filter((x) => x.cle === "approbateur");
  const ligne = (cle) => lignes.find((x) => x.cle === cle);
  return (
    <main className="nt-page ins-page-fiche-controle" data-fiche-controle={etat}>
      <a className="nt-fil nt-sans-impression" href={`/clients/${slug}`}><Icone nom="retour" />Fiche du client</a>
      <header className="nt-entete">
        <div className="nt-entete-texte">
          <p className="nt-sur-titre">Client <Valeur>{slug}</Valeur></p>
          <h1>{TITRE_FICHE}</h1>
          <p className="nt-sous-titre nt-sans-impression">À remettre au client avant l'étape 2 de son inscription : chaque approbateur y reconnaît sa propre adresse de signature. Le client vous renvoie la fiche confirmée par écrit ; vous notez cette confirmation sur l'écran des confirmations, et l'outil peut alors enregistrer les approbateurs sur le registre public. Rien ne part d'ici.</p>
        </div>
        <div className="nt-entete-etat nt-sans-impression">
          <Pastille ton={p.ton} icone={p.icone} grande data-etat-fiche={etat}>{p.libelle}</Pastille>
        </div>
      </header>

      <div className="nt-actions nt-sans-impression" data-actions-fiche="">
        <a className="nt-bouton nt-bouton-principal" href={`/api/clients/${slug}/fiche-controle`} download={nomFichierFiche(slug)} data-telecharger-fiche="">Télécharger la fiche (fichier texte)</a>
        <Imprimer />
        {aConfirmer ? <a className="nt-bouton" href={`/clients/${slug}/confirmations`} data-noter-fiche="">Aller noter la confirmation du client</a> : null}
      </div>
      <p className="nt-attenue nt-petit nt-sans-impression" data-remise-fiche="">Remettez au client le fichier téléchargé ou la page imprimée, par le moyen convenu avec lui : les deux disent la même chose. {PIECE_FICHE}</p>

      <section className="nt-carte ins-fiche-controle" aria-labelledby="fiche-titre" data-fiche="">
        <h2 id="fiche-titre" data-ligne="titre">{ligne("titre").libelle}</h2>
        <dl className="nt-definitions">
          <dt data-ligne="organisation">{ligne("organisation").libelle}</dt><dd><Valeur>{ligne("organisation").valeur}</Valeur></dd>
          <dt data-ligne="approbations">{ligne("approbations").libelle}</dt><dd data-approbations="">{ligne("approbations").valeur}</dd>
        </dl>
        <ol className="ins-fiche-approbateurs" data-approbateurs={approbateurs.length}>
          {approbateurs.map((x) => (
            <li key={x.valeur} data-ligne="approbateur">
              <span className="ins-fiche-libelle">{x.libelle}</span>
              <span className="nt-fixe ins-adresse" data-valeur="" data-adresse-approbateur="">{x.valeur}</span>
              <span className="ins-fiche-nom"><span className="ins-fiche-nom-libelle">nom :</span>{x.nom ? <span data-valeur="" data-nom-approbateur-fiche="">{x.nom}</span> : <span data-nom-a-completer="">{NOM_A_COMPLETER}</span>}</span>
            </li>
          ))}
        </ol>
        <dl className="nt-definitions">
          <dt data-ligne="responsable">{ligne("responsable").libelle}</dt><dd><span className="nt-fixe ins-adresse" data-valeur="" data-adresse-responsable="">{ligne("responsable").valeur}</span></dd>
          <dt data-ligne="consigne">{ligne("consigne").libelle}</dt><dd data-consigne-fiche="">{ligne("consigne").valeur}</dd>
        </dl>
      </section>

      <section className="nt-carte" aria-labelledby="empreinte-titre" data-empreinte-fiche="">
        <h2 id="empreinte-titre">Empreinte de cette fiche</h2>
        <p>Celle du fichier texte, calculée sur ses lignes telles qu'elles sont ci-dessus{courante?.version ? <>, version <span data-version-courante="">{courante.version}</span> de la fiche</> : null} : <CopierValeur valeur={c.fiche.sha256} forme="empreinte" libelle="Copier l'empreinte" data-fiche-sha256="" /></p>
        <p className="nt-attenue nt-petit">Le fichier téléchargé a exactement cette empreinte ; la confirmation du client la cite. Si le dossier change (un approbateur ajouté ou retiré, une adresse modifiée) ou si un nom change, la fiche change et l'empreinte aussi : c'est une nouvelle version, et une confirmation qui cite l'ancienne ne vaut plus.</p>
        {versions.length > 0 ? (
          <dl className="nt-definitions" data-versions-fiche={versions.length}>
            {versions.map((v) => (
              <div className="ins-contenu" key={v.fiche_sha256} data-version-fiche={v.version ?? "courante"}>
                <dt>{v.version === null ? "Fiche actuelle, pas encore numérotée" : `Version ${v.version}`}{v.courante ? " (courante)" : ""}</dt>
                <dd><span className="ins-ligne">{v.produite_a ? <>produite le <time dateTime={v.produite_a}>{dateLisible(v.produite_a)}</time></> : "le dossier vient de changer : elle sera numérotée à la prochaine action du service d'inscription"}</span><span className="nt-fixe ins-empreinte" data-valeur="">{v.fiche_sha256}</span></dd>
              </div>
            ))}
          </dl>
        ) : null}
      </section>

      {!enregistrees ? (
        <details className="nt-detail ins-replie nt-sans-impression" id="noms" data-noms-approbateurs-action="">
          <summary>Noms des approbateurs<span className="nt-detail-note">{approbateurs.filter((x) => x.nom).length} sur {approbateurs.length} donnés ; se changent ici tant que l'étape 2 n'est pas faite</span></summary>
          <div className="nt-detail-corps"><NomsApprobateurs slug={slug} adresses={d.approvers.members} noms={c.fiche.noms} /></div>
        </details>
      ) : null}

      <section className="nt-carte nt-sans-impression" aria-labelledby="confirmation-titre" data-confirmation-fiche="">
        <h2 id="confirmation-titre">Confirmation du client</h2>
        {enregistrees ? <p data-fiche-etat-phrase="">{PASTILLES.fiche_adresses_enregistrees.sens}</p> : null}
        {!enregistrees && valables.length > 0 ? (
          <ul className="ins-liste" data-confirmations-fiche="">
            {valables.map((x) => (
              <li key={x.id} data-confirmation={x.id}>
                <span>Confirmée par <span data-valeur="">{x.personne_client}</span> (<span data-valeur="">{x.canal}</span>) le <time dateTime={x.instant}>{dateLisible(x.instant)}</time>, notée par <Valeur>{nomDuCompte(x.exploitant)}</Valeur> le <time dateTime={x.recu_a}>{dateLisible(x.recu_a)}</time>{x.consommee_par ? " ; déjà utilisée" : " ; prête à servir"}.</span>
              </li>
            ))}
          </ul>
        ) : null}
        {!enregistrees && valables.length === 0 ? <p data-fiche-etat-phrase="">Aucune confirmation notée pour cette fiche. {PASTILLES.fiche_a_confirmer.sens}</p> : null}
        {perimees.length > 0 ? (
          <div className="nt-bandeau nt-bandeau-avertissement" role="status" data-confirmations-perimees={perimees.length}>
            <Icone nom="alerte" />
            <div className="nt-bandeau-texte">
              <p className="nt-bandeau-titre">{perimees.length > 1 ? `${perimees.length} confirmations notées ne valent plus.` : "Une confirmation notée ne vaut plus."}</p>
              <p>La fiche a changé depuis : {perimees.length > 1 ? "elles citent" : "elle cite"} une autre version de la fiche ({perimees.map((x) => `${versionDe(x.objet.fiche_sha256)?.version ? `version ${versionDe(x.objet.fiche_sha256).version}, ` : ""}empreinte ${x.objet.fiche_sha256.slice(0, 10)}…${x.objet.fiche_sha256.slice(-6)}, notée le ${dateLisible(x.recu_a)}`).join(" ; ")}){courante?.version ? ` ; la fiche actuelle est la version ${courante.version}` : ""}. Remettez au client la fiche actuelle et faites-la confirmer de nouveau ; l'étape 2 reste bloquée d'ici là.</p>
            </div>
          </div>
        ) : null}
        <details className="nt-detail ins-replie">
          <summary>Pourquoi une fiche de contrôle<span className="nt-detail-note">ce que répondre au client</span></summary>
          <div className="nt-detail-corps"><p>{POURQUOI_LA_FICHE}</p></div>
        </details>
      </section>
      <Lexique />
    </main>
  );
}
