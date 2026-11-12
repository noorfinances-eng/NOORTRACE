// /clients/<slug> : le dossier, ses étapes et leurs états (EX-7.16), les sorties des travaux, et les actions offertes
// selon l'état : pas 2 à 5, approvisionner, condensé d'inscription (la demande se remet aux approbateurs hors de
// l'application, EX-7.27), relais d'une demande signée, capture, export et vérification (pas 10), et administration
// du jeu (demande préparée, remise à l'administrateur du jeu hors de l'application, relais de la demande signée après
// la confirmation hors bande du client : CT-4 §8.5, EX-7.26).

import { notFound } from "next/navigation";
import { client } from "../../../lib/donnees.mjs";
import { exigerSession } from "../../../lib/page.mjs";
import FormulaireTravail from "../../../composants/FormulaireTravail.js";

export const dynamic = "force-dynamic";

const NON_OUI = [{ valeur: "", libelle: "non" }, { valeur: "oui", libelle: "oui" }];
const OPERATIONS = ["CuratorSet.addCurator", "CuratorSet.removeCurator", "CuratorSet.setThreshold", "CuratorSet.proposeAdmin", "CuratorSet.acceptAdmin"].map((o) => ({ valeur: o, libelle: o }));

export default async function PageClient({ params }) {
  await exigerSession();
  const { slug } = await params;
  const c = client(slug);
  if (!c) notFound();
  const d = c.dossier;
  const cles = d.recorders.map((r) => ({ valeur: r.chain_key, libelle: `${r.chain_key} (${r.key_id})` }));
  const keyIds = d.recorders.map((r) => ({ valeur: r.key_id, libelle: r.key_id }));
  const periodes = c.periodes.map((p) => ({ valeur: p, libelle: p }));
  const parties = c.parties.map((p) => ({ valeur: p, libelle: p }));
  return (
    <>
      <h1>Client {slug}</h1>
      <p><a href={`/clients/${slug}/confirmations`}>Confirmations hors bande</a> · <a href={`/clients/${slug}/paquet`}>Paquet client</a></p>
      <p>org_id <code>{d.organisation.org_id}</code> · instance <code>{d.instance.bft_chain_id}</code> ({d.instance.evm_chain_id})</p>
      <h2>Étapes (EX-7.16)</h2>
      <table>
        <thead><tr><th>Étape</th><th>Objet</th><th>État</th><th>Transaction</th><th>Capture</th></tr></thead>
        <tbody>
          {d.steps.map((e, k) => (
            <tr key={k}>
              <td>{e.step}</td><td><code>{e.subject}</code></td><td className={e.state === "echec" ? "refus etat" : "etat"}>{e.state}{e.error ? ` (${e.error.code})` : ""}</td>
              <td><code>{e.transaction_hash ?? "—"}</code></td><td><code>{e.capture ?? "—"}</code></td>
            </tr>
          ))}
        </tbody>
      </table>
      <FormulaireTravail titre="Pas 2 à 5 : jeu, assignation, lecture, approvisionnement" commande="inscrire-client" slug={slug} bouton="Conduire les pas 2 à 5" />
      <FormulaireTravail
        titre="Approvisionner une clé de chaîne (8.7)"
        commande="approvisionner"
        slug={slug}
        champs={[
          { nom: "cle_chaine", libelle: "Clé de chaîne du dossier", type: "adresse", options: cles },
          { nom: "budget_jour", libelle: "Budget journalier en gaz", type: "montant", facultatif: true },
        ]}
      />
      <FormulaireTravail titre="Pas 6 : préparer la demande d'inscription" commande="condense-inscription" slug={slug} champs={[{ nom: "key_id", libelle: "Clé d'enregistreur", type: "texte", options: keyIds }]} bouton="Préparer la demande (à remettre aux approbateurs hors de l'application)" />
      <FormulaireTravail
        titre="Pas 6 : relayer une demande signée"
        commande="inscrire-cle"
        slug={slug}
        champs={[
          { nom: "demande", libelle: "Demande signée (document demande_signature, JSON)", type: "document" },
          { nom: "cle_chaine", libelle: "Référence de la clé de chaîne expéditrice (fichier:, env: ; laisser vide avec le relayeur)", type: "reference_cle", facultatif: true, exemple: "fichier:/chemin/vers/cle-chaine.cle" },
          { nom: "relayeur", libelle: "Relayer par le relayeur de l'exploitant", type: "texte", options: NON_OUI, oui: true, facultatif: true },
        ]}
        bouton="Relayer la demande signée"
      />
      <FormulaireTravail
        titre="Administration du jeu (8.5) : préparer la demande"
        commande="condense-administration"
        slug={slug}
        champs={[
          { nom: "op", libelle: "Opération", type: "texte", options: OPERATIONS },
          { nom: "arg_adresse", parametre: "arg", libelle: "Membre ou administrateur proposé (adresse ; addCurator, removeCurator, proposeAdmin)", type: "adresse", facultatif: true },
          { nom: "arg_seuil", parametre: "arg", libelle: "Nouveau seuil (entier ; setThreshold)", type: "entier", facultatif: true },
        ]}
        bouton="Préparer la demande (à remettre à l'administrateur du jeu hors de l'application)"
      />
      <FormulaireTravail
        titre="Administration du jeu (8.5) : relayer la demande signée"
        commande="administrer-jeu"
        slug={slug}
        champs={[
          { nom: "demande", libelle: "Demande signée (document demande_signature administration_jeu, JSON)", type: "document" },
          { nom: "expediteur", libelle: "Référence de la clé expéditrice (fichier:, env: ; laisser vide avec le relayeur)", type: "reference_cle", facultatif: true, exemple: "fichier:/chemin/vers/expediteur.cle" },
          { nom: "relayeur", libelle: "Relayer par le relayeur de l'exploitant", type: "texte", options: NON_OUI, oui: true, facultatif: true },
        ]}
        bouton="Relayer la demande signée (confirmation hors bande exigée)"
      />
      <FormulaireTravail
        titre="Capturer une transaction ou reprendre un envoi (8.6)"
        commande="capturer"
        slug={slug}
        champs={[
          { nom: "transaction", libelle: "Hachage d'une transaction incluse", type: "hachage", facultatif: true },
          { nom: "envoi", libelle: "Hachage d'un envoi sans issue", type: "hachage", facultatif: true },
        ]}
      />
      {periodes.length > 0 ? (
        <FormulaireTravail titre="Pas 10 : exporter les parties du registre" commande="exporter" slug={slug} champs={[{ nom: "manifeste", libelle: "Manifeste de la période", type: "chemin", options: periodes }, { nom: "cles", libelle: "cles.json (chemin relatif au client)", type: "chemin", facultatif: true }]} />
      ) : null}
      {parties.length > 0 ? (
        <FormulaireTravail titre="Pas 10 : vérifier les parties (contrôle 8)" commande="verifier" slug={slug} champs={[{ nom: "parties", libelle: "Parties", type: "chemin", options: parties }, { nom: "manifeste", libelle: "Manifeste de la période", type: "chemin", options: periodes }, { nom: "ancres", libelle: "Fichier d'ancres (chemin relatif au client)", type: "chemin", facultatif: true }]} />
      ) : null}
      <h2>Demandes de signature</h2>
      {c.demandes.length === 0 ? <p className="discret">Aucune.</p> : c.demandes.map((x) => (
        <details key={x.nom}><summary>{x.nom}</summary><pre>{JSON.stringify(x.document, null, 2)}</pre></details>
      ))}
      <h2>Travaux</h2>
      {c.travaux.map((t) => (
        <details key={t.id}>
          <summary>{t.recu_a} · {t.commande} · {t.etat}{t.sortie ? ` · ${t.sortie.result}` : ""}{t.motif ? ` · ${t.motif.code === "confirmation_absente" ? "confirmation hors bande absente" : t.motif.code}` : ""} · {t.exploitant}</summary>
          <pre>{JSON.stringify(t.sortie ?? t.motif ?? null, null, 2)}</pre>
        </details>
      ))}
    </>
  );
}
