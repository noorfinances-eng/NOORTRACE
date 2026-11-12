// /clients/<slug>/confirmations : registre des confirmations hors bande du client (EX-7.26) et formulaire d'ajout.

import { notFound } from "next/navigation";
import { client, confirmations } from "../../../../lib/donnees.mjs";
import { exigerSession } from "../../../../lib/page.mjs";
import FormulaireConfirmation from "../../../../composants/FormulaireConfirmation.js";

export const dynamic = "force-dynamic";

export default async function PageConfirmations({ params }) {
  await exigerSession();
  const { slug } = await params;
  const c = client(slug);
  if (!c) notFound();
  const liste = confirmations(slug);
  return (
    <>
      <h1>Confirmations hors bande · {slug}</h1>
      <p><a href={`/clients/${slug}`}>Retour au dossier</a></p>
      <table>
        <thead><tr><th>Reçue</th><th>Exploitant</th><th>Opération</th><th>Clé de chaîne</th><th>Personne du client</th><th>Canal</th><th>Instant</th><th>Pièce (SHA-256)</th><th>Consommée par</th></tr></thead>
        <tbody>
          {liste.map((x) => (
            <tr key={x.id}><td>{x.recu_a}</td><td>{x.exploitant}</td><td>{x.operation}</td><td><code>{x.objet.cle_chaine}</code></td><td>{x.personne_client}</td><td>{x.canal}</td><td>{x.instant}</td><td><code>{x.piece_sha256}</code></td><td>{x.consommee_par ?? "non consommée"}</td></tr>
          ))}
        </tbody>
      </table>
      <h2>Ajouter une confirmation</h2>
      <FormulaireConfirmation slug={slug} orgId={c.dossier.organisation.org_id} clesChaine={c.dossier.recorders.map((r) => r.chain_key)} />
    </>
  );
}
