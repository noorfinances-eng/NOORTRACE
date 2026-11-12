// /clients : clients connus, slug, org_id, état de chaque étape (EX-7.16), dernier travail.

import { clients } from "../../lib/donnees.mjs";
import { exigerSession } from "../../lib/page.mjs";
import Deconnexion from "../../composants/Deconnexion.js";

export const dynamic = "force-dynamic";

export default async function PageClients() {
  const s = await exigerSession();
  const liste = clients();
  return (
    <>
      <h1>Clients</h1>
      <p className="discret">Session : {s.identite}</p>
      <Deconnexion />
      <table>
        <thead><tr><th>Slug</th><th>org_id</th><th>Étapes</th><th>Dernier travail</th></tr></thead>
        <tbody>
          {liste.map((c) => (
            <tr key={c.slug}>
              <td><a href={`/clients/${c.slug}`}>{c.slug}</a></td>
              <td><code>{c.org_id}</code></td>
              <td className="etat">{c.steps.map((e) => `${e.step} ${e.state}`).join(" · ")}</td>
              <td>{c.dernier_travail ? `${c.dernier_travail.commande} : ${c.dernier_travail.etat}${c.dernier_travail.result ? ` (${c.dernier_travail.result})` : ""}` : "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {liste.length === 0 ? <p className="discret">Aucun client.</p> : null}
    </>
  );
}
