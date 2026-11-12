// Accueil : renvoi à la liste des clients.

import { redirect } from "next/navigation";

export const dynamic = "force-dynamic";

export default function Accueil() {
  redirect("/clients");
}
