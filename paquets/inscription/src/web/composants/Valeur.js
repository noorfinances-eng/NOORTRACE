// Valeur qui vient des données (nom d'un client, d'un enregistreur, adresse, empreinte, identité, nom de fichier) :
// affichée telle quelle, en chasse fixe, jamais traduite ni reformulée (complément du 2026-11-18, décision du
// porteur sur le langage des écrans). L'attribut `data-valeur` la distingue des phrases de l'outil : l'essai
// « aucun mot de technicien au premier niveau » lit le texte de l'écran hors de ces valeurs.

export default function Valeur({ children, attenuee = false, className = "", ...attributs }) {
  const classes = ["nt-fixe", attenuee ? "nt-attenue" : "", className].filter(Boolean).join(" ");
  return <span className={classes} data-valeur="" {...attributs}>{children}</span>;
}
