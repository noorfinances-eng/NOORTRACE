// Pastille d'état : un mot et une icône, jamais la seule couleur. `ton` : succes, refus, attente, info, ou vide (neutre).

import Icone from "./Icone.js";

export default function Pastille({ ton = "", icone = null, grande = false, children, ...attributs }) {
  const classes = ["nt-pastille", ton ? `nt-pastille-${ton}` : "", grande ? "nt-pastille-grande" : ""].filter(Boolean).join(" ");
  return (
    <span className={classes} {...attributs}>
      {icone ? <Icone nom={icone} /> : null}
      {children}
    </span>
  );
}
