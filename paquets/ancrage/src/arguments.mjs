// Lecture stricte des arguments des programmes du paquet (`noortrace-ancrage`,
// `noortrace-tsa-interne` ; complément du 2026-11-16) : chaque commande
// déclare ses options à valeur, ses drapeaux et le nombre de ses arguments.
// Une option inconnue, donnée deux fois, ou à valeur sans sa valeur (absente,
// vide, ou remplacée par une autre option), et un argument en trop, sont des
// erreurs d'usage (code 2) : une option mal écrite n'est plus ignorée en
// silence, une option répétée ne prend plus sa dernière valeur, une option
// laissée sans valeur ne prend plus une valeur par défaut. Un drapeau ne
// prend jamais l'argument qui le suit.

/**
 * @param {string[]} argv arguments qui suivent le nom de la commande
 * @param {{valeurs?: string[], drapeaux?: string[], positionnels?: number}} specification
 *   noms des options à valeur et des drapeaux (sans `--`), nombre d'arguments au plus
 * @param {new (message: string) => Error} ErreurUsage classe de l'erreur d'usage du programme
 * @returns {{options: Record<string, string|true>, positionnels: string[]}}
 */
export function lireArguments(argv, { valeurs = [], drapeaux = [], positionnels = 0 }, ErreurUsage) {
  const options = Object.create(null);
  const lus = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) {
      lus.push(a);
      continue;
    }
    const nom = a.slice(2);
    if (!valeurs.includes(nom) && !drapeaux.includes(nom)) throw new ErreurUsage(`option inconnue : ${a}`);
    if (nom in options) throw new ErreurUsage(`${a} donnée deux fois`);
    if (drapeaux.includes(nom)) {
      options[nom] = true;
      continue;
    }
    const v = argv[i + 1];
    if (v === undefined || v === "" || v.startsWith("--")) throw new ErreurUsage(`${a} : valeur attendue`);
    options[nom] = v;
    i++;
  }
  if (lus.length > positionnels) throw new ErreurUsage(`argument en trop : ${lus[positionnels]}`);
  return { options, positionnels: lus };
}
