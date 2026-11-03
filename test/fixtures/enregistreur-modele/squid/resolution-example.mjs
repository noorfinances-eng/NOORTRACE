// Résolution de test des noms du domaine réservé `.example` (RFC 2606) vers
// 127.0.0.1, chargée dans un processus Node par `--import` (épreuve TI-19 de
// CT-9) : le démon réel joint en passerelle le fournisseur simulé sous le même
// nom (`api.fournisseur.example`) que le mandataire Squid, qui le résout par
// une entrée de son /etc/hosts (`docker run --add-host`). Les deux résolutions
// donnent la même adresse ; aucune autre n'est touchée, et le démon n'en sait
// rien (`dns.lookup`, appelé par `net.connect` des modules http et https).

import dns from "node:dns";

const DOMAINE = /\.example\.?$/i;
const lookupOrigine = dns.lookup;
const lookupPromesseOrigine = dns.promises.lookup;

dns.lookup = function lookup(nom, options, rappel) {
  if (typeof options === "function") {
    rappel = options;
    options = {};
  }
  if (typeof nom === "string" && DOMAINE.test(nom)) {
    const o = typeof options === "number" ? { family: options } : (options ?? {});
    process.nextTick(() => (o.all ? rappel(null, [{ address: "127.0.0.1", family: 4 }]) : rappel(null, "127.0.0.1", 4)));
    return {};
  }
  return lookupOrigine.call(this, nom, options, rappel);
};

dns.promises.lookup = async function lookup(nom, options) {
  if (typeof nom === "string" && DOMAINE.test(nom)) {
    const o = typeof options === "number" ? { family: options } : (options ?? {});
    return o.all ? [{ address: "127.0.0.1", family: 4 }] : { address: "127.0.0.1", family: 4 };
  }
  return lookupPromesseOrigine.call(this, nom, options);
};
