// Équipement de copie simulé du mode miroir (CT-2 §5.1.3) : un relais TCP
// entre l'agent et le fournisseur (le trafic « déchiffré ») qui envoie à
// l'adaptateur de capture une copie de chaque sens de chaque connexion, au
// fil de l'eau, en trames (ligne JSON `{connexion, sens, source, longueur}`
// puis les octets), et une trame `fin` à la fermeture. Il ne modifie rien et
// ne peut rien bloquer.

import net from "node:net";

/**
 * @param {{amont: string, adaptateur: {host: string, port: number}, source?: string, tronquerServeurApres?: number}} o
 *   `tronquerServeurApres` : la copie du sens serveur s'arrête après tant d'octets (copie incomplète)
 */
export async function demarrerCopie(o) {
  const amont = new URL(o.amont);
  const versAdaptateur = net.connect(o.adaptateur.port, o.adaptateur.host);
  await new Promise((r, j) => {
    versAdaptateur.once("connect", r);
    versAdaptateur.once("error", j);
  });
  let n = 0;
  const trame = (connexion, sens, octets) => {
    versAdaptateur.write(`${JSON.stringify({ connexion, sens, source: o.source ?? "127.0.0.1", longueur: octets.length })}\n`);
    if (octets.length) versAdaptateur.write(octets);
  };
  const serveur = net.createServer((client) => {
    const id = `c-${++n}`;
    const serveurAmont = net.connect(Number(amont.port), amont.hostname);
    let copieServeur = 0;
    client.on("data", (d) => {
      trame(id, "client", d);
      serveurAmont.write(d);
    });
    serveurAmont.on("data", (d) => {
      if (o.tronquerServeurApres === undefined) trame(id, "serveur", d);
      else if (copieServeur < o.tronquerServeurApres) trame(id, "serveur", d.subarray(0, o.tronquerServeurApres - copieServeur));
      copieServeur += d.length;
      client.write(d);
    });
    let fini = false;
    const fin = () => {
      if (fini) return;
      fini = true;
      trame(id, "fin", Buffer.alloc(0));
      client.destroy();
      serveurAmont.destroy();
    };
    client.on("end", () => serveurAmont.end());
    serveurAmont.on("end", () => client.end());
    client.on("close", fin);
    serveurAmont.on("close", fin);
    client.on("error", () => {});
    serveurAmont.on("error", () => {});
  });
  await new Promise((r) => serveur.listen(0, "127.0.0.1", r));
  return {
    url: `http://127.0.0.1:${serveur.address().port}`,
    trame,
    async arreter() {
      await new Promise((r) => serveur.close(() => r()));
      versAdaptateur.end();
    },
  };
}
