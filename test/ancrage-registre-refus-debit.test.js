// CT-4 OP-8 (lecture `inscriptionAilleurs` de @noortrace/ancrage/registre,
// partagée par le relais d'inscription du composant d'ancrage et l'agent
// d'inscription) face au refus pour débit du nœud : noorcore rend l'erreur
// JSON-RPC `-32000 rate limited` à un `eth_getLogs` quand on lui en enchaîne
// une dizaine d'affilée, ce que fait la lecture en tranches de 16 384 blocs
// (EX-5.11) dès que le contrat a plus de quelques centaines de milliers de
// blocs (relevé sur le réseau de développement 2124 : 14 tranches, refus à la
// onzième, accepté de nouveau moins d'une seconde plus tard). Un refus pour
// débit ne dit rien des journaux : l'appel est refait aux mêmes paramètres
// après une pause de 250 ms doublée à chaque refus et plafonnée à 4 s, au plus
// 30 s de pause par tranche, comme la lecture du jeu de CT-3 EX-8.1 ; au-delà,
// ou pour toute autre erreur, la lecture lève `noeud_injoignable` : la
// vérification n'est jamais sautée. Nœud simulé par le transport du client
// JSON-RPC ; pauses relevées, non dormies.

import { expect } from "chai";
import * as R from "@noortrace/ancrage/registre";

const CONTRAT = "0xbec49fa140acaa83533fb00a2bb19bddd0290f25";
const CLE = "0x1111111111111111111111111111111111111111";
const ORG = "0x" + "aa".repeat(32);
const AUTRE = "0x" + "bb".repeat(32);
const SUJET_CLE = "0x" + "00".repeat(12) + CLE.slice(2);

/**
 * Nœud simulé : tête `tete` ; `refus(n)` dit si le n-ième `eth_getLogs`
 * (compté depuis 1) est refusé pour débit ; un événement RecorderRegistered de
 * la clé sous `AUTRE` au bloc `bloc`. Rend le transport et le relevé des
 * appels.
 */
function noeud({ tete, refus = () => false, bloc = null, autreErreur = null }) {
  const appels = [];
  let n = 0;
  const transport = async ({ octets }) => {
    const req = JSON.parse(Buffer.from(octets).toString("utf8"));
    const rep = (corps) => ({ status: 200, octets: Buffer.from(JSON.stringify({ jsonrpc: "2.0", id: req.id, ...corps })) });
    if (req.method === "eth_blockNumber") return rep({ result: "0x" + tete.toString(16) });
    if (req.method !== "eth_getLogs") return rep({ error: { code: -32601, message: "method not found" } });
    n += 1;
    const f = req.params[0];
    appels.push({ n, de: BigInt(f.fromBlock), a: BigInt(f.toBlock) });
    if (autreErreur && autreErreur(n)) return rep({ error: { code: -32000, message: "header not found" } });
    if (refus(n)) return rep({ error: { code: -32000, message: "rate limited" } });
    const journaux = bloc !== null && BigInt(f.fromBlock) <= BigInt(bloc) && BigInt(bloc) <= BigInt(f.toBlock)
      ? [{ address: CONTRAT, topics: [R.SUJETS.RecorderRegistered, AUTRE, SUJET_CLE, "0x" + "cc".repeat(32)], blockNumber: "0x" + bloc.toString(16), transactionHash: "0x" + "dd".repeat(32) }]
      : [];
    return rep({ result: journaux });
  };
  return { rpc: new R.ClientRpc({ points: ["http://127.0.0.1:8645"], transport }), appels };
}

describe("CT-4 OP-8, lecture inscriptionAilleurs : refus pour débit du nœud (-32000 rate limited) refait après une pause, jamais une vérification sautée", function () {
  it("quatorze tranches, refus à partir de la onzième puis une fois sur deux : chaque tranche est lue, l'inscription ailleurs est trouvée dans la dernière ; pauses 250 ms doublées, remises à 250 ms à la tranche suivante", async function () {
    const pauses = [];
    const depuis = 8328n;
    const tete = depuis + 14n * R.TRANCHE_JOURNAUX - 1n;
    const { rpc, appels } = noeud({ tete, refus: (n) => n >= 11 && n % 2 === 1, bloc: Number(tete) - 5 });
    const r = await R.inscriptionAilleurs({ rpc, contrat: CONTRAT, depuis, orgId: ORG, chainKey: CLE, attendre: async (ms) => pauses.push(ms) });
    expect(r).to.deep.equal({ org_id: AUTRE, block_number: Number(tete) - 5, transaction_hash: "0x" + "dd".repeat(32) });
    // Chaque tranche lue avec succès une fois, dans l'ordre, sans trou.
    const lues = appels.filter((x) => !(x.n >= 11 && x.n % 2 === 1));
    expect(lues.map((x) => x.de)).to.deep.equal(Array.from({ length: 14 }, (_, i) => depuis + BigInt(i) * R.TRANCHE_JOURNAUX));
    expect(pauses, "une pause de 250 ms par refus, chaque refus suivi d'une réponse").to.deep.equal([250, 250, 250, 250]);
  });

  it("refus répétés : pauses 250, 500, 1 000, 2 000, puis 4 000 ms, jusqu'à 30 s de pause pour la tranche ; au-delà, noeud_injoignable (la vérification n'est pas sautée)", async function () {
    const pauses = [];
    const { rpc } = noeud({ tete: 100n, refus: () => true });
    let err = null;
    try {
      await R.inscriptionAilleurs({ rpc, contrat: CONTRAT, depuis: 0, orgId: ORG, chainKey: CLE, attendre: async (ms) => pauses.push(ms) });
    } catch (e) {
      err = e;
    }
    expect(err?.code, String(err)).to.equal("noeud_injoignable");
    expect(err.message).to.match(/rate limited/);
    expect(pauses).to.deep.equal([250, 500, 1000, 2000, 4000, 4000, 4000, 4000, 4000, 4000]);
    expect(pauses.reduce((a, b) => a + b, 0)).to.be.at.most(30000);
  });

  it("une autre erreur JSON-RPC n'est pas refaite : noeud_injoignable aussitôt ; sans refus, aucune pause et null quand la clé n'est inscrite nulle part ailleurs", async function () {
    const pauses = [];
    const a = noeud({ tete: 100n, autreErreur: (n) => n === 1 });
    let err = null;
    try {
      await R.inscriptionAilleurs({ rpc: a.rpc, contrat: CONTRAT, depuis: 0, orgId: ORG, chainKey: CLE, attendre: async (ms) => pauses.push(ms) });
    } catch (e) {
      err = e;
    }
    expect(err?.code).to.equal("noeud_injoignable");
    expect(a.appels).to.have.lengthOf(1);
    const b = noeud({ tete: 3n * R.TRANCHE_JOURNAUX });
    expect(await R.inscriptionAilleurs({ rpc: b.rpc, contrat: CONTRAT, depuis: 0, orgId: ORG, chainKey: CLE, attendre: async (ms) => pauses.push(ms) })).to.equal(null);
    expect(b.appels).to.have.lengthOf(4);
    expect(pauses).to.deep.equal([]);
  });
});
