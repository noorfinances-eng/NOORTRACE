// Agent d'inscription : nonce du déploiement du jeu d'approbateurs (CT-4
// EX-8.14, recoupement et plancher du complément du 2026-11-17 ; RG-19).
// L'adresse du jeu est CREATE(déployeur, nonce) : elle est calculée avant
// l'envoi. Le nonce qui sert à ce calcul doit être celui qui est signé, plancher
// compris ; sinon le contrat est créé à une autre adresse que celle que l'agent
// attend et relit (OP-11).
//
// Réseau Hardhat en mémoire (31337), présenté comme un validateur noorcore par
// le pont de test/fixtures/inscription/reseau-essai.mjs, derrière trois points :
// le premier à jour mais muet sur eth_getTransactionCount ; les deux autres en
// retard d'un bloc (nonce de leur hauteur, reçus des blocs qu'ils n'ont pas
// appliqués absents). Un approvisionnement de la trésorerie (compte Hardhat 0,
// aussi déployeur) est inclus et écrit dans les captures du client juste avant
// `inscrire-client` : le plancher du déployeur dépasse alors de 1 la valeur des
// points, et le jeu se déploie au plancher.

import { expect } from "chai";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { SignataireChaineFichier } from "@noortrace/ancrage/registre";
import * as R from "@noortrace/ancrage/registre";
import * as E from "./fixtures/inscription/reseau-essai.mjs";
import * as O from "./fixtures/inscription/outils.mjs";

const X = "exploitant operateur-1";
const JOURNAL = "journal-principal";
const JID = "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b";

/** Point JSON-RPC devant le pont ; `regle(requete)` rend `undefined` (pont), `{ couper: true }` ou `{ result }`. */
function point(cible, regle) {
  const serveur = http.createServer(async (req, res) => {
    let corps = "";
    for await (const b of req) corps += b;
    const requete = JSON.parse(corps);
    const s = await regle(requete);
    if (s?.couper) {
      res.destroy();
      return;
    }
    const octets = s !== undefined
      ? Buffer.from(JSON.stringify({ jsonrpc: "2.0", id: requete.id, result: s.result }))
      : Buffer.from(await (await fetch(cible, { method: "POST", headers: { "content-type": "application/json" }, body: corps })).arrayBuffer());
    res.writeHead(200, { "content-type": "application/json", "content-length": octets.length });
    res.end(octets);
  });
  return new Promise((ok) => serveur.listen(0, "127.0.0.1", () => ok({ serveur, url: `http://127.0.0.1:${serveur.address().port}` })));
}

describe("inscription : agent, nonce du déploiement du jeu d'approbateurs (CT-4 EX-8.14, RG-19), réseau Hardhat derrière trois points", function () {
  this.timeout(600000);
  let reseau;
  let pont;
  let dir;
  let a;
  const serveurs = [];
  const etat = { actif: false };

  before(async function () {
    dir = O.repertoireTemporaire("noortrace-inscription-nonce-deploiement-");
    reseau = await E.demarrerReseau();
    pont = await E.ouvrirPont(reseau.provider, { noorcore: true });
    const manifeste = E.ecrireManifesteEssai(path.join(dir, "instance"), reseau);
    const p = reseau.provider;
    const tete = async () => BigInt(await p.request({ method: "eth_blockNumber", params: [] }));
    const aJour = await point(pont.url, async (q) => (etat.actif && q.method === "eth_getTransactionCount" ? { couper: true } : undefined));
    const regleRetard = async (q) => {
      if (!etat.actif) return undefined;
      const sienne = (await tete()) - 1n;
      if (q.method === "eth_getTransactionCount") return { result: await p.request({ method: q.method, params: [q.params[0], "0x" + sienne.toString(16)] }) };
      if (q.method === "eth_getTransactionReceipt") {
        const r = await p.request({ method: q.method, params: q.params });
        if (r && BigInt(r.blockNumber) > sienne) return { result: null };
      }
      return undefined;
    };
    const enRetard = await point(pont.url, regleRetard);
    const enRetard2 = await point(pont.url, regleRetard);
    serveurs.push(aJour.serveur, enRetard.serveur, enRetard2.serveur);
    a = await O.demarrerAgentEssai({ manifeste, rpc: [aJour.url, enRetard.url, enRetard2.url], delai_s: 3, clesRepertoire: dir });
  });

  after(async function () {
    await a?.arreter();
    for (const s of serveurs) await new Promise((ok) => s.close(() => ok()));
    await pont?.fermer();
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
    if (a?.base) fs.rmSync(a.base, { recursive: true, force: true });
  });

  it("approvisionnement inclus juste avant, nonce relu sur les deux points en retard d'un bloc : le jeu est signé au plancher, à l'adresse calculée sur ce même nonce, et inscrire-client réussit", async function () {
    const slug = "nonce-deploiement";
    const k = crypto.createHash("sha256").update(`noortrace/essai/inscription/chaine/${slug}`).digest();
    fs.writeFileSync(path.join(dir, `${slug}.cle`), k.toString("hex"), { mode: 0o600 });
    const chaine = new SignataireChaineFichier(new Uint8Array(k)).adresse();
    const ed = O.cleEd25519(slug);
    const doc = O.documentCle({ keyId: `rec-${slug}-1`, journalId: JID, chainKey: chaine, publique: ed.publique });
    const travail = async (t) => {
      const r = await a.executer(X, t);
      expect(r.refus, JSON.stringify(r.refus)).to.equal(undefined);
      return r.sortie;
    };
    const confirmer = async (operation, orgId) => {
      const piece = "0x" + crypto.createHash("sha256").update(`pièce ${operation} ${slug}`).digest("hex");
      const r = await a.confirmation(X, { operation, objet: { org_id: orgId, cle_chaine: chaine }, personne_client: "Responsable de l'essai", canal: "appel téléphonique au numéro du contrat", instant: "2026-11-17T10:00:00.000Z", piece_sha256: piece });
      expect(r.accepte, JSON.stringify(r)).to.equal(true);
    };
    const APP = [1, 2, 3].map((i) => O.compteHardhat(i).adresse);
    const s0 = await travail({ commande: "inscrire-client-preparer", slug, parametres: { org: slug, journaux: [JOURNAL], approbateurs: APP, seuil: 2, admin_jeu: O.compteHardhat(4).adresse, cles_enregistreur: [doc] } });
    expect(s0.result, JSON.stringify(s0.error)).to.equal("reussi");
    const orgId = JSON.parse(fs.readFileSync(a.client(slug).dossier, "utf8")).organisation.org_id;
    await confirmer("approvisionner", orgId);
    const s1 = await travail({ commande: "approvisionner", slug, parametres: { cle_chaine: chaine } });
    expect(s1.result, JSON.stringify(s1.error)).to.equal("reussi");
    const caps = a.client(slug).captures;
    const deployeur = O.compteHardhat(0).adresse;
    const avant = R.lireEnvois(caps).filter((e) => e.envoi.from === deployeur);
    expect(avant.length, "un envoi inclus de la trésorerie, qui est aussi le déployeur").to.equal(1);
    expect(avant[0].issue?.block_number).to.be.a("number");

    etat.actif = true;
    let s2;
    try {
      await confirmer("approvisionnement", orgId);
      // Décisions du 2026-11-25 (CT-4 EX-7.8) : la fiche de contrôle des adresses des approbateurs, confirmée avant le déploiement du jeu.
      expect((await a.confirmerFiche(X, slug)).reponse.accepte).to.equal(true);
      s2 = await travail({ commande: "inscrire-client", slug, parametres: {} });
    } finally {
      etat.actif = false;
    }
    const deploiement = R.lireEnvois(caps).find((e) => e.envoi.from === deployeur && e.envoi.to === null);
    expect(deploiement, "envoi du déploiement écrit").to.not.equal(undefined);
    expect(deploiement.envoi.nonce, "signé au plancher, après le nonce de l'approvisionnement inclus").to.equal(avant[0].envoi.nonce + 1);
    expect(s2.result, `${JSON.stringify(s2.error)} ; jeu ${s2.outputs?.curator_set}`).to.equal("reussi");
    expect(s2.outputs.curator_set, "adresse du jeu = CREATE(déployeur, nonce signé)").to.equal(R.adresseCreation(deployeur, deploiement.envoi.nonce));
  });
});
