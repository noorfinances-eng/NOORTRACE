// Revue de sécurité interne de l'étape 8 : OpenTimestamps. Une
// attestation Bitcoin n'est acquise qu'après O-4 (CT-5 EX-6.6, EX-6.9) :
// défaut majeur relevé par la campagne TM-30 (engagement du nœud en attente
// de 44 octets sur un calendrier réel), calendrier menteur (jamais
// `complete` sans O-4 ; source indisponible : rien n'est écrit), O-4 (plage
// d'en-têtes bornée aux hauteurs du profil ; doublons du lecteur).

import { expect } from "chai";
import http from "node:http";
import { randomBytes } from "node:crypto";
import { sha256, octetsVersHex } from "@noortrace/noyau";
import * as O from "@noortrace/ancrage/ots";
import { chaineRegtest } from "./fixtures/ancrage-ots/outils.mjs";

const URI_A = "https://alice.calendrier.example";
const URI_B = "https://bob.calendrier.example";
const horlogeReelle = { murale: () => Date.now(), monotone: () => performance.now() };

/** Calendrier factice qui agrège comme un calendrier réel : sha256 · prepend(4) · append(8) · attestation en attente ; puis sert un chemin Bitcoin pour ce message de 44 octets. */
function calendrierAgregateur(hauteur = 975648) {
  const engagements = new Map();
  const serveur = http.createServer((req, rep) => {
    const morceaux = [];
    req.on("data", (d) => morceaux.push(d));
    req.on("end", () => {
      if (req.method === "POST" && req.url === "/digest") {
        const racine = new O.Noeud();
        const n1 = racine.operation(O.OP.SHA256, null);
        const n2 = n1.operation(O.OP.PREPEND, Uint8Array.from([0x6a, 0xf6, 0xbc, 0xd3]));
        const n3 = n2.operation(O.OP.APPEND, Uint8Array.from(randomBytes(8)));
        n3.ajouterAttestation(O.attestationEnAttente(URI_A));
        rep.writeHead(200, { "content-type": "application/vnd.opentimestamps.v1" });
        rep.end(Buffer.from(O.ecrireTimestamp(racine)));
        return;
      }
      const m = /^\/timestamp\/([0-9a-f]+)$/.exec(req.url ?? "");
      if (req.method === "GET" && m) {
        engagements.set(m[1], true);
        const chemin = new O.Noeud();
        chemin.operation(O.OP.SHA256, null).ajouterAttestation(O.attestationBitcoin(hauteur));
        rep.writeHead(200, { "content-type": "application/vnd.opentimestamps.v1" });
        rep.end(Buffer.from(O.ecrireTimestamp(chemin)));
        return;
      }
      rep.writeHead(404);
      rep.end();
    });
  });
  return new Promise((res) => serveur.listen(0, "127.0.0.1", () => {
    const port = serveur.address().port;
    const fetchLocal = (url, init) => fetch(url.replace(URI_A, `http://127.0.0.1:${port}`), init);
    res({ transport: O.transportHttps({ fetch: fetchLocal }), engagements, fermer: () => new Promise((r) => serveur.close(r)) });
  }));
}

describe("ancrage, revue de sécurité de l'étape 8 : mise à niveau d'une preuve réelle (CT-5 EX-6.6 ; défaut majeur relevé par TM-30)", function () {
  this.timeout(20000);
  let cal;
  before(async () => {
    cal = await calendrierAgregateur();
  });
  after(async () => {
    await cal.fermer();
  });

  it("mettreANiveau fusionne le chemin reçu pour un engagement de 44 octets (sub_stamp.msg du client officiel) et rend une preuve complète (défaut : ErreurOts engagement levée par fusionnerOts)", async () => {
    const empreinte = new Uint8Array(randomBytes(32));
    const r = await O.soumettre({ empreinte, nonce: new Uint8Array(randomBytes(16)), calendriers: [URI_A], minReponses: 1, delaiMs: 5000, transport: cal.transport, horloge: horlogeReelle });
    expect(r.ecrire).to.equal(true);
    const lu = O.lireOts(r.octets);
    const attentes = O.attestationsEnAttente(lu.arbre, lu.empreinte);
    expect(attentes).to.have.length(1);
    expect(attentes[0].message).to.have.length(44);
    const m = await O.mettreANiveau({ preuve: r.octets, listeBlanche: [URI_A], transport: cal.transport, horloge: horlogeReelle, delaiMs: 5000, entetes: null, reseau: null });
    expect([...cal.engagements.keys()]).to.deep.equal([Buffer.from(attentes[0].message).toString("hex")]);
    expect(m.refus).to.deep.equal([]);
    expect(m.nouvelle).to.be.instanceOf(Uint8Array);
    expect(m.etat).to.equal("complete");
    expect(O.etatPreuve(m.nouvelle)).to.equal("complete");
    expect(m.hauteurs).to.deep.equal([975648, 975648]);
  });

  it("fusionnerOts accepte un engagement de 1 à 4 096 octets (BORNES.MESSAGE_MAX) et refuse un engagement vide, au-delà de la borne ou inconnu de la preuve", () => {
    const empreinte = new Uint8Array(32).fill(3);
    const nonce = new Uint8Array(16).fill(4);
    const n = new O.Noeud();
    n.operation(O.OP.APPEND, Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8)).ajouterAttestation(O.attestationEnAttente(URI_B));
    const preuve = O.construirePreuve({ empreinte, nonce, reponses: [n] }).octets;
    const lu = O.lireOts(preuve);
    const [attente] = O.attestationsEnAttente(lu.arbre, lu.empreinte);
    expect(attente.message).to.have.length(40);
    const chemin = new O.Noeud();
    chemin.operation(O.OP.SHA256, null).ajouterAttestation(O.attestationBitcoin(12));
    const f = O.fusionnerOts(preuve, { engagement: attente.message, chemin, uri: URI_B });
    expect(f.retirees).to.equal(1);
    expect(O.etatPreuve(f.octets)).to.equal("complete");
    expect(() => O.fusionnerOts(preuve, { engagement: new Uint8Array(0), chemin, uri: URI_B })).to.throw(O.ErreurOts, /engagement/);
    expect(() => O.fusionnerOts(preuve, { engagement: new Uint8Array(4097), chemin, uri: URI_B })).to.throw(O.ErreurOts, /engagement/);
    expect(() => O.fusionnerOts(preuve, { engagement: new Uint8Array(32).fill(9), chemin, uri: URI_B })).to.throw(O.ErreurOts, /engagement_inconnu|aucune attestation/);
  });
});

describe("ancrage, revue de sécurité de l'étape 8 : une attestation Bitcoin non vérifiée ne rend jamais une preuve complete (CT-5 EX-6.6, EX-6.9)", function () {
  const EMPREINTE = sha256(new TextEncoder().encode("manifeste de la période (revue de sécurité)"));
  const NONCE = Uint8Array.from({ length: 16 }, (_, i) => i + 1);
  let t = 0;
  const horloge = { murale: () => 1_800_000_000_000 + t, monotone: () => t++ };
  const promesse = (uri, sel) => {
    const n = new O.Noeud();
    n.operation(O.OP.APPEND, Uint8Array.of(sel, 7, 7, 7)).operation(O.OP.SHA256, null).ajouterAttestation(O.attestationEnAttente(uri));
    return O.ecrireTimestamp(n);
  };
  const mensonge = (hauteur) => {
    const n = new O.Noeud();
    n.operation(O.OP.PREPEND, Uint8Array.of(0xde, 0xad)).operation(O.OP.SHA256, null).ajouterAttestation(O.attestationBitcoin(hauteur));
    return O.ecrireTimestamp(n);
  };
  const rep = (octets) => ({ status: 200, entetes: {}, corps: octets });
  const E = O.engagementOctets(EMPREINTE, NONCE);
  // Chaîne regtest de 17 en-têtes (0 à 16) ; la racine de la hauteur 5 porte le résultat du chemin honnête de B.
  const honneteB = (() => {
    const n = new O.Noeud();
    n.operation(O.OP.PREPEND, Uint8Array.of(9)).operation(O.OP.SHA256, null).ajouterAttestation(O.attestationBitcoin(5));
    return n;
  })();
  const racine5 = sha256(new Uint8Array([9, ...sha256(new Uint8Array([...E, 2, 7, 7, 7]))]));
  const chaine = chaineRegtest({ debut: 0, nombre: 17, racines: new Map([[5, racine5]]) }).document;
  /** Source d'en-têtes qui ne connaît que les hauteurs 0 à `connus` : erreur au-delà (comme un nœud en retard). */
  const source = (connus) => async ({ hauteurs }) => {
    if (hauteurs[1] > connus) throw new O.ErreurEntetes("hauteur_indisponible", "le nœud ne connaît pas encore la hauteur demandée");
    return chaine;
  };

  async function preuveEnAttente() {
    return O.soumettre({ empreinte: EMPREINTE, nonce: NONCE, calendriers: [URI_A, URI_B], minReponses: 2, delaiMs: 5000, horloge, transport: { post: async (url) => rep(url.startsWith(URI_A) ? promesse(URI_A, 1) : promesse(URI_B, 2)) } });
  }
  const miseANiveau = ({ preuve, reponseB, entetes, exigerO4 = true }) => O.mettreANiveau({
    preuve, listeBlanche: [URI_A, URI_B], horloge, reseau: "regtest", entetes, exigerO4,
    transport: { get: async (url) => (url.startsWith(URI_B) ? rep(reponseB) : { status: 404, entetes: {}, corps: new TextEncoder().encode("Pending confirmation in Bitcoin blockchain") }) },
  });

  it("à la soumission : une réponse qui porte d'emblée une attestation Bitcoin n'est pas complete sans O-4 réussie ; avec une source, O-4 est exécutée ; sans source, l'état le dit (attestation_non_verifiee)", async () => {
    const transport = { post: async (url) => rep(url.startsWith(URI_A) ? promesse(URI_A, 1) : mensonge(5)) };
    const sansSource = await O.soumettre({ empreinte: EMPREINTE, nonce: NONCE, calendriers: [URI_A, URI_B], minReponses: 2, delaiMs: 5000, horloge, transport });
    expect(sansSource.ecrire).to.equal(true);
    expect(sansSource.attestation, "sans source d'en-têtes, l'attestation Bitcoin reste en attente de vérification").to.equal("en_attente");
    expect(sansSource.attestation_non_verifiee).to.equal(true);
    const avecSource = await O.soumettre({ empreinte: EMPREINTE, nonce: NONCE, calendriers: [URI_A, URI_B], minReponses: 2, delaiMs: 5000, horloge, transport, entetes: source(16), reseau: "regtest" });
    expect(avecSource.attestation).to.equal("en_attente");
    expect(avecSource.verification.checks["O-4"]).to.equal("echoue");
    expect(avecSource.refus.map((r) => r.motif)).to.deep.equal(["verification_O-4"]);
    // Une attestation vraie, vérifiée : complete.
    const vraie = { post: async (url) => rep(url.startsWith(URI_A) ? promesse(URI_A, 1) : (() => { const n = new O.Noeud(); n.operation(O.OP.APPEND, Uint8Array.of(2, 7, 7, 7)).operation(O.OP.SHA256, null).fusionner(honneteB); return O.ecrireTimestamp(n); })()) };
    const verifiee = await O.soumettre({ empreinte: EMPREINTE, nonce: NONCE, calendriers: [URI_A, URI_B], minReponses: 2, delaiMs: 5000, horloge, transport: vraie, entetes: source(16), reseau: "regtest" });
    expect(verifiee.verification.checks["O-4"]).to.equal("reussi");
    expect(verifiee.attestation).to.equal("complete");
  });

  it("à la mise à niveau : un calendrier qui ment est refusé par O-4 quand les en-têtes sont là ; source indisponible ou hauteur absente : rien n'est écrit, état en_attente ; sans source, rien n'est écrit non plus quand O-4 est exigée", async () => {
    const p0 = await preuveEnAttente();
    expect(p0.attestation).to.equal("en_attente");
    // Témoin : en-têtes disponibles, mensonge à la hauteur 5 refusé par O-4.
    const refuse = await miseANiveau({ preuve: p0.octets, reponseB: mensonge(5), entetes: source(16) });
    expect(refuse.nouvelle).to.equal(null);
    expect(refuse.etat).to.equal("en_attente");
    expect(refuse.refus.map((r) => r.motif)).to.deep.equal(["verification_O-4"]);
    // Le nœud du client n'a que la hauteur 4 (h' = 5 absente) : source indisponible, rien n'est écrit.
    const indisponible = await miseANiveau({ preuve: p0.octets, reponseB: mensonge(5), entetes: source(4) });
    expect(indisponible.nouvelle).to.equal(null);
    expect(indisponible.etat).to.equal("en_attente");
    expect(indisponible.refus.map((r) => r.motif)).to.deep.equal(["en_tetes_indisponibles"]);
    // Le menteur choisit une hauteur que le nœud n'a pas (4 000 000) : même issue.
    const lointaine = await miseANiveau({ preuve: p0.octets, reponseB: mensonge(4000000), entetes: source(16) });
    expect(lointaine.nouvelle).to.equal(null);
    expect(lointaine.etat).to.equal("en_attente");
    // Chemin honnête (racine de l'en-tête 5), nœud à la hauteur 5 : O-4 n'a besoin que de h' (pas de h' + 11) → complete.
    const honnete = await miseANiveau({ preuve: p0.octets, reponseB: O.ecrireTimestamp(honneteB), entetes: source(5) });
    expect(honnete.verification.checks["O-4"]).to.equal("reussi");
    expect(honnete.etat).to.equal("complete");
    expect(honnete.nouvelle).to.not.equal(null);
    expect(honnete.hauteurs).to.deep.equal([5, 5]);
    // O-4 exigée sans source : rien n'est écrit (la promesse de A reste à mettre à niveau).
    const sansSource = await miseANiveau({ preuve: p0.octets, reponseB: mensonge(5), entetes: null });
    expect(sansSource.nouvelle).to.equal(null);
    expect(sansSource.refus.map((r) => r.motif)).to.deep.equal(["en_tetes_indisponibles"]);
    // Conduite d'avant (en-têtes facultatifs) : encore disponible quand O-4 n'est pas exigée.
    const facultatif = await miseANiveau({ preuve: p0.octets, reponseB: mensonge(5), entetes: null, exigerO4: false });
    expect(facultatif.etat).to.equal("complete");
  });

  it("CT-6 O-4 : la plage d'en-têtes demandée vient des seules attestations du profil ; un écart de hauteurs démesuré est refusé sans demande d'en-têtes", async () => {
    const p0 = await preuveEnAttente();
    // Preuve relue du disque : chemin honnête à la hauteur 5 sous le profil, et une attestation à la hauteur 199 000 sous
    // une opération hors profil (keccak256) ; seule la hauteur du profil compte pour la plage d'en-têtes.
    const mixte = (() => {
      const racine = new O.Noeud();
      const e = racine.operation(O.OP.APPEND, NONCE).operation(O.OP.SHA256, null);
      const b = e.operation(O.OP.APPEND, Uint8Array.of(2, 7, 7, 7)).operation(O.OP.SHA256, null);
      b.operation(O.OP.PREPEND, Uint8Array.of(9)).operation(O.OP.SHA256, null).ajouterAttestation(O.attestationBitcoin(5));
      b.operation(O.OP.KECCAK256, null).ajouterAttestation(O.attestationBitcoin(199000));
      return O.ecrireOts({ empreinte: EMPREINTE, arbre: racine });
    })();
    const arbre = O.lireOts(mixte).arbre;
    expect(O.hauteursAttestees(arbre)).to.deep.equal({ min: 5, max: 199000 });
    expect(O.hauteursProfil(arbre, EMPREINTE), "les hauteurs hors profil ne dictent pas la plage demandée au nœud").to.deep.equal({ min: 5, max: 5 });
    let demandees = null;
    const c = await O.verifierCompletude({ octets: mixte, empreinteAttendue: EMPREINTE, reseau: "regtest", exigerO4: true, entetes: async ({ hauteurs }) => { demandees = hauteurs; return chaine; } });
    expect(demandees).to.deep.equal([5, 5]);
    expect(c.complete).to.equal(true);
    // Deux attestations du profil à 0 et 199 000 : écart au-delà de la borne, refus, aucun en-tête demandé.
    const ecartee = (() => {
      const n = new O.Noeud();
      const a = n.operation(O.OP.PREPEND, Uint8Array.of(9)).operation(O.OP.SHA256, null);
      a.ajouterAttestation(O.attestationBitcoin(0));
      a.ajouterAttestation(O.attestationBitcoin(199000));
      return O.ecrireTimestamp(n);
    })();
    demandees = null;
    const r2 = await miseANiveau({ preuve: p0.octets, reponseB: ecartee, entetes: async ({ hauteurs }) => { demandees = hauteurs; return chaine; } });
    expect(demandees).to.equal(null);
    expect(r2.nouvelle).to.equal(null);
    expect(r2.refus.map((x) => x.motif)).to.deep.equal(["hauteurs_incoherentes"]);
    expect(O.BORNES.ECART_HAUTEURS_MAX).to.equal(4032);
  });

  it("CT-6 O-4 : le contrôle de doublon du lecteur .ots n'est plus quadratique : 23 800 attestations distinctes sous un nœud se lisent en moins d'une seconde", function () {
    this.timeout(20000);
    const n = new O.Noeud();
    for (let h = 1; h <= 23800; h += 1) n.ajouterAttestation(O.attestationBitcoin(h));
    const octets = O.ecrireTimestamp(n);
    expect(octets.length).to.be.above(256 * 1024);
    const debut = performance.now();
    const lu = O.lireTimestamp(octets, { tailleMax: 1024 * 1024 });
    const duree = performance.now() - debut;
    expect(lu.attestations).to.have.length(23800);
    expect(duree, `lecture en ${Math.round(duree)} ms`).to.be.below(1000);
    expect(() => O.lireOts(O.ecrireOts({ empreinte: new Uint8Array(32).fill(1), arbre: (() => { const m = new O.Noeud(); m.attestations.push(O.attestationBitcoin(7), O.attestationBitcoin(7)); return m; })() }))).to.throw(O.ErreurOts, /double/);
  });
});

export { octetsVersHex };
