// Lot B du composant d'ancrage (CT-5 §6) : soumission aux calendriers
// (EX-6.2, AN-17), décision d'écriture et rejeu avec le même engagement
// (EX-8.11), mise à niveau (EX-6.6, EX-6.7, AN-19 : liste blanche, 404, 200
// fusionné puis vérifié), cadence (first_after_s, interval_s ≥ 60,
// give_up_after_s), transport par défaut (HTTPS, Accept, corps borné à
// 10 000 octets), fichier d'en-têtes (EX-6.8, AN-20 : bitcoin_rpc ou fichier),
// dépôt des preuves (EX-6.5, EX-5.14 : création exclusive, versions,
// entetes-bitcoin.json). Un essai contre les calendriers publics d'EX-6.2 et
// un essai avec le vérificateur Go de CT-6 sont en attente quand leur
// condition n'est pas remplie (condition nommée dans le titre).

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import * as N from "@noortrace/noyau";
import {
  engagement, soumettre, mettreANiveau, cadenceMiseANiveau, transportHttps, relireReponseCalendrier, ErreurTransport, ACCEPT_OTS, DEFAUTS,
  lireOts, ecrireTimestamp, construirePreuve, attestationEnAttente, attestationBitcoin, Noeud, OP, ErreurOts, BORNES, attestationsEnAttente,
  verifierOts, etatPreuve, executerArbre, hauteursAttestees,
  fichierEntetes, lireFichierEntetes, rpcBitcoinHttp, bornesFichierEntetes, ErreurEntetes, decomposerEnTete,
  DepotOts, ErreurDepot, nomObjet, nomPeriode,
} from "@noortrace/ancrage/ots";
import { verifierChaineEntetes } from "@noortrace/ancrage/ots";
import {
  RACINE, CT5_OTS, CT6_OTS, CT6_DOSSIERS, lireOctets, lireJson, hex, sha256, sha256Hex, utf8, memesOctets, chaineRegtest, horlogeFixe,
  transportFactice, reponseHttp, enAttente, repertoireTemporaire, construireVerificateurGo,
} from "./fixtures/ancrage-ots/outils.mjs";

const OTS_JSON = lireJson(path.join(CT5_OTS, "ots.json"));
const MISE_A_NIVEAU = lireJson(path.join(CT5_OTS, "mise-a-niveau.json"));
const ALICE = "https://alice.btc.calendar.opentimestamps.org";
const BOB = "https://bob.btc.calendar.opentimestamps.org";
const K2 = "0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff";
const ORG = "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab";
const JOURNAL = "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b";
// Agrégateurs publics par défaut (EX-6.2, R1-F56) et liste blanche de l'exemple d'EX-4.8.
const AGREGATEURS = ["https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org", "https://a.pool.eternitywall.com", "https://ots.btc.catallaxy.com"];
const LISTE_BLANCHE = [ALICE, BOB, "https://finney.calendar.eternitywall.com", "https://ots.btc.catallaxy.com"];

const verifierChaineEntetesOk = (doc) => verifierChaineEntetes(lireFichierEntetes(doc)).statut === "reussi";
const promesse = (uri) => {
  const n = new Noeud();
  n.ajouterAttestation(attestationEnAttente(uri));
  return ecrireTimestamp(n);
};
const brancheCalendrier = (uri, argument) => {
  const n = new Noeud();
  n.operation(OP.PREPEND, argument).operation(OP.SHA256, null).ajouterAttestation(attestationEnAttente(uri));
  return ecrireTimestamp(n);
};
/** Chemin Bitcoin synthétique pour un engagement : f1, 08, f0, 08, 08, attestation à `hauteur`. */
const cheminBitcoin = (hauteur, graine) => {
  const n = new Noeud();
  n.operation(OP.PREPEND, sha256(utf8(`${graine}/agregation`)))
    .operation(OP.SHA256, null)
    .operation(OP.APPEND, sha256(utf8(`${graine}/transaction`)))
    .operation(OP.SHA256, null)
    .operation(OP.SHA256, null)
    .ajouterAttestation(attestationBitcoin(hauteur));
  return n;
};

describe("ancrage lot B : soumission aux calendriers (EX-6.2, EX-8.11, AN-17)", () => {
  const cas = OTS_JSON.cases.find((c) => c.id === "point-k2-minimal");
  const nonce = N.hexVersOctets(cas.nonce, 16);
  const attendu = lireOctets(path.join(CT5_OTS, cas.file));

  it("engagement e = SHA-256(empreinte ‖ nonce) pour les trois cas de la famille ots", () => {
    for (const c of OTS_JSON.cases) expect(engagement(c.digest, N.hexVersOctets(c.nonce, 16))).to.equal(c.commitment);
    expect(engagement(N.hexVersOctets(K2), nonce)).to.equal(cas.commitment);
    expect(() => engagement(K2, new Uint8Array(15))).to.throw(ErreurOts).with.property("code", "nonce");
    expect(() => engagement("0x00", nonce)).to.throw();
  });

  it("POST <url>/digest, corps de 32 octets, Accept d'EX-6.2 ; deux promesses nues → le fichier d'EX-6.4 octet pour octet (min_responses atteint)", async () => {
    const transport = transportFactice((methode, url) => {
      if (url === `${BOB}/digest`) return reponseHttp(200, promesse(BOB), { "content-type": "application/octet-stream" });
      if (url === `${ALICE}/digest`) return reponseHttp(200, promesse(ALICE), { "content-type": "application/octet-stream" });
      throw new Error("inattendu");
    });
    const horloge = horlogeFixe();
    const r = await soumettre({ empreinte: K2, nonce, calendriers: [BOB, `${ALICE}/`], minReponses: 2, delaiMs: 5000, transport, horloge });
    expect(r.engagement).to.equal(cas.commitment);
    expect(r.ecrire).to.equal(true);
    expect(r.valides).to.equal(2);
    expect(r.attestation).to.equal("en_attente");
    expect(memesOctets(r.octets, attendu)).to.equal(true);
    expect(r.instant).to.equal(horloge.murale());
    expect(transport.appels).to.have.length(2);
    for (const a of transport.appels) {
      expect(a.methode).to.equal("POST");
      expect(a.url.endsWith("/digest")).to.equal(true);
      expect(a.corps).to.have.length(32);
      expect(hex(a.corps)).to.equal(cas.commitment);
      expect(a.entetes.Accept).to.equal(ACCEPT_OTS);
      expect(a.delaiMs).to.equal(5000);
    }
    // Les réponses ne portent que l'engagement : jamais l'empreinte.
    expect(transport.appels.some((a) => hex(a.corps) === K2)).to.equal(false);
  });

  it("branches de calendrier à opérations propres (A.2) : point-k2-en-attente.ots reconstruit, quel que soit l'ordre des réponses", async () => {
    const c = OTS_JSON.cases.find((x) => x.id === "point-k2-en-attente");
    const transport = transportFactice((methode, url) => {
      const b = c.branches.find((x) => url === `${x.uri}/digest`);
      return reponseHttp(200, brancheCalendrier(b.uri, N.hexVersOctets(b.ops[0].argument, 16)));
    });
    const r = await soumettre({ empreinte: c.digest, nonce: N.hexVersOctets(c.nonce, 16), calendriers: [BOB, ALICE], transport, horloge: horlogeFixe() });
    expect(r.ecrire).to.equal(true);
    expect(memesOctets(r.octets, lireOctets(path.join(CT5_OTS, c.file)))).to.equal(true);
    expect(r.reponses.map((x) => x.attestations)).to.deep.equal([[{ genre: "en_attente", uri: BOB, hauteur: null }], [{ genre: "en_attente", uri: ALICE, hauteur: null }]]);
  });

  it("seuil non atteint (503, délai, réponse illisible) : rien n'est écrit, attestation « aucune » ; le rejeu avec le même nonce rend le même engagement et, les calendriers répondant, le même fichier", async () => {
    let panne = true;
    const transport = transportFactice((methode, url) => {
      if (url.startsWith(BOB)) return reponseHttp(200, promesse(BOB));
      if (panne) return reponseHttp(503, "indisponible", { "retry-after": "30" });
      return reponseHttp(200, promesse(ALICE));
    });
    const horloge = horlogeFixe();
    const r1 = await soumettre({ empreinte: K2, nonce, calendriers: [ALICE, BOB], minReponses: 2, transport, horloge });
    expect(r1.ecrire).to.equal(false);
    expect(r1.octets).to.equal(null);
    expect(r1.attestation).to.equal("aucune");
    expect(r1.valides).to.equal(1);
    expect(r1.reponses[0]).to.include({ calendrier: ALICE, status: 503, erreur: "http_503", octets: null });
    panne = false;
    const r2 = await soumettre({ empreinte: K2, nonce, calendriers: [ALICE, BOB], minReponses: 2, transport, horloge });
    expect(r2.engagement).to.equal(r1.engagement);
    expect(r2.ecrire).to.equal(true);
    expect(memesOctets(r2.octets, attendu)).to.equal(true);
    // Avec min_responses = 1, une seule promesse suffit : le fichier ne porte que cette branche.
    panne = true;
    const r3 = await soumettre({ empreinte: K2, nonce, calendriers: [ALICE, BOB], minReponses: 1, transport, horloge });
    expect(r3.ecrire).to.equal(true);
    const lu = lireOts(r3.octets);
    expect(executerArbre(lu.arbre, lu.empreinte).attestations.map((a) => a.uri)).to.deep.equal([BOB]);
    expect(verifierOts({ octets: r3.octets, empreinteAttendue: K2 }).checks["O-3"]).to.equal("reussi");
  });

  it("réponses refusées (EX-6.2, étape 3) : plus de 10 000 octets, hors profil, résultat hors bornes, sans attestation, octets en trop, erreur de transport, statut autre que 200", async () => {
    const horsProfil = (() => {
      const n = new Noeud();
      n.operation(OP.RIPEMD160, null).ajouterAttestation(attestationEnAttente(ALICE));
      return ecrireTimestamp(n);
    })();
    const tropLong = (() => {
      const n = new Noeud();
      n.operation(OP.APPEND, new Uint8Array(4096)).operation(OP.SHA256, null).ajouterAttestation(attestationEnAttente(ALICE));
      return ecrireTimestamp(n);
    })();
    const reponses = {
      "https://c1.example": reponseHttp(200, new Uint8Array(10001)),
      "https://c2.example": reponseHttp(200, horsProfil),
      "https://c3.example": reponseHttp(200, tropLong),
      "https://c4.example": reponseHttp(200, new Uint8Array([...promesse(ALICE), 0x00])),
      "https://c5.example": { lever: new ErreurTransport("delai", "aucune réponse") },
      "https://c6.example": reponseHttp(400, "mauvaise requete"),
      "https://c7.example": reponseHttp(200, new Uint8Array(0)),
      "https://c8.example": reponseHttp(200, promesse(ALICE)),
    };
    const transport = transportFactice((methode, url) => {
      const r = reponses[url.replace(/\/digest$/, "")];
      if (r.lever) throw r.lever;
      return r;
    });
    const r = await soumettre({ empreinte: K2, nonce, calendriers: Object.keys(reponses), minReponses: 2, transport, horloge: horlogeFixe() });
    expect(r.ecrire).to.equal(false);
    expect(r.valides).to.equal(1);
    expect(r.reponses.map((x) => x.erreur)).to.deep.equal(["reponse_trop_grande", "hors_profil", "operations", "illisible_octets_en_trop", "transport_delai", "http_400", "illisible_tronque", null]);
    // Le lecteur direct des réponses.
    const e = N.hexVersOctets(engagement(K2, nonce));
    expect(relireReponseCalendrier(horsProfil, e).erreur).to.equal("hors_profil");
    expect(relireReponseCalendrier(promesse(ALICE), e).erreur).to.equal(null);
    expect(relireReponseCalendrier(ecrireTimestamp(cheminBitcoin(1001, "x")), e).attestations[0].hauteur).to.equal(1001);
  });

  it("paramètres refusés : calendrier http, en double, min_responses hors bornes, délai nul, transport ou horloge absents", async () => {
    const transport = transportFactice(() => reponseHttp(200, promesse(ALICE)));
    const base = { empreinte: K2, nonce, calendriers: [ALICE, BOB], transport, horloge: horlogeFixe() };
    const refus = async (p, code) => {
      let erreur = null;
      try {
        await soumettre({ ...base, ...p });
      } catch (e) {
        erreur = e;
      }
      expect(erreur, code).to.be.instanceOf(ErreurOts);
      expect(erreur.code).to.equal(code);
    };
    await refus({ calendriers: ["http://alice.example"] }, "calendrier");
    await refus({ calendriers: ["https://alice.example/x y"] }, "calendrier");
    await refus({ calendriers: [ALICE, `${ALICE}/`] }, "calendriers");
    await refus({ calendriers: [] }, "calendriers");
    await refus({ minReponses: 3 }, "min_reponses");
    await refus({ minReponses: 0 }, "min_reponses");
    await refus({ delaiMs: 0 }, "delai");
    await refus({ transport: {} }, "transport");
    await refus({ horloge: null }, "horloge");
    await refus({ nonce: new Uint8Array(32) }, "nonce");
    expect(transport.appels).to.have.length(0);
  });
});

describe("ancrage lot B : mise à niveau (EX-6.6, EX-6.7, EX-8.11, AN-19)", () => {
  const avant = lireOctets(path.join(CT5_OTS, MISE_A_NIVEAU.before.file));
  const apres = lireOctets(path.join(CT5_OTS, MISE_A_NIVEAU.after.file));
  const reponseDer = N.hexVersOctets(MISE_A_NIVEAU.response.der);
  const chaine = lireJson(path.join(CT6_OTS, "entetes/chaine.json"));
  const engagementAlice = (() => {
    const lu = lireOts(avant);
    return hex(attestationsEnAttente(lu.arbre, lu.empreinte)[0].message);
  })();

  it("GET <uri>/timestamp/<e hex> avec Accept ; 200 : chemin fusionné, preuve vérifiée (O-1, O-3 ; O-4, O-5 avec en-têtes) → periode-1.ots, état complete", async () => {
    const transport = transportFactice((methode, url) => {
      expect(methode).to.equal("GET");
      expect(url).to.equal(`${ALICE}/timestamp/${engagementAlice.slice(2)}`);
      return reponseHttp(200, reponseDer, { "cache-control": "public, max-age=31536000" });
    });
    const horloge = horlogeFixe();
    const r = await mettreANiveau({ preuve: avant, listeBlanche: LISTE_BLANCHE, transport, horloge, entetes: chaine, reseau: "regtest" });
    expect(transport.appels).to.have.length(1);
    expect(transport.appels[0].entetes.Accept).to.equal(ACCEPT_OTS);
    expect(r.etat).to.equal("complete");
    expect(memesOctets(r.nouvelle, apres)).to.equal(true);
    expect(r.hauteurs).to.deep.equal([1001, 1001]);
    expect(r.refus).to.deep.equal([]);
    expect(r.reponses).to.have.length(1);
    expect(r.reponses[0]).to.include({ uri: ALICE, engagement: engagementAlice, status: 200, resultat: "fusionne" });
    expect(r.verification.checks).to.deep.equal({ "O-1": "reussi", "O-2": "reussi", "O-3": "reussi", "O-4": "reussi", "O-5": "reussi", "O-7": "reussi" });
    expect(r.instant).to.equal(horloge.murale());
    // Sans en-têtes : O-4 et O-5 non exécutées, la preuve est admise.
    const sans = await mettreANiveau({ preuve: avant, listeBlanche: LISTE_BLANCHE, transport, horloge });
    expect(memesOctets(sans.nouvelle, apres)).to.equal(true);
    expect(sans.verification.checks["O-4"]).to.equal("non_execute");
    // En-têtes par fonction, appelée avec les hauteurs attestées.
    let recu = null;
    const parFonction = await mettreANiveau({ preuve: avant, listeBlanche: LISTE_BLANCHE, transport, horloge, entetes: async ({ hauteurs }) => { recu = hauteurs; return chaine; } });
    expect(recu).to.deep.equal([1001, 1001]);
    expect(parFonction.verification.checks["O-5"]).to.equal("reussi");
  });

  it("404 « Pending confirmation in Bitcoin blockchain », « Timestamped by transaction… », « Not found » : rien n'est écrit, état en_attente ; autre statut : erreur consignée", async () => {
    for (const [corps, resultat] of [
      ["Pending confirmation in Bitcoin blockchain", "en_attente"],
      ["Timestamped by transaction 0123; waiting for 6 confirmations", "en_attente"],
      ["Not found", "non_trouve"],
      ["autre chose", "http_404"],
    ]) {
      const transport = transportFactice(() => reponseHttp(404, corps, { "cache-control": "public, max-age=60" }));
      const r = await mettreANiveau({ preuve: avant, listeBlanche: LISTE_BLANCHE, transport, horloge: horlogeFixe() });
      expect(r.nouvelle).to.equal(null);
      expect(r.etat).to.equal("en_attente");
      expect(r.reponses[0].resultat).to.equal(resultat);
      expect(r.refus).to.deep.equal([]);
    }
    for (const [reponse, resultat] of [[reponseHttp(500, "panne"), "http_500"], [{ lever: new ErreurTransport("delai", "délai") }, "transport_delai"], [{ lever: new Error("réseau") }, "transport_erreur"]]) {
      const transport = transportFactice(() => {
        if (reponse.lever) throw reponse.lever;
        return reponse;
      });
      const r = await mettreANiveau({ preuve: avant, listeBlanche: LISTE_BLANCHE, transport, horloge: horlogeFixe() });
      expect(r.nouvelle).to.equal(null);
      expect(r.reponses[0].resultat).to.equal(resultat);
    }
  });

  it("URI hors liste blanche : ignorée avec avertissement, aucune requête, attestation conservée ; liste blanche vide : rien n'est demandé", async () => {
    const transport = transportFactice(() => {
      throw new Error("aucune requête attendue");
    });
    const r = await mettreANiveau({ preuve: avant, listeBlanche: [BOB], transport, horloge: horlogeFixe() });
    expect(transport.appels).to.have.length(0);
    expect(r.nouvelle).to.equal(null);
    expect(r.etat).to.equal("en_attente");
    expect(r.refus).to.deep.equal([{ uri: ALICE, motif: "hors_liste_blanche", detail: "attestation conservée telle quelle" }]);
    const vide = await mettreANiveau({ preuve: avant, listeBlanche: [], transport, horloge: horlogeFixe() });
    expect(vide.refus[0].motif).to.equal("hors_liste_blanche");
    let erreur = null;
    try {
      await mettreANiveau({ preuve: avant, listeBlanche: ["http://alice.example"], transport, horloge: horlogeFixe() });
    } catch (e) {
      erreur = e;
    }
    expect(erreur).to.be.instanceOf(ErreurOts);
  });

  it("chemin reçu corrompu : résultat différent de la racine de l'en-tête attesté (O-4) → refusé, rien n'écrit ; hors profil ou illisible → refusé par le lecteur ; plus de 10 000 octets → refusé", async () => {
    const corrompu = Uint8Array.from(reponseDer);
    corrompu[3] ^= 0x01; // un octet de l'argument de la première opération
    const transport = transportFactice(() => reponseHttp(200, corrompu));
    const r = await mettreANiveau({ preuve: avant, listeBlanche: LISTE_BLANCHE, transport, horloge: horlogeFixe(), entetes: chaine });
    expect(r.nouvelle).to.equal(null);
    expect(r.etat).to.equal("en_attente");
    expect(r.refus).to.have.length(1);
    expect(r.refus[0].motif).to.equal("verification_O-4");
    expect(r.verification.checks["O-4"]).to.equal("echoue");
    // Sans en-têtes, le même chemin corrompu passe O-1 et O-3 : il est admis, l'exploitant n'ayant pas configuré de source (EX-6.6).
    const sansEntetes = await mettreANiveau({ preuve: avant, listeBlanche: LISTE_BLANCHE, transport, horloge: horlogeFixe() });
    expect(sansEntetes.nouvelle).to.not.equal(null);
    expect(sansEntetes.etat).to.equal("complete");
    // Hors profil.
    const horsProfil = (() => {
      const n = new Noeud();
      n.operation(OP.KECCAK256, null).ajouterAttestation(attestationBitcoin(1001));
      return ecrireTimestamp(n);
    })();
    const r2 = await mettreANiveau({ preuve: avant, listeBlanche: LISTE_BLANCHE, transport: transportFactice(() => reponseHttp(200, horsProfil)), horloge: horlogeFixe() });
    expect(r2.nouvelle).to.equal(null);
    expect(r2.refus[0].motif).to.equal("hors_profil");
    // Illisible.
    const r3 = await mettreANiveau({ preuve: avant, listeBlanche: LISTE_BLANCHE, transport: transportFactice(() => reponseHttp(200, Uint8Array.of(0xf0, 0x00))), horloge: horlogeFixe() });
    expect(r3.refus[0].motif).to.match(/^illisible_/);
    // Trop grand.
    const r4 = await mettreANiveau({ preuve: avant, listeBlanche: LISTE_BLANCHE, transport: transportFactice(() => reponseHttp(200, new Uint8Array(10001))), horloge: horlogeFixe() });
    expect(r4.refus[0].motif).to.equal("reponse_trop_grande");
    expect(r4.nouvelle).to.equal(null);
  });

  it("deux calendriers : l'un complète, l'autre reste en attente ; la seconde mise à niveau ne redemande que l'attestation restante ; en-têtes qui ne couvrent pas la hauteur : admise avec avertissement", async () => {
    const c = OTS_JSON.cases.find((x) => x.id === "point-k2-en-attente");
    const preuve = lireOctets(path.join(CT5_OTS, c.file));
    const lu = lireOts(preuve);
    const attentes = attestationsEnAttente(lu.arbre, lu.empreinte);
    const eAlice = hex(attentes.find((a) => a.attestation.uri === ALICE).message);
    const eBob = hex(attentes.find((a) => a.attestation.uri === BOB).message);
    const chemin = ecrireTimestamp(cheminBitcoin(1010, "alice"));
    const transport = transportFactice((methode, url) => {
      if (url === `${ALICE}/timestamp/${eAlice.slice(2)}`) return reponseHttp(200, chemin);
      if (url === `${BOB}/timestamp/${eBob.slice(2)}`) return reponseHttp(404, "Pending confirmation in Bitcoin blockchain");
      throw new Error(`URL inattendue ${url}`);
    });
    const r = await mettreANiveau({ preuve, listeBlanche: LISTE_BLANCHE, transport, horloge: horlogeFixe() });
    expect(r.etat).to.equal("complete");
    expect(r.hauteurs).to.deep.equal([1010, 1010]);
    const nouvelle = lireOts(r.nouvelle);
    const restantes = attestationsEnAttente(nouvelle.arbre, nouvelle.empreinte);
    expect(restantes.map((a) => a.attestation.uri)).to.deep.equal([BOB]);
    expect(etatPreuve(r.nouvelle)).to.equal("complete");
    // Racines des en-têtes : la hauteur 1010 porte le résultat → O-4 réussie ; en-têtes trop courts → avertissement.
    const resultat = executerArbre(nouvelle.arbre, nouvelle.empreinte).attestations.find((a) => a.genre === "bitcoin").resultat;
    const { document } = chaineRegtest({ debut: 1000, nombre: 25, racines: new Map([[1010, resultat]]) });
    const r2 = await mettreANiveau({ preuve, listeBlanche: LISTE_BLANCHE, transport, horloge: horlogeFixe(), entetes: document });
    expect(r2.verification.checks["O-4"]).to.equal("reussi");
    expect(r2.refus).to.deep.equal([]);
    const courts = chaineRegtest({ debut: 1011, nombre: 5 }).document;
    const r3 = await mettreANiveau({ preuve, listeBlanche: LISTE_BLANCHE, transport, horloge: horlogeFixe(), entetes: courts });
    expect(r3.nouvelle).to.not.equal(null);
    expect(r3.refus.map((x) => x.motif)).to.deep.equal(["en_tetes_insuffisants"]);
    // Seconde mise à niveau : seule l'attestation de bob est demandée.
    transport.appels.length = 0;
    const r4 = await mettreANiveau({ preuve: r.nouvelle, listeBlanche: LISTE_BLANCHE, transport, horloge: horlogeFixe() });
    expect(transport.appels.map((a) => a.url)).to.deep.equal([`${BOB}/timestamp/${eBob.slice(2)}`]);
    expect(r4.nouvelle).to.equal(null);
    expect(r4.etat).to.equal("complete");
  });

  it("cadence : first_after_s après la soumission, puis interval_s (jamais moins de 60 s), give_up_after_s → abandon signalé et tentative quotidienne", () => {
    const cadence = { first_after_s: 21600, interval_s: 1800, give_up_after_s: 1209600 };
    const t0 = 1793714400000;
    let c = cadenceMiseANiveau({ soumisMs: t0, derniereTentativeMs: null, maintenantMs: t0, cadence });
    expect(c).to.deep.equal({ prochaineMs: t0 + 21600000, abandon: false, echue: false });
    c = cadenceMiseANiveau({ soumisMs: t0, derniereTentativeMs: t0 + 21600000, maintenantMs: t0 + 21600000, cadence });
    expect(c.prochaineMs).to.equal(t0 + 21600000 + 1800000);
    expect(c.echue).to.equal(false);
    c = cadenceMiseANiveau({ soumisMs: t0, derniereTentativeMs: t0 + 21600000, maintenantMs: t0 + 21600000 + 1800000, cadence });
    expect(c.echue).to.equal(true);
    // Jamais moins de 60 s (R1-F64), même avec une configuration plus courte.
    c = cadenceMiseANiveau({ soumisMs: t0, derniereTentativeMs: t0 + 60000, maintenantMs: t0 + 60000, cadence: { ...cadence, first_after_s: 60, interval_s: 10 } });
    expect(c.prochaineMs).to.equal(t0 + 120000);
    // Au-delà de give_up_after_s : abandon (alerte ots_give_up), une tentative par jour, jamais de suppression.
    const tard = t0 + 1209600000;
    c = cadenceMiseANiveau({ soumisMs: t0, derniereTentativeMs: tard, maintenantMs: tard, cadence });
    expect(c.abandon).to.equal(true);
    expect(c.prochaineMs).to.equal(tard + 86400000);
    expect(() => cadenceMiseANiveau({ soumisMs: t0, derniereTentativeMs: t0 - 1, maintenantMs: t0, cadence })).to.throw(ErreurOts);
    expect(() => cadenceMiseANiveau({ soumisMs: t0, derniereTentativeMs: null, maintenantMs: t0, cadence: { ...cadence, interval_s: 0 } })).to.throw(ErreurOts);
    expect(() => cadenceMiseANiveau({ soumisMs: -1, derniereTentativeMs: null, maintenantMs: t0, cadence })).to.throw(ErreurOts);
  });
});

describe("ancrage lot B : transport par défaut (EX-6.2, EX-6.6 : HTTPS, Accept, corps borné)", () => {
  const fauxFetch = (repondre) => async (url, init) => repondre(url, init);

  it("https exigé (http admis vers 127.0.0.1 seulement), identifiants dans l'URL refusés, redirection refusée", async () => {
    const t = transportHttps({ fetch: fauxFetch(() => new Response(new Uint8Array(3), { status: 200 })) });
    for (const url of ["http://a.pool.opentimestamps.org/digest", "ftp://x.example/", "https://utilisateur:secret@x.example/digest", "pas une url"]) {
      let erreur = null;
      try {
        await t.post(url, new Uint8Array(32), { Accept: ACCEPT_OTS }, 1000);
      } catch (e) {
        erreur = e;
      }
      expect(erreur, url).to.be.instanceOf(ErreurTransport);
    }
    const local = await t.get("http://127.0.0.1:8080/timestamp/00", { Accept: ACCEPT_OTS }, 1000);
    expect(local.status).to.equal(200);
    expect(local.corps).to.have.length(3);
  });

  it("POST : méthode, Accept, corps de 32 octets sans Content-Length posé à la main (fetch le calcule ; un double Content-Length est refusé en 400) ; GET : en-têtes de réponse en minuscules ; redirect error", async () => {
    let vu = null;
    const t = transportHttps({ fetch: fauxFetch((url, init) => { vu = { url, init }; return new Response(new Uint8Array([1, 2]), { status: 200, headers: { "Cache-Control": "public, max-age=60" } }); }) });
    const r = await t.post("https://a.pool.opentimestamps.org/digest", new Uint8Array(32), { Accept: ACCEPT_OTS }, 2500);
    expect(vu.init.method).to.equal("POST");
    expect(vu.init.headers.Accept).to.equal(ACCEPT_OTS);
    expect(Object.keys(vu.init.headers).map((k) => k.toLowerCase())).to.not.include("content-length");
    expect(vu.init.body).to.have.length(32);
    expect(vu.init.redirect).to.equal("error");
    expect(vu.init.signal).to.be.instanceOf(AbortSignal);
    expect(r.entetes["cache-control"]).to.equal("public, max-age=60");
    expect(hex(r.corps)).to.equal("0x0102");
    const g = await t.get("https://alice.btc.calendar.opentimestamps.org/timestamp/00", { Accept: ACCEPT_OTS }, 2500);
    expect(vu.init.method).to.equal("GET");
    expect(g.status).to.equal(200);
  });

  it("corps de plus de 10 000 octets : reponse_trop_grande sans lecture au-delà ; 10 000 admis ; délai → delai ; panne réseau → reseau", async () => {
    const flux = (taille) => new ReadableStream({
      start(c) {
        let reste = taille;
        while (reste > 0) {
          const n = Math.min(4000, reste);
          c.enqueue(new Uint8Array(n));
          reste -= n;
        }
        c.close();
      },
    });
    const t = transportHttps({ fetch: fauxFetch(() => new Response(flux(10001), { status: 200 })) });
    let erreur = null;
    try {
      await t.get("https://x.example/timestamp/00", {}, 1000);
    } catch (e) {
      erreur = e;
    }
    expect(erreur).to.be.instanceOf(ErreurTransport).with.property("code", "reponse_trop_grande");
    const juste = await transportHttps({ fetch: fauxFetch(() => new Response(flux(10000), { status: 200 })) }).get("https://x.example/", {}, 1000);
    expect(juste.corps).to.have.length(10000);
    const delai = transportHttps({ fetch: fauxFetch(() => { const e = new Error("délai"); e.name = "TimeoutError"; throw e; }) });
    erreur = null;
    try {
      await delai.get("https://x.example/", {}, 1000);
    } catch (e) {
      erreur = e;
    }
    expect(erreur).to.have.property("code", "delai");
    const panne = transportHttps({ fetch: fauxFetch(() => { throw new TypeError("fetch failed"); }) });
    erreur = null;
    try {
      await panne.get("https://x.example/", {}, 1000);
    } catch (e) {
      erreur = e;
    }
    expect(erreur).to.have.property("code", "reseau");
    expect(() => transportHttps({ fetch: 42 })).to.throw(ErreurTransport);
  });
});

describe("ancrage lot B : fichier d'en-têtes (EX-6.8, AN-20 : bitcoin_rpc, fichier)", () => {
  const racines = new Map();
  const { document: operations, enTetes } = chaineRegtest({ debut: 0, nombre: 1030, racines });
  /** Nœud Bitcoin factice : getblockchaininfo, getblockhash, getblockheader <hash> false. */
  const noeudFactice = (surcharges = {}) => {
    const appels = [];
    return {
      appels,
      async appeler(methode, params) {
        appels.push([methode, params]);
        if (surcharges[methode]) return surcharges[methode](params);
        if (methode === "getblockchaininfo") return { chain: "regtest", blocks: 1029, headers: 1029 };
        if (methode === "getblockhash") return enTetes[params[0]].hashAffiche.slice(2);
        if (methode === "getblockheader") {
          const h = enTetes.find((x) => x.hashAffiche.slice(2) === params[0]);
          if (!h || params[1] !== false) throw new Error("getblockheader inattendu");
          return operations.headers[h.hauteur].slice(2);
        }
        throw new Error(`méthode inattendue ${methode}`);
      },
    };
  };

  it("bornes d'EX-6.8 : start_height = max(0, 2016 × (⌊h ÷ 2016⌋ − 1)), fin ≥ h' + 11", () => {
    expect(bornesFichierEntetes(1001, 1004)).to.deep.equal({ start_height: 0, end_height: 1015 });
    expect(bornesFichierEntetes(2016, 2016)).to.deep.equal({ start_height: 0, end_height: 2027 });
    expect(bornesFichierEntetes(4032, 4040)).to.deep.equal({ start_height: 2016, end_height: 4051 });
    expect(bornesFichierEntetes(840000, 840003)).to.deep.equal({ start_height: 836640, end_height: 840014 }); // ⌊840000 ÷ 2016⌋ = 416 → 2016 × 415
    expect(bornesFichierEntetes(358391, 358391)).to.deep.equal({ start_height: 2016 * 176, end_height: 358402 });
    expect(() => bornesFichierEntetes(10, 9)).to.throw(ErreurEntetes);
    expect(() => bornesFichierEntetes(-1, 9)).to.throw(ErreurEntetes);
    expect(() => bornesFichierEntetes(1.5, 9)).to.throw(ErreurEntetes);
    expect(() => bornesFichierEntetes(4294967290, 4294967290)).to.throw(ErreurEntetes);
  });

  it("source bitcoin_rpc : réseau confirmé, getblockhash puis getblockheader brut par hauteur, en-têtes contrôlés, document conforme au schéma", async () => {
    const rpc = noeudFactice();
    const source = { type: "bitcoin_rpc", network: "regtest", url: "http://127.0.0.1:18443", auth: null };
    const doc = await fichierEntetes({ source, hauteurs: [1001, 1004], rpc });
    expect(doc.version).to.equal(0);
    expect(doc.network).to.equal("regtest");
    expect(doc.start_height).to.equal(0);
    expect(doc.headers).to.have.length(1016);
    expect(doc.headers).to.deep.equal(operations.headers.slice(0, 1016));
    expect(doc.source).to.include("bitcoin_rpc");
    expect(doc.source).to.include("127.0.0.1");
    expect(doc.source).to.not.include("secret");
    expect(rpc.appels[0][0]).to.equal("getblockchaininfo");
    expect(rpc.appels.filter((a) => a[0] === "getblockhash")).to.have.length(1016);
    expect(rpc.appels.filter((a) => a[0] === "getblockheader").every((a) => a[1][1] === false)).to.equal(true);
    const lu = lireFichierEntetes(doc);
    expect(lu.end_height).to.equal(1015);
    expect(verifierOts({ octets: lireOctets(path.join(CT6_OTS, "preuves/periode-1.ots")), empreinteAttendue: "0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914", entetes: doc }).checks["O-5"]).to.equal("reussi");
  });

  it("source bitcoin_rpc refusée : autre réseau, hauteur inconnue du nœud, hachage annoncé différent de l'en-tête, hexadécimal mal formé, chaînage rompu, erreur RPC", async () => {
    const source = { type: "bitcoin_rpc", network: "regtest", url: "http://127.0.0.1:18443", auth: null };
    const refus = async (rpc, code) => {
      let erreur = null;
      try {
        await fichierEntetes({ source, hauteurs: [1001, 1004], rpc });
      } catch (e) {
        erreur = e;
      }
      expect(erreur, code).to.be.instanceOf(ErreurEntetes);
      expect(erreur.code).to.equal(code);
    };
    await refus(noeudFactice({ getblockchaininfo: () => ({ chain: "main", headers: 900000 }) }), "reseau");
    await refus(noeudFactice({ getblockchaininfo: () => ({ chain: "regtest", headers: 1010 }) }), "hauteur_indisponible");
    await refus(noeudFactice({ getblockheader: ([hash]) => (hash === enTetes[500].hashAffiche.slice(2) ? operations.headers[501].slice(2) : operations.headers[enTetes.findIndex((x) => x.hashAffiche.slice(2) === hash)].slice(2)) }), "rpc_incoherent");
    await refus(noeudFactice({ getblockheader: () => "zz" }), "rpc_en_tete");
    await refus(noeudFactice({ getblockhash: () => "0x12" }), "rpc_hash");
    const autre = chaineRegtest({ debut: 700, nombre: 2 });
    await refus(noeudFactice({ getblockhash: ([h]) => (h === 700 ? autre.enTetes[0].hashAffiche.slice(2) : enTetes[h].hashAffiche.slice(2)), getblockheader: ([hash]) => (hash === autre.enTetes[0].hashAffiche.slice(2) ? autre.document.headers[0].slice(2) : operations.headers[enTetes.findIndex((x) => x.hashAffiche.slice(2) === hash)].slice(2)) }), "chainage");
    await refus({ appeler: async () => { throw new ErreurEntetes("rpc_http", "503"); } }, "rpc_http");
    await refus(null, "rpc");
    await fichierEntetes({ source: { ...source, type: "autre" }, hauteurs: [1, 2], rpc: noeudFactice() }).then(() => expect.fail("refus attendu"), (e) => expect(e.code).to.equal("source"));
    await fichierEntetes({ source: { ...source, network: "testnet" }, hauteurs: [1, 2], rpc: noeudFactice() }).then(() => expect.fail("refus attendu"), (e) => expect(e.code).to.equal("reseau"));
  });

  it("source fichier : tranche extraite du fichier d'exploitation, contrôlée ; couverture insuffisante, autre réseau, fichier non conforme refusés", async () => {
    const source = { type: "fichier", network: "regtest", path: "/var/lib/noortrace/bitcoin/entetes-bitcoin.json" };
    const doc = await fichierEntetes({ source, hauteurs: [1001, 1004], fichier: utf8(JSON.stringify(operations)) });
    expect(doc.start_height).to.equal(0);
    expect(doc.headers).to.deep.equal(operations.headers.slice(0, 1016));
    expect(doc.source).to.include("fichier d'exploitation");
    const partiel = { ...operations, start_height: 500, headers: operations.headers.slice(500) };
    // h = 4500 : start_height = 2016 × (2 − 1) = 2016, fin 4511 ; le fichier d'exploitation couvre 2000 à 4599.
    const longue = chaineRegtest({ debut: 2000, nombre: 2600 }).document;
    const doc2 = await fichierEntetes({ source, hauteurs: [4500, 4500], fichier: longue });
    expect(doc2.start_height).to.equal(2016);
    expect(doc2.headers).to.have.length(4511 - 2016 + 1);
    expect(doc2.headers).to.deep.equal(longue.headers.slice(16, 16 + 2496));
    expect(verifierChaineEntetesOk(doc2)).to.equal(true);
    const refus = async (p, code) => {
      let erreur = null;
      try {
        await fichierEntetes({ source, hauteurs: [1001, 1004], ...p });
      } catch (e) {
        erreur = e;
      }
      expect(erreur, code).to.be.instanceOf(ErreurEntetes);
      expect(erreur.code).to.equal(code);
    };
    await refus({ fichier: partiel }, "couverture");
    await refus({ fichier: { ...operations, network: "mainnet" } }, "reseau");
    await refus({ fichier: { ...operations, headers: operations.headers.map((h, i) => (i === 3 ? h.slice(0, 20) + "00" + h.slice(22) : h)) } }, "chainage");
    await refus({ fichier: utf8("{") }, "json");
    await refus({ fichier: { ...operations, version: 1 } }, "schema");
    await refus({ fichier: null }, "fichier");
    await refus({ fichier: new Uint8Array(64 * 1024 * 1024 + 1) }, "taille");
  });

  it("client JSON-RPC par défaut : POST JSON, Authorization Basic depuis le secret résolu, réponse bornée, erreur RPC et HTTP", async () => {
    const appels = [];
    const transport = {
      async post(url, octets, entetes, delaiMs, options) {
        appels.push({ url, corps: JSON.parse(Buffer.from(octets).toString("utf8")), entetes, delaiMs, options });
        const { method } = appels[appels.length - 1].corps;
        if (method === "getblockchaininfo") return reponseHttp(200, JSON.stringify({ result: { chain: "regtest", headers: 10 }, error: null, id: appels[appels.length - 1].corps.id }));
        if (method === "erreur") return reponseHttp(200, JSON.stringify({ result: null, error: { code: -8, message: "x" }, id: 1 }));
        if (method === "http") return reponseHttp(401, "non autorise");
        return reponseHttp(200, "pas du json");
      },
    };
    const rpc = rpcBitcoinHttp({ url: "http://127.0.0.1:18443", auth: utf8("utilisateur:motdepasse"), transport });
    const info = await rpc.appeler("getblockchaininfo", []);
    expect(info).to.deep.equal({ chain: "regtest", headers: 10 });
    expect(appels[0].entetes.Authorization).to.equal(`Basic ${Buffer.from("utilisateur:motdepasse").toString("base64")}`);
    expect(appels[0].corps).to.include({ jsonrpc: "1.0", method: "getblockchaininfo" });
    expect(appels[0].options).to.deep.equal({ tailleMax: 1024 * 1024 });
    for (const [methode, code] of [["erreur", "rpc_erreur"], ["http", "rpc_http"], ["autre", "rpc_json"]]) {
      let erreur = null;
      try {
        await rpc.appeler(methode, []);
      } catch (e) {
        erreur = e;
      }
      expect(erreur, methode).to.be.instanceOf(ErreurEntetes).with.property("code", code);
      expect(erreur.message).to.not.include("motdepasse");
    }
    expect(() => rpcBitcoinHttp({ url: "ftp://x", auth: null, transport })).to.throw(ErreurEntetes);
    expect(() => rpcBitcoinHttp({ url: "http://127.0.0.1:1", auth: null, transport: {} })).to.throw(ErreurEntetes);
    const sansAuth = rpcBitcoinHttp({ url: "http://127.0.0.1:18443", auth: null, transport });
    await sansAuth.appeler("getblockchaininfo", []);
    expect(appels[appels.length - 1].entetes.Authorization).to.equal(undefined);
  });
});

describe("ancrage lot B : dépôt des preuves (EX-6.5, EX-5.14)", () => {
  let dir;
  beforeEach(() => {
    dir = repertoireTemporaire("ancrage-ots-depot-");
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });
  const minimal = lireOctets(path.join(CT5_OTS, "point-k2-minimal.ots"));
  const periode1 = lireOctets(path.join(CT6_OTS, "preuves/periode-1.ots"));

  it("noms d'EX-5.14 : <racine>/<org_id>/<journal_id>/ancres/periode-<dix chiffres>/ots/<objet>-<n>.ots ; objet manifeste ou point-<checkpointHash>", () => {
    expect(nomObjet({ type: "manifeste" })).to.equal("manifeste");
    expect(nomObjet({ type: "point", checkpointHash: K2 })).to.equal(`point-${K2.slice(2)}`);
    expect(() => nomObjet({ type: "point", checkpointHash: "0x00" })).to.throw(ErreurDepot);
    expect(() => nomObjet({ type: "autre" })).to.throw(ErreurDepot);
    expect(nomPeriode(1793710800)).to.equal("periode-1793710800");
    expect(nomPeriode(0)).to.equal("periode-0000000000");
    expect(() => nomPeriode(-1)).to.throw(ErreurDepot);
    expect(() => nomPeriode(10000000000)).to.throw(ErreurDepot);
    expect(() => nomPeriode(1.5)).to.throw(ErreurDepot);
    const depot = DepotOts.ouvrir({ racine: dir, orgId: ORG, journalId: JOURNAL });
    expect(depot.repertoirePeriode(1793710800)).to.equal(path.join(dir, ORG.slice(2), JOURNAL.slice(2), "ancres", "periode-1793710800"));
    expect(() => DepotOts.ouvrir({ racine: dir, orgId: "0x00", journalId: JOURNAL })).to.throw(ErreurDepot);
    expect(() => DepotOts.ouvrir({ racine: "", orgId: ORG, journalId: JOURNAL })).to.throw(ErreurDepot);
  });

  it("écriture en création exclusive, versions successives, dernière version rendue, fichier jamais réécrit, preuve illisible refusée", () => {
    const depot = DepotOts.ouvrir({ racine: dir, orgId: ORG, journalId: JOURNAL });
    const objet = nomObjet({ type: "point", checkpointHash: K2 });
    expect(depot.derniere({ periodStart: 1793710800, objet })).to.equal(null);
    expect(depot.versions({ periodStart: 1793710800, objet })).to.deep.equal([]);
    const v1 = depot.ecrire({ periodStart: 1793710800, objet, octets: minimal });
    expect(v1.version).to.equal(1);
    expect(v1.nom).to.equal(`${objet}-1.ots`);
    expect(v1.fichier).to.equal(`ots/${objet}-1.ots`);
    expect(v1.chemin).to.equal(path.join(dir, ORG.slice(2), JOURNAL.slice(2), "ancres", "periode-1793710800", "ots", `${objet}-1.ots`));
    expect(memesOctets(lireOctets(v1.chemin), minimal)).to.equal(true);
    const v2 = depot.ecrire({ periodStart: 1793710800, objet, octets: periode1 });
    expect(v2.version).to.equal(2);
    const d = depot.derniere({ periodStart: 1793710800, objet });
    expect(d.version).to.equal(2);
    expect(memesOctets(d.octets, periode1)).to.equal(true);
    expect(memesOctets(lireOctets(v1.chemin), minimal)).to.equal(true); // la version 1 n'a pas bougé
    expect(depot.versions({ periodStart: 1793710800, objet }).map((v) => v.version)).to.deep.equal([1, 2]);
    // Un fichier créé par un autre processus sous le nom de la version suivante : la création exclusive saute à la version d'après.
    fs.writeFileSync(path.join(path.dirname(v1.chemin), `${objet}-3.ots`), minimal);
    const v4 = depot.ecrire({ periodStart: 1793710800, objet, octets: minimal });
    expect(v4.version).to.equal(4);
    // Autre objet et autre période : indépendants.
    const m = depot.ecrire({ periodStart: 1793714400, objet: "manifeste", octets: periode1 });
    expect(m.version).to.equal(1);
    expect(m.chemin).to.include("periode-1793714400");
    expect(depot.derniere({ periodStart: 1793710800, objet: "manifeste" })).to.equal(null);
    // Refus : preuve illisible, vide, trop grande, nom d'objet refusé.
    expect(() => depot.ecrire({ periodStart: 1793710800, objet, octets: new Uint8Array([...minimal, 0]) })).to.throw(ErreurOts);
    expect(() => depot.ecrire({ periodStart: 1793710800, objet, octets: new Uint8Array(0) })).to.throw(ErreurDepot);
    expect(() => depot.ecrire({ periodStart: 1793710800, objet, octets: new Uint8Array(BORNES.TAILLE_FICHIER + 1) })).to.throw(ErreurDepot);
    expect(() => depot.ecrire({ periodStart: 1793710800, objet: "point-zz", octets: minimal })).to.throw(ErreurDepot);
    expect(() => depot.ecrire({ periodStart: 1793710800, objet: "../manifeste", octets: minimal })).to.throw(ErreurDepot);
    // Les fichiers du lot A dans le même répertoire ne sont pas touchés.
    const rfc = path.join(depot.repertoirePeriode(1793710800), "rfc3161");
    fs.mkdirSync(rfc);
    fs.writeFileSync(path.join(rfc, "manifeste-qtsa-principal-a.tsq"), "x");
    depot.ecrire({ periodStart: 1793710800, objet: "manifeste", octets: minimal });
    expect(fs.readdirSync(depot.repertoirePeriode(1793710800)).sort()).to.deep.equal(["ots", "rfc3161"]);
    expect(fs.readFileSync(path.join(rfc, "manifeste-qtsa-principal-a.tsq"), "utf8")).to.equal("x");
  });

  it("entetes-bitcoin.json : document contrôlé, écrit une fois (création exclusive), relu ; second écrit refusé (fichier_existant) ; document non conforme refusé", () => {
    const depot = DepotOts.ouvrir({ racine: dir, orgId: ORG, journalId: JOURNAL });
    const chaine = lireJson(path.join(CT6_OTS, "entetes/chaine.json"));
    expect(depot.lireEntetes(1793710800)).to.equal(null);
    const e = depot.ecrireEntetes({ periodStart: 1793710800, document: chaine });
    expect(e.fichier).to.equal("entetes-bitcoin.json");
    expect(e.chemin).to.equal(path.join(depot.repertoirePeriode(1793710800), "entetes-bitcoin.json"));
    expect(fs.readFileSync(e.chemin, "utf8")).to.equal(JSON.stringify(chaine, null, 2) + "\n");
    const relu = depot.lireEntetes(1793710800);
    expect(relu.start_height).to.equal(990);
    expect(relu.end_height).to.equal(1020);
    expect(N.egaliteJson(relu.document, chaine)).to.equal(true);
    expect(() => depot.ecrireEntetes({ periodStart: 1793710800, document: chaine })).to.throw(ErreurDepot).with.property("code", "fichier_existant");
    expect(() => depot.ecrireEntetes({ periodStart: 1793714400, document: { ...chaine, network: "testnet" } })).to.throw(ErreurEntetes);
    expect(depot.lireEntetes(1793714400)).to.equal(null);
  });
});

describe("ancrage lot B : essais hors ligne du dépôt avec le vérificateur Go de CT-6 et contre les calendriers publics", () => {
  let dir;
  before(() => {
    dir = repertoireTemporaire("ancrage-ots-essais-");
  });
  after(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("le fichier entetes-bitcoin.json écrit par DepotOts est lu par le binaire Go (--entetes-bitcoin) : même verdict et contrôle 5 réussi sur valide-point-de-controle-complet", function () {
    const bin = construireVerificateurGo(dir);
    if (!bin) return enAttente(this, "NOORTRACE_GO_BIN désigne un répertoire avec go1.27.3 et verificateur/scripts/construire.sh réussit");
    const dossier = path.join(CT6_DOSSIERS, "valide-point-de-controle-complet");
    const attendu = lireJson(path.join(dossier, "attendu.json"));
    const depot = DepotOts.ouvrir({ racine: dir, orgId: ORG, journalId: JOURNAL });
    const { chemin } = depot.ecrireEntetes({ periodStart: 1793710800, document: lireJson(path.resolve(dossier, attendu.bitcoin_headers)) });
    const r = spawnSync(bin, [dossier, "--ancres", path.resolve(dossier, attendu.anchors), "--entetes-bitcoin", chemin, "--json"], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
    expect(r.status, r.stderr).to.equal(attendu.exit_code);
    const rapport = JSON.parse(r.stdout);
    expect(rapport.verdict ?? rapport.valid).to.satisfy((v) => v === "valide" || v === true);
    const controle5 = (rapport.controls ?? rapport.controles ?? []).find((c) => String(c.id ?? c.number ?? c.numero) === "5");
    expect(controle5 && (controle5.status ?? controle5.statut)).to.equal("reussi");
  });

  it("soumission d'un engagement d'essai aux agrégateurs publics d'EX-6.2 puis mise à niveau immédiate (404 attendu : en attente ou non trouvé)", async function () {
    this.timeout(60000);
    if (process.env.NOORTRACE_RESEAU_PUBLIC !== "1") return enAttente(this, "NOORTRACE_RESEAU_PUBLIC=1 (réseau public joignable, soumission réelle d'un engagement d'essai)");
    const transport = transportHttps();
    const horloge = { murale: () => Date.now(), monotone: () => performance.now() };
    const empreinte = sha256Hex(utf8("noortrace/ancrage/lot-b/essai-reseau-public"));
    const nonce = new Uint8Array(randomBytes(16));
    const r = await soumettre({ empreinte, nonce, calendriers: AGREGATEURS, minReponses: 2, delaiMs: 10000, transport, horloge });
    console.log(`      soumission : engagement ${r.engagement}, ${r.valides} réponse(s) valable(s) sur ${AGREGATEURS.length}, écrire=${r.ecrire}, ${r.dureeMs} ms`);
    for (const x of r.reponses) console.log(`        ${x.calendrier} : statut ${x.status}, erreur ${x.erreur}, ${x.octets ? x.octets.length + " octets" : "-"}, attestations ${JSON.stringify(x.attestations)}, ${x.dureeMs} ms`);
    expect(r.ecrire, "au moins deux agrégateurs ont répondu").to.equal(true);
    expect(r.attestation).to.equal("en_attente");
    const v = verifierOts({ octets: r.octets, empreinteAttendue: empreinte });
    expect(v.checks["O-1"]).to.equal("reussi");
    expect(v.checks["O-3"]).to.equal("reussi");
    expect(v.checks["O-7"]).to.equal("non_execute");
    fs.writeFileSync(path.join(dir, "essai-public.ots"), r.octets);
    const m = await mettreANiveau({ preuve: r.octets, listeBlanche: LISTE_BLANCHE, transport, horloge, delaiMs: 10000 });
    for (const x of m.reponses) console.log(`      mise à niveau ${x.uri} : statut ${x.status}, résultat ${x.resultat}, ${x.dureeMs} ms`);
    for (const x of m.refus) console.log(`      refus ${x.uri} : ${x.motif}`);
    expect(m.nouvelle).to.equal(null);
    expect(m.etat).to.equal("en_attente");
    expect(m.reponses.length + m.refus.length).to.be.at.least(1);
    for (const x of m.reponses) expect(["en_attente", "non_trouve"], `${x.uri} ${x.resultat}`).to.include(x.resultat);
  });
});
