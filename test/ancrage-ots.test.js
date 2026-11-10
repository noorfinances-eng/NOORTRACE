// Lot B du composant d'ancrage (CT-5 §6, client OpenTimestamps) : format des
// fichiers .ots (CT-6 §10.2, EX-10.2, EX-10.5 ; CT-5 EX-6.4, AN-18), fusion
// (EX-6.6), vérifications O-1 à O-5 et O-7 (CT-6 §10.4, CT-5 EX-6.9, AN-20),
// rejouées contre les vecteurs de `spec/vecteurs/ct-5/ots` (octet pour octet),
// de `spec/vecteurs/ct-6/ots` (attendu.json : statut de chaque O- pour chaque
// preuve) et des dossiers de `spec/vecteurs/ct-6/dossiers` (preuve.ots et
// anchors.ots.proof des parties points-de-controle.json), puis entrées
// hostiles (bornes de CT-6 §15.1) et confrontation par python-opentimestamps
// (CT-5 annexe A.6 ; en attente si l'interpréteur n'importe pas le paquet).

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import * as N from "@noortrace/noyau";
import {
  lireOts, ecrireOts, lireTimestamp, ecrireTimestamp, fusionnerOts, construirePreuve, attestationsEnAttente, engagementOctets,
  attestationBitcoin, attestationEnAttente, Noeud, OP, ErreurOts, BORNES, EN_TETE_MAGIQUE, encoderVaruint, encoderVarbytes,
  verifierOts, verifierChaineEntetes, etatPreuve, hauteursAttestees, executerArbre, STATUT, RAISON, VERIFICATIONS,
  lireFichierEntetes, SCHEMA_ENTETES_BITCOIN, setCompact, getCompact, decomposerEnTete, hachageEnEntier, RESEAUX, ErreurEntetes,
} from "@noortrace/ancrage/ots";
import {
  RACINE, CT5_OTS, CT6_OTS, CT6_DOSSIERS, lireOctets, lireJson, hex, sha256, sha256Hex, utf8, memesOctets, chaineRegtest,
  pythonOts, reserialiserPython, enAttente, muter, concat, repertoireTemporaire,
} from "./fixtures/ancrage-ots/outils.mjs";

const OTS_JSON = lireJson(path.join(CT5_OTS, "ots.json"));
const MISE_A_NIVEAU = lireJson(path.join(CT5_OTS, "mise-a-niveau.json"));
const ATTENDU_CT6 = lireJson(path.join(CT6_OTS, "attendu.json"));
const ALICE = "https://alice.btc.calendar.opentimestamps.org";
const BOB = "https://bob.btc.calendar.opentimestamps.org";
const K2 = "0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff";
const PERIODE_1 = "0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1";
// Forme embarquée d'EX-6.4 (CT-1 §11.2, base64 canonique).
const BASE64_MINIMAL =
  "AE9wZW5UaW1lc3RhbXBzAABQcm9vZgC/ieLohOiSlAEIao4DWrm5CTelsNQRGFZ8lS885JyJW4FjarcLUWJT5v/wEKEPDcyuYwonkd3jkktQc3kI/wCD3+MNLvkMji4taHR0cHM6Ly9hbGljZS5idGMuY2FsZW5kYXIub3BlbnRpbWVzdGFtcHMub3JnAIPf4w0u+QyOLCtodHRwczovL2JvYi5idGMuY2FsZW5kYXIub3BlbnRpbWVzdGFtcHMub3Jn";

/** Étiquette du nonce d'un cas de la famille ots (CT-5 A.2). */
function etiquetteNonce(cas) {
  if (cas.id === "point-k2-minimal") return "noortrace/vecteurs/v0/ct-5/ots/nonce/point-k2";
  const sujet = cas.id.startsWith("point") ? `point/${cas.digest.slice(2)}` : `periode/${cas.digest.slice(2)}`;
  return `noortrace/vecteurs/v0/ct-5/ots/nonce/journal-principal/${sujet}`;
}
function etiquetteCalendrier(cas, calendrier) {
  const sujet = cas.id.startsWith("point") ? `point/${cas.digest.slice(2)}` : `periode/${cas.digest.slice(2)}`;
  return `noortrace/vecteurs/v0/ct-5/ots/calendrier/${calendrier}/journal-principal/${sujet}`;
}
/** Construit la réponse (Timestamp) d'une branche décrite par ots.json. */
function brancheDepuisDescription(branche) {
  const racine = new Noeud();
  let noeud = racine;
  for (const op of branche.ops) {
    if (op.op === "prepend") noeud = noeud.operation(OP.PREPEND, N.hexVersOctets(op.argument));
    else if (op.op === "append") noeud = noeud.operation(OP.APPEND, N.hexVersOctets(op.argument));
    else if (op.op === "sha256") noeud = noeud.operation(OP.SHA256, null);
    else throw new Error(`opération inconnue ${op.op}`);
  }
  noeud.ajouterAttestation(attestationEnAttente(branche.uri));
  return racine;
}
/** Préfixe d'un fichier .ots (en-tête, version, 08, empreinte). */
const prefixeFichier = (empreinteHex) => concat(EN_TETE_MAGIQUE, Uint8Array.of(0x01, 0x08), N.hexVersOctets(empreinteHex, 32));
const ATT_ALICE = concat(Uint8Array.of(0x00), N.hexVersOctets("0x83dfe30d2ef90c8e"), encoderVarbytes(encoderVarbytes(utf8(ALICE))));
const attBitcoin = (h) => concat(Uint8Array.of(0x00), N.hexVersOctets("0x0588960d73d71901"), encoderVarbytes(encoderVaruint(h)));
const statutsAttendus = (checks) => Object.fromEntries(checks.filter((c) => c.id !== "O-6").map((c) => [c.id, c.status]));
const raisonsAttendues = (checks) => Object.fromEntries(checks.filter((c) => c.id !== "O-6" && c.status === "non_execute").map((c) => [c.id, c.reason]));

describe("ancrage lot B : famille ots de CT-5 (EX-6.2 à EX-6.7, AN-17, AN-18)", () => {
  for (const cas of OTS_JSON.cases) {
    const chemin = path.join(CT5_OTS, cas.file);
    const octets = lireOctets(chemin);

    it(`${cas.id} : taille, SHA-256, lecture, résérialisation identique (EX-6.4, O-1)`, () => {
      expect(octets.length).to.equal(cas.size);
      expect(sha256Hex(octets)).to.equal(cas.sha256);
      const lu = lireOts(octets);
      expect(lu.empreinteHex).to.equal(cas.digest);
      expect(memesOctets(ecrireOts(lu), octets)).to.equal(true);
    });

    it(`${cas.id} : nonce et engagement dérivés des constantes d'A.2 ; opérations de calendrier synthétiques`, () => {
      const nonce = sha256(utf8(etiquetteNonce(cas))).subarray(0, 16);
      expect(hex(nonce)).to.equal(cas.nonce);
      expect(hex(engagementOctets(cas.digest, nonce))).to.equal(cas.commitment);
      for (const branche of cas.branches) {
        if (branche.ops.length === 0) continue;
        expect(branche.ops[0].argument).to.equal(hex(sha256(utf8(etiquetteCalendrier(cas, branche.calendar))).subarray(0, 16)));
      }
    });

    it(`${cas.id} : reconstruit octet pour octet depuis l'empreinte, le nonce et les réponses des calendriers, quel que soit l'ordre d'arrivée (EX-6.4, AN-18)`, () => {
      const nonce = N.hexVersOctets(cas.nonce, 16);
      const reponses = [...cas.branches].reverse().map(brancheDepuisDescription);
      const p = construirePreuve({ empreinte: cas.digest, nonce, reponses });
      expect(hex(p.engagement)).to.equal(cas.commitment);
      expect(memesOctets(p.octets, octets)).to.equal(true);
      // Les réponses sous forme d'octets (Timestamp nu) donnent le même fichier.
      const p2 = construirePreuve({ empreinte: cas.digest, nonce, reponses: reponses.map(ecrireTimestamp) });
      expect(memesOctets(p2.octets, octets)).to.equal(true);
    });

    it(`${cas.id} : O-1 à O-3 réussies, O-7 non exécutée (partie_absente), O-4 et O-5 non exécutées, état en_attente`, () => {
      const v = verifierOts({ octets, empreinteAttendue: cas.digest });
      expect(v.checks["O-1"]).to.equal(cas.expected_checks["O-1"]);
      expect(v.checks["O-2"]).to.equal(cas.expected_checks["O-2"]);
      expect(v.checks["O-3"]).to.equal(cas.expected_checks["O-3"]);
      expect(v.checks["O-7"]).to.equal(cas.expected_checks["O-7"]);
      expect(v.raisons["O-7"]).to.equal(cas.expected_checks["O-7_reason"]);
      expect(v.checks["O-4"]).to.equal("non_execute");
      expect(v.raisons["O-4"]).to.equal("partie_absente");
      expect(v.checks["O-5"]).to.equal("non_execute");
      expect(v.raisons["O-5"]).to.equal("partie_absente");
      expect(v.etat).to.equal(cas.state);
      expect(etatPreuve(octets)).to.equal("en_attente");
      expect(v.attestations.map((a) => a.uri).sort()).to.deep.equal(cas.branches.map((b) => b.uri).sort());
      expect(v.avertissements).to.deep.equal(["AV-O-2"]);
      // O-2 en échec contre une autre empreinte, sans arrêter O-3 et O-7 (EX-10.6).
      const autre = verifierOts({ octets, empreinteAttendue: cas.digest === K2 ? PERIODE_1 : K2 });
      expect(autre.checks["O-2"]).to.equal("echoue");
      expect(autre.checks["O-3"]).to.equal("reussi");
      expect(autre.checks["O-7"]).to.equal("non_execute");
    });
  }

  it("point-k2-minimal : empreinte du fichier P_K ‖ C_K de K2 (EX-6.1), base64 canonique d'EX-6.4 (CT-1 §11.2)", () => {
    const octets = lireOctets(path.join(CT5_OTS, "point-k2-minimal.ots"));
    expect(N.encoderBase64(octets)).to.equal(BASE64_MINIMAL);
    expect(memesOctets(N.decoderBase64Canonique(BASE64_MINIMAL, BORNES.TAILLE_FICHIER), octets)).to.equal(true);
    // L'exemple d'EX-6.4 : deux attestations sœurs nues sous l'engagement, alice avant bob (tri par URI).
    const lu = lireOts(octets);
    const noeudE = lu.arbre.operations[0].noeud.operations[0].noeud;
    expect(lu.arbre.operations[0].code).to.equal(OP.APPEND);
    expect(hex(lu.arbre.operations[0].argument)).to.equal("0xa10f0dccae630a2791dde3924b507379");
    expect(noeudE.attestations.map((a) => a.uri)).to.have.members([ALICE, BOB]);
    const ordre = ecrireOts(lu);
    expect(Buffer.from(ordre).indexOf(Buffer.from(utf8(ALICE)))).to.be.lessThan(Buffer.from(ordre).indexOf(Buffer.from(utf8(BOB))));
  });

  it("mise-a-niveau.json : la réponse du calendrier remplace l'attestation en attente et la preuve fusionnée est periode-1.ots octet pour octet (EX-6.6, EX-6.7, AN-19)", () => {
    const avant = lireOctets(path.join(CT5_OTS, MISE_A_NIVEAU.before.file));
    const apres = lireOctets(path.join(CT5_OTS, MISE_A_NIVEAU.after.file));
    expect(avant.length).to.equal(MISE_A_NIVEAU.before.size);
    expect(sha256Hex(avant)).to.equal(MISE_A_NIVEAU.before.sha256);
    expect(etatPreuve(avant)).to.equal(MISE_A_NIVEAU.expected.state_before);
    const reponse = N.hexVersOctets(MISE_A_NIVEAU.response.der);
    expect(reponse.length).to.equal(MISE_A_NIVEAU.response.size);
    expect(sha256Hex(reponse)).to.equal(MISE_A_NIVEAU.response.sha256);
    const lu = lireOts(avant);
    const attentes = attestationsEnAttente(lu.arbre, lu.empreinte);
    expect(attentes).to.have.length(1);
    expect(attentes[0].attestation.uri).to.equal(MISE_A_NIVEAU.calendar);
    const fusion = fusionnerOts(avant, { engagement: attentes[0].message, chemin: reponse, uri: MISE_A_NIVEAU.calendar });
    expect(fusion.retirees).to.equal(1);
    expect(sha256Hex(fusion.octets)).to.equal(MISE_A_NIVEAU.expected.merged_sha256);
    expect(memesOctets(fusion.octets, apres)).to.equal(MISE_A_NIVEAU.expected.merged_equals_after);
    expect(etatPreuve(fusion.octets)).to.equal(MISE_A_NIVEAU.expected.state_after);
    expect(attestationsEnAttente(lireOts(fusion.octets).arbre, lu.empreinte)).to.have.length(0);
    // Fusion refusée pour un engagement qui n'est pas celui d'une attestation en attente.
    expect(() => fusionnerOts(avant, { engagement: lu.empreinte, chemin: reponse, uri: MISE_A_NIVEAU.calendar })).to.throw(ErreurOts).with.property("code", "engagement_inconnu");
    // Fusion refusée pour une autre URI au même engagement.
    expect(() => fusionnerOts(avant, { engagement: attentes[0].message, chemin: reponse, uri: BOB })).to.throw(ErreurOts).with.property("code", "engagement_inconnu");
    // La preuve d'origine n'est pas modifiée.
    expect(sha256Hex(avant)).to.equal(MISE_A_NIVEAU.before.sha256);
  });
});

describe("ancrage lot B : famille ots de CT-6 (attendu.json, O-1 à O-5 et O-7 ; CT-5 EX-6.9)", () => {
  const ancre = ATTENDU_CT6.bitcoin_anchor;

  it("attendu.json de CT-6 révision 0.5 : treize preuves et vingt et un cas, dont o1-attestation-en-double (O-1 echoue, raison doublon ; EX-10.2, EX-10.5)", () => {
    expect(ATTENDU_CT6.proofs).to.have.lengthOf(13);
    expect(ATTENDU_CT6.cases).to.have.lengthOf(21);
    const double = ATTENDU_CT6.proofs.find((p) => p.file === "preuves/o1-attestation-en-double.ots");
    expect(double.python_opentimestamps.parsing).to.equal("acceptee_en_ecrasant");
    const octets = lireOctets(path.join(CT6_OTS, double.file));
    expect(() => lireOts(octets)).to.throw(ErreurOts).with.property("code", "doublon");
    const v = verifierOts({ octets, empreinteAttendue: double.file_digest, entetes: null });
    expect(v.checks["O-1"]).to.equal("echoue");
    expect(v.details["O-1"]).to.match(/^doublon : attestation en double sous un même nœud/);
    expect(ATTENDU_CT6.cases.filter((c) => c.proof === double.file).map((c) => c.checks.find((x) => x.id === "O-1").status)).to.deep.equal(["echoue"]);
  });

  for (const preuve of ATTENDU_CT6.proofs) {
    it(`${preuve.file} : taille, SHA-256, lecture ${preuve.python_opentimestamps.parsing}, attestations et résultats des opérations`, () => {
      const octets = lireOctets(path.join(CT6_OTS, preuve.file));
      expect(octets.length).to.equal(preuve.size);
      expect(sha256Hex(octets)).to.equal(preuve.sha256);
      if (preuve.target === "O-1") {
        expect(() => lireOts(octets)).to.throw(ErreurOts);
        return;
      }
      const lu = lireOts(octets);
      expect(lu.empreinteHex).to.equal(preuve.file_digest);
      expect(memesOctets(ecrireOts(lu), octets)).to.equal(true);
      const { attestations } = executerArbre(lu.arbre, lu.empreinte);
      const miennes = attestations.map((a) => JSON.stringify({ kind: a.genre, height: a.hauteur, uri: a.uri, result: a.resultat === null ? null : hex(a.resultat) })).sort();
      const attendues = preuve.attestations.map((a) => JSON.stringify({ kind: a.kind, height: a.height, uri: a.uri, result: a.result })).sort();
      expect(miennes).to.deep.equal(attendues);
    });
  }

  for (const cas of ATTENDU_CT6.cases) {
    const titre = `${cas.proof} avec ${cas.headers ?? "sans en-têtes"}, ${cas.anchors ? "ancre bitcoin" : "sans ancre"}${cas.checkpoint ? " (K-9)" : ""} : ${Object.entries(statutsAttendus(cas.checks)).map(([k, v]) => `${k} ${v}`).join(", ")}`;
    it(titre, () => {
      const octets = lireOctets(path.join(CT6_OTS, cas.proof));
      const entetes = cas.headers ? lireJson(path.join(CT6_OTS, cas.headers)) : null;
      const v = verifierOts({ octets, empreinteAttendue: cas.dossier_period_hash, entetes, ancre: cas.anchors ? ancre : null });
      expect(v.checks).to.deep.equal(statutsAttendus(cas.checks));
      const raisons = Object.fromEntries(Object.entries(v.raisons).filter(([, r]) => r !== null));
      expect(raisons).to.deep.equal(raisonsAttendues(cas.checks));
      expect(v.avertissements).to.deep.equal([...cas.warnings].sort());
      if (cas.facts) {
        expect(v.retenue).to.deep.equal({ hauteur: cas.facts.retained_height, hash: cas.facts.block_hash });
        expect(v.attestations.map((a) => a.statut)).to.deep.equal(cas.facts.attestations.map((a) => a.status));
        expect(v.etat).to.equal("complete");
      }
    });
  }

  it("mode du composant (EX-6.9, sans point de contrôle de réviseur) : O-4 et O-5 contre les en-têtes de CT-5 ; réseau configuré contrôlé", () => {
    const octets = lireOctets(path.join(CT6_OTS, "preuves/periode-1.ots"));
    const chaine = lireJson(path.join(CT6_OTS, "entetes/chaine.json"));
    const v = verifierOts({ octets, empreinteAttendue: ATTENDU_CT6.proofs[0].file_digest, entetes: chaine, reseau: "regtest" });
    expect(v.checks).to.deep.equal({ "O-1": "reussi", "O-2": "reussi", "O-3": "reussi", "O-4": "reussi", "O-5": "reussi", "O-7": "reussi" });
    expect(v.retenue).to.deep.equal({ hauteur: 1001, hash: ATTENDU_CT6.headers["entetes/chaine.json"].hashes["1001"] });
    expect(v.avertissements).to.deep.equal(["AV-O-3"]);
    // Réseau configuré différent du fichier : O-5 en échec (règle 1).
    const mauvaisReseau = verifierOts({ octets, empreinteAttendue: ATTENDU_CT6.proofs[0].file_digest, entetes: chaine, reseau: "mainnet" });
    expect(mauvaisReseau.checks["O-5"]).to.equal("echoue");
    expect(mauvaisReseau.checks["O-4"]).to.equal("non_execute");
    expect(mauvaisReseau.raisons["O-4"]).to.equal("prerequis_en_echec");
    // Travail absent : O-5 en échec.
    const sansTravail = verifierOts({ octets, empreinteAttendue: ATTENDU_CT6.proofs[0].file_digest, entetes: lireJson(path.join(CT6_OTS, "entetes/chaine-sans-travail.json")) });
    expect(sansTravail.checks["O-5"]).to.equal("echoue");
    expect(sansTravail.details["O-5"]).to.include("règle 4");
    // Hauteur attestée hors du fichier : O-4 non exécutée (ancre_absente), O-5 réussie.
    const courte = verifierOts({ octets, empreinteAttendue: ATTENDU_CT6.proofs[0].file_digest, entetes: { ...chaine, start_height: 1002, headers: chaine.headers.slice(12) } });
    expect(courte.checks["O-5"]).to.equal("reussi");
    expect(courte.checks["O-4"]).to.equal("non_execute");
    expect(courte.raisons["O-4"]).to.equal("ancre_absente");
    // Mauvaise hauteur : O-4 en échec.
    const mauvaise = verifierOts({ octets: lireOctets(path.join(CT6_OTS, "preuves/o4-mauvaise-hauteur.ots")), empreinteAttendue: ATTENDU_CT6.proofs[0].file_digest, entetes: chaine });
    expect(mauvaise.checks["O-4"]).to.equal("echoue");
  });

  it("fichier d'en-têtes inexploitable (schéma, hexadécimal, réseau hors énumération, nombres hors bornes) : O-5 non exécutée, prerequis_en_echec", () => {
    const octets = lireOctets(path.join(CT6_OTS, "preuves/periode-1.ots"));
    const chaine = lireJson(path.join(CT6_OTS, "entetes/chaine.json"));
    const variantes = [
      { ...chaine, network: "testnet" },
      { ...chaine, start_height: -1 },
      { ...chaine, start_height: 4294967296 },
      { ...chaine, start_height: 4294967295 },
      { ...chaine, headers: [] },
      { ...chaine, headers: [chaine.headers[0].slice(0, 100)] },
      { ...chaine, headers: [chaine.headers[0].toUpperCase()] },
      { ...chaine, source: "" },
      { ...chaine, version: 1 },
      { ...chaine, extra: true },
      utf8("{\"version\":0"),
      Uint8Array.of(0xff, 0xfe, 0x7b),
    ];
    for (const entetes of variantes) {
      const v = verifierOts({ octets, empreinteAttendue: ATTENDU_CT6.proofs[0].file_digest, entetes });
      expect(v.checks["O-5"], JSON.stringify(entetes).slice(0, 60)).to.equal("non_execute");
      expect(v.raisons["O-5"]).to.equal("prerequis_en_echec");
      expect(v.checks["O-4"]).to.equal("non_execute");
      expect(v.raisons["O-4"]).to.equal("prerequis_en_echec");
    }
    expect(() => lireFichierEntetes({ ...chaine, network: "testnet" })).to.throw(ErreurEntetes).with.property("code", "schema");
  });
});

describe("ancrage lot B : dossiers de CT-6 (preuve.ots et anchors.ots.proof, CT-1 §11.2, CT-6 §10.9)", () => {
  const dossiers = fs.readdirSync(CT6_DOSSIERS).filter((d) => fs.existsSync(path.join(CT6_DOSSIERS, d, "attendu.json")));

  /** Statut attendu d'une vérification O- d'après attendu.json d'un dossier. */
  const attenduVerification = (attendu, id) => {
    if (attendu.failed_checks.includes(id)) return { statut: "echoue", raison: null };
    const ne = attendu.not_executed.find((x) => x.id === id);
    if (ne) return { statut: "non_execute", raison: ne.reason };
    return { statut: "reussi", raison: null };
  };
  const entreesDossier = (d) => {
    const attendu = lireJson(path.join(CT6_DOSSIERS, d, "attendu.json"));
    const entetes = attendu.bitcoin_headers ? lireJson(path.resolve(CT6_DOSSIERS, d, attendu.bitcoin_headers)) : null;
    const ancres = attendu.anchors ? lireJson(path.resolve(CT6_DOSSIERS, d, attendu.anchors)) : null;
    return { attendu, entetes, ancre: ancres ? ancres.bitcoin : null };
  };

  let comptePreuves = 0;
  let comptePoints = 0;
  for (const d of dossiers) {
    const index = lireJson(path.join(CT6_DOSSIERS, d, "dossier.json"));
    const partiePreuve = index.parts.find((p) => p.name === "preuve_ots");
    if (partiePreuve && partiePreuve.present && fs.existsSync(path.join(CT6_DOSSIERS, d, "preuve.ots"))) {
      comptePreuves += 1;
      it(`${d} : preuve.ots, statuts O-1 à O-5 et O-7 de l'attendu`, () => {
        const { attendu, entetes, ancre } = entreesDossier(d);
        const octets = lireOctets(path.join(CT6_DOSSIERS, d, "preuve.ots"));
        expect(sha256Hex(octets)).to.equal(partiePreuve.sha256);
        // O-2 a pour prérequis P-1 (periodHash recalculé) : quand l'attendu la dit non exécutée faute de prérequis, l'empreinte n'est pas fournie.
        const o2 = attenduVerification(attendu, "O-2");
        const manifeste = lireJson(path.join(CT6_DOSSIERS, d, "manifeste.json"));
        const empreinteAttendue = o2.statut === "non_execute" && o2.raison === "prerequis_en_echec" ? null : N.hacherManifeste(manifeste);
        const v = verifierOts({ octets, empreinteAttendue, entetes, ancre });
        for (const id of VERIFICATIONS) {
          const a = attenduVerification(attendu, id);
          expect(v.checks[id], `${d} ${id}`).to.equal(a.statut);
          if (a.statut === "non_execute") expect(v.raisons[id], `${d} ${id} raison`).to.equal(a.raison);
        }
      });
    }
    const partiePoints = index.parts.find((p) => p.name === "points_de_controle");
    if (partiePoints && partiePoints.present && fs.existsSync(path.join(CT6_DOSSIERS, d, "points-de-controle.json"))) {
      let points;
      try {
        points = lireJson(path.join(CT6_DOSSIERS, d, "points-de-controle.json"));
      } catch {
        points = null;
      }
      if (points && points.anchors && points.anchors.ots) {
        comptePoints += 1;
        it(`${d} : anchors.ots.proof (base64 canonique) vérifié avec checkpoint_hash, cohérent avec K-9 de l'attendu`, () => {
          const { attendu, entetes, ancre } = entreesDossier(d);
          const octets = N.decoderBase64Canonique(points.anchors.ots.proof, BORNES.TAILLE_FICHIER);
          expect(octets).to.not.equal(null);
          const v = verifierOts({ octets, empreinteAttendue: points.checkpoint_hash, entetes, ancre });
          const k9 = attenduVerification(attendu, "K-9");
          if (k9.statut === "echoue") {
            expect(Object.values(v.checks)).to.include("echoue");
          } else if (k9.statut === "non_execute" && k9.raison === "prerequis_en_echec") {
            // Prérequis de CT-1 (K-2 ou partie inexploitable) : hors de ce lot, la preuve est seulement lisible.
            expect(v.checks["O-1"]).to.equal("reussi");
          } else if (k9.statut === "non_execute") {
            expect(Object.values(v.checks)).to.not.include("echoue");
            expect(Object.values(v.raisons)).to.include(k9.raison);
          } else {
            expect(v.checks).to.deep.equal({ "O-1": "reussi", "O-2": "reussi", "O-3": "reussi", "O-4": "reussi", "O-5": "reussi", "O-7": "reussi" });
          }
        });
      }
    }
  }
  it("au moins trente dossiers portent preuve.ots et au moins huit une ancre ots de point", () => {
    expect(comptePreuves).to.be.at.least(30);
    expect(comptePoints).to.be.at.least(8);
  });
});

describe("ancrage lot B : lecture stricte et entrées hostiles (CT-6 EX-10.2, EX-10.5, §15.1)", () => {
  const minimal = lireOctets(path.join(CT5_OTS, "point-k2-minimal.ots"));
  const prefixe = prefixeFichier(K2);
  const refus = (octets, code) => {
    let erreur = null;
    try {
      lireOts(octets);
    } catch (e) {
      erreur = e;
    }
    expect(erreur, "une ErreurOts est attendue").to.be.instanceOf(ErreurOts);
    if (code) expect(erreur.code).to.equal(code);
    return erreur;
  };

  it("en-tête magique, version, opération de hachage du fichier", () => {
    refus(muter(minimal, 0, 0x01), "en_tete");
    refus(muter(minimal, 30, 0x95), "en_tete");
    refus(muter(minimal, 31, 0x02), "version");
    refus(muter(minimal, 31, 0x00), "version");
    refus(muter(minimal, 32, 0x02), "operation_fichier");
    refus(muter(minimal, 32, 0x67), "operation_fichier");
  });

  it("toute troncature d'un fichier valable est refusée comme fichier tronqué ou ff sans branche, jamais autrement", () => {
    for (let n = 0; n < minimal.length; n += 1) {
      const e = refus(minimal.subarray(0, n));
      expect(["tronque", "branche"]).to.include(e.code);
    }
  });

  it("octets après l'arbre (O-1, R2-F67) ; ff sans branche ; ff ff", () => {
    refus(concat(minimal, Uint8Array.of(0x00)), "octets_en_trop");
    refus(concat(prefixe, Uint8Array.of(0xff), ATT_ALICE, Uint8Array.of(0xff)), "tronque");
    refus(concat(prefixe, Uint8Array.of(0xff, 0xff), ATT_ALICE, ATT_ALICE), "branche");
  });

  it("étiquette d'opération inconnue (R2-F15) ; opérations hors profil reconnues et conservées", () => {
    refus(concat(prefixe, Uint8Array.of(0x05), ATT_ALICE), "operation_inconnue");
    refus(concat(prefixe, Uint8Array.of(0x09), ATT_ALICE), "operation_inconnue");
    for (const code of [0x02, 0x03, 0x67, 0xf2, 0xf3]) {
      const octets = concat(prefixe, Uint8Array.of(code), ATT_ALICE);
      const lu = lireOts(octets);
      expect(lu.arbre.operations[0].code).to.equal(code);
      expect(memesOctets(ecrireOts(lu), octets)).to.equal(true);
      const v = verifierOts({ octets, empreinteAttendue: K2 });
      expect(v.checks["O-3"]).to.equal("reussi");
      expect(v.attestations[0].chemin).to.equal("hors_profil");
      expect(v.attestations[0].raison).to.equal("hors_perimetre_version");
      expect(v.avertissements).to.deep.equal(["AV-O-2"]);
    }
  });

  it("varuint : forme non minimale refusée, plus de 9 octets refusé, 9 octets admis pour une charge inconnue", () => {
    // Longueur de charge d'attestation écrite 2e 00 au lieu de 2e (groupe final nul).
    const nonMinimal = concat(prefixe, Uint8Array.of(0x00), N.hexVersOctets("0x83dfe30d2ef90c8e"), Uint8Array.of(0xae, 0x00), encoderVarbytes(utf8(ALICE)));
    refus(nonMinimal, "varuint_non_minimal");
    const dixOctets = concat(prefixe, Uint8Array.of(0x00), N.hexVersOctets("0x0588960d73d71901"), Uint8Array.of(0x0a), Uint8Array.of(0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01));
    refus(dixOctets, "varuint_trop_long");
    // Argument d'opération : longueur 81 00 (non minimale) refusée.
    refus(concat(prefixe, Uint8Array.of(0xf0, 0x81, 0x00), new Uint8Array(1), ATT_ALICE), "varuint_non_minimal");
    expect(encoderVaruint(0)).to.deep.equal(Uint8Array.of(0));
    expect(encoderVaruint(1001)).to.deep.equal(Uint8Array.of(0xe9, 0x07));
    expect(encoderVaruint(2n ** 63n - 1n)).to.have.length(9);
    expect(() => encoderVaruint(2n ** 63n)).to.throw(ErreurOts);
  });

  it("argument d'opération : 0 octet et 4097 octets refusés, 1 et 4096 admis (R2-F13)", () => {
    refus(concat(prefixe, Uint8Array.of(0xf0, 0x00), ATT_ALICE), "varbytes_longueur");
    refus(concat(prefixe, Uint8Array.of(0xf0), encoderVarbytes(new Uint8Array(4097)), ATT_ALICE), "varbytes_longueur");
    const grand = concat(prefixe, Uint8Array.of(0xf0), encoderVarbytes(new Uint8Array(4096)), ATT_ALICE);
    expect(lireOts(grand).arbre.operations[0].argument).to.have.length(4096);
    expect(lireOts(concat(prefixe, Uint8Array.of(0xf1, 0x01, 0x00), ATT_ALICE)).arbre.operations[0].argument).to.have.length(1);
    // O-3 : un résultat de plus de 4096 octets fait échouer O-3 (le fichier reste lisible, O-1 réussie).
    const v = verifierOts({ octets: grand, empreinteAttendue: K2 });
    expect(v.checks["O-1"]).to.equal("reussi");
    expect(v.checks["O-3"]).to.equal("echoue");
    expect(v.attestations[0].chemin).to.equal("echec");
    expect(v.attestations[0].raison).to.equal("prerequis_en_echec");
  });

  it("attestation en attente : URI vide admise (R2-F20), plus de 1000 octets refusée, caractère hors alphabet refusé, UTF-8 mal formé refusé, charge non consommée exactement refusée", () => {
    const attUri = (uriOctets) => concat(Uint8Array.of(0x00), N.hexVersOctets("0x83dfe30d2ef90c8e"), encoderVarbytes(encoderVarbytes(uriOctets)));
    const vide = lireOts(concat(prefixe, attUri(new Uint8Array(0))));
    expect(vide.arbre.attestations[0].uri).to.equal("");
    expect(lireOts(concat(prefixe, attUri(utf8("a".repeat(1000))))).arbre.attestations[0].uri).to.have.length(1000);
    refus(concat(prefixe, attUri(utf8("a".repeat(1001)))), "varbytes_longueur");
    refus(concat(prefixe, attUri(utf8("https://alice.example/?x=1"))), "uri");
    refus(concat(prefixe, attUri(utf8("https://alice.exam ple"))), "uri");
    refus(concat(prefixe, attUri(Uint8Array.of(0x68, 0xc3, 0x28))), "uri");
    refus(concat(prefixe, attUri(Uint8Array.of(0xff, 0xfe))), "uri");
    // Charge avec un octet de plus que l'URI.
    const charge = concat(encoderVarbytes(utf8("https://a")), Uint8Array.of(0x00));
    refus(concat(prefixe, Uint8Array.of(0x00), N.hexVersOctets("0x83dfe30d2ef90c8e"), encoderVarbytes(charge)), "attestation");
  });

  it("attestation Bitcoin : hauteur 2^32 refusée, 2^32 − 1 admise, charge non consommée exactement refusée ; étiquette inconnue conservée et ignorée", () => {
    refus(concat(prefixe, attBitcoin(4294967296)), "hauteur");
    expect(lireOts(concat(prefixe, attBitcoin(4294967295))).arbre.attestations[0].hauteur).to.equal(4294967295);
    refus(concat(prefixe, Uint8Array.of(0x00), N.hexVersOctets("0x0588960d73d71901"), encoderVarbytes(Uint8Array.of(0xe9, 0x07, 0x00))), "attestation");
    const inconnue = concat(prefixe, Uint8Array.of(0xff), attBitcoin(1001), Uint8Array.of(0x00), N.hexVersOctets("0x06869a0d73d71901"), encoderVarbytes(utf8("litecoin?")));
    const lu = lireOts(inconnue);
    expect(lu.arbre.attestations.map((a) => a.genre)).to.have.members(["inconnue", "bitcoin"]);
    expect(memesOctets(ecrireOts(lu), inconnue)).to.equal(true);
    const v = verifierOts({ octets: inconnue, empreinteAttendue: K2 });
    expect(v.checks["O-7"]).to.equal("reussi");
    expect(v.avertissements).to.deep.equal(["AV-O-2"]);
    // Charge d'attestation de 8193 octets refusée, 8192 admise.
    refus(concat(prefixe, Uint8Array.of(0x00), N.hexVersOctets("0x06869a0d73d71901"), encoderVarbytes(new Uint8Array(8193))), "varbytes_longueur");
    expect(lireOts(concat(prefixe, Uint8Array.of(0x00), N.hexVersOctets("0x06869a0d73d71901"), encoderVarbytes(new Uint8Array(8192)))).arbre.attestations[0].charge).to.have.length(8192);
  });

  it("profondeur : 255 opérations sur un chemin admises, 256 refusées (R2-F18) ; même borne à l'écriture", () => {
    const chaine = (n) => concat(prefixe, ...Array.from({ length: n }, () => Uint8Array.of(0xf0, 0x01, 0x00)), ATT_ALICE);
    const lu = lireOts(chaine(255));
    expect(memesOctets(ecrireOts(lu), chaine(255))).to.equal(true);
    refus(chaine(256), "profondeur");
    const arbre = new Noeud();
    let n = arbre;
    for (let i = 0; i < 256; i += 1) n = n.operation(OP.APPEND, Uint8Array.of(0));
    n.ajouterAttestation(attestationEnAttente(ALICE));
    expect(() => ecrireOts({ empreinte: K2, arbre })).to.throw(ErreurOts).with.property("code", "profondeur");
  });

  it("taille : plus de 256 Kio refusé sans lecture ; réponse de calendrier de plus de 10 000 octets refusée", () => {
    const trop = new Uint8Array(BORNES.TAILLE_FICHIER + 1);
    trop.set(minimal, 0);
    refus(trop, "taille");
    expect(() => lireTimestamp(new Uint8Array(10001))).to.throw(ErreurOts).with.property("code", "taille");
    expect(() => lireTimestamp(new Uint8Array(0))).to.throw(ErreurOts).with.property("code", "tronque");
    expect(() => lireOts("texte")).to.throw(ErreurOts).with.property("code", "type");
  });

  it("doublons sous un même nœud (attestation, opération) refusés : la bibliothèque de référence ne les resérialise pas à l'identique", () => {
    refus(concat(prefixe, Uint8Array.of(0xff), ATT_ALICE, ATT_ALICE), "doublon");
    refus(concat(prefixe, Uint8Array.of(0xff, 0xf0, 0x01, 0x00), ATT_ALICE, Uint8Array.of(0xf0, 0x01, 0x00), ATT_ALICE), "doublon");
    refus(concat(prefixe, Uint8Array.of(0xff, 0x08), ATT_ALICE, Uint8Array.of(0x08), ATT_ALICE), "doublon");
  });

  it("nœud vide à l'écriture refusé ; empreinte et arbre contrôlés", () => {
    expect(() => ecrireOts({ empreinte: K2, arbre: new Noeud() })).to.throw(ErreurOts).with.property("code", "branche_vide");
    const arbre = new Noeud();
    arbre.operation(OP.SHA256, null);
    expect(() => ecrireOts({ empreinte: K2, arbre })).to.throw(ErreurOts).with.property("code", "branche_vide");
    expect(() => ecrireOts({ empreinte: "0x00", arbre })).to.throw();
    expect(() => construirePreuve({ empreinte: K2, nonce: new Uint8Array(15), reponses: [] })).to.throw(ErreurOts).with.property("code", "nonce");
    expect(() => construirePreuve({ empreinte: K2, nonce: new Uint8Array(16), reponses: [] })).to.throw(ErreurOts).with.property("code", "reponses");
    expect(() => attestationBitcoin(-1)).to.throw(ErreurOts);
    expect(() => attestationEnAttente("https://a b")).to.throw(ErreurOts);
  });

  it("ordre de sérialisation (EX-6.4) : attestations avant opérations, triées par étiquette puis hauteur ou URI, opérations par code puis argument, ff avant chaque branche sauf la dernière", () => {
    const arbre = new Noeud();
    arbre.operation(OP.PREPEND, Uint8Array.of(0x02)).ajouterAttestation(attestationEnAttente(BOB));
    arbre.operation(OP.APPEND, Uint8Array.of(0x01, 0x02)).ajouterAttestation(attestationEnAttente(BOB));
    arbre.operation(OP.APPEND, Uint8Array.of(0x01)).ajouterAttestation(attestationEnAttente(BOB));
    arbre.ajouterAttestation(attestationEnAttente(BOB));
    arbre.ajouterAttestation(attestationBitcoin(2000));
    arbre.ajouterAttestation(attestationEnAttente(ALICE));
    arbre.ajouterAttestation(attestationBitcoin(1000));
    arbre.operation(OP.SHA256, null).ajouterAttestation(attestationEnAttente(ALICE));
    const attBob = concat(N.hexVersOctets("0x83dfe30d2ef90c8e"), encoderVarbytes(encoderVarbytes(utf8(BOB))));
    const attAlice = concat(N.hexVersOctets("0x83dfe30d2ef90c8e"), encoderVarbytes(encoderVarbytes(utf8(ALICE))));
    const btc = (h) => concat(N.hexVersOctets("0x0588960d73d71901"), encoderVarbytes(encoderVaruint(h)));
    const attendu = concat(
      Uint8Array.of(0xff, 0x00), btc(1000),
      Uint8Array.of(0xff, 0x00), btc(2000),
      Uint8Array.of(0xff, 0x00), attAlice,
      Uint8Array.of(0xff, 0x00), attBob,
      Uint8Array.of(0xff, 0x08, 0x00), attAlice,
      Uint8Array.of(0xff, 0xf0, 0x01, 0x01, 0x00), attBob,
      Uint8Array.of(0xff, 0xf0, 0x02, 0x01, 0x02, 0x00), attBob,
      Uint8Array.of(0xf1, 0x01, 0x02, 0x00), attBob,
    );
    const octets = ecrireTimestamp(arbre);
    expect(hex(octets)).to.equal(hex(attendu));
    // Relecture puis réécriture : point fixe.
    expect(hex(ecrireTimestamp(lireTimestamp(octets))).toString()).to.equal(hex(octets));
    // Un ordre d'insertion différent donne les mêmes octets.
    const autre = new Noeud();
    autre.operation(OP.SHA256, null).ajouterAttestation(attestationEnAttente(ALICE));
    autre.ajouterAttestation(attestationBitcoin(1000));
    autre.ajouterAttestation(attestationEnAttente(ALICE));
    autre.ajouterAttestation(attestationBitcoin(2000));
    autre.ajouterAttestation(attestationEnAttente(BOB));
    autre.operation(OP.APPEND, Uint8Array.of(0x01)).ajouterAttestation(attestationEnAttente(BOB));
    autre.operation(OP.APPEND, Uint8Array.of(0x01, 0x02)).ajouterAttestation(attestationEnAttente(BOB));
    autre.operation(OP.PREPEND, Uint8Array.of(0x02)).ajouterAttestation(attestationEnAttente(BOB));
    expect(hex(ecrireTimestamp(autre))).to.equal(hex(attendu));
  });

  it("O-1 en échec : O-2, O-3, O-4, O-5 et O-7 non exécutées (prerequis_en_echec)", () => {
    const v = verifierOts({ octets: concat(minimal, Uint8Array.of(0x00)), empreinteAttendue: K2 });
    expect(v.checks["O-1"]).to.equal("echoue");
    for (const id of ["O-2", "O-3", "O-4", "O-5", "O-7"]) {
      expect(v.checks[id]).to.equal("non_execute");
      expect(v.raisons[id]).to.equal("prerequis_en_echec");
    }
    expect(v.etat).to.equal(null);
    expect(() => etatPreuve(concat(minimal, Uint8Array.of(0x00)))).to.throw(ErreurOts);
  });

  it("empreinte attendue absente ou mal formée : O-2 non exécutée (prerequis_en_echec), les autres s'exécutent", () => {
    for (const e of [null, undefined, "0x00", new Uint8Array(31), "6a8e"]) {
      const v = verifierOts({ octets: minimal, empreinteAttendue: e });
      expect(v.checks["O-2"]).to.equal("non_execute");
      expect(v.raisons["O-2"]).to.equal("prerequis_en_echec");
      expect(v.checks["O-3"]).to.equal("reussi");
    }
    expect(verifierOts({ octets: minimal, empreinteAttendue: N.hexVersOctets(K2) }).checks["O-2"]).to.equal("reussi");
  });
});

describe("ancrage lot B : chaîne d'en-têtes (CT-6 EX-10.3, EX-10.9 ; CT-5 EX-6.8, EX-6.9, AN-20)", () => {
  it("SCHEMA_ENTETES_BITCOIN est la copie exacte de spec/schemas/entetes-bitcoin-v0.schema.json", () => {
    const original = lireJson(path.join(RACINE, "spec", "schemas", "entetes-bitcoin-v0.schema.json"));
    expect(N.egaliteJson(SCHEMA_ENTETES_BITCOIN, original)).to.equal(true);
  });

  it("exemple de CT-6 §10.3 (bloc 358391 du réseau principal) : en-tête décomposé, preuve de travail satisfaite, SetCompact et GetCompact réciproques", () => {
    const exemple = {
      version: 0, network: "mainnet", start_height: 358391, source: "en-tête du bloc 358391, celui de l'exemple hello-world.txt.ots d'OpenTimestamps",
      headers: ["0x02000000b96394585a281b7e5f438fd1c9ed492645a1fd61cb3802040000000000000000007ee445d23ad061af4a36b809501fab1ac4f2d7e7a739817dd0cbb7ec661b8a1e376755f58616186272def6"],
    };
    const lu = lireFichierEntetes(exemple);
    const H = lu.enTetes[0];
    expect(H.version).to.equal(2);
    expect(hex(H.prev)).to.equal("0x" + exemple.headers[0].slice(2 + 8, 2 + 8 + 64));
    expect(hex(H.racine)).to.equal("0x" + exemple.headers[0].slice(2 + 72, 2 + 72 + 64));
    expect(H.nTime).to.be.greaterThan(1400000000).and.lessThan(1500000000); // 2015
    expect(H.nBits >>> 24).to.equal(0x18);
    const { cible, negatif, debordement } = setCompact(H.nBits);
    expect(negatif).to.equal(false);
    expect(debordement).to.equal(false);
    expect(cible <= RESEAUX.mainnet.powLimit).to.equal(true);
    expect(hachageEnEntier(H.hash) <= cible).to.equal(true);
    expect(getCompact(cible)).to.equal(H.nBits);
    expect(H.hashAffiche.startsWith("0x00000000000000")).to.equal(true);
    // Constantes de Bitcoin Core : 0x1d00ffff est la cible maximale du réseau principal.
    expect(setCompact(0x1d00ffff).cible).to.equal(0x00000000ffff0000000000000000000000000000000000000000000000000000n);
    expect(getCompact(RESEAUX.mainnet.powLimit)).to.equal(0x1d00ffff);
    expect(getCompact(setCompact(0x1b0404cb).cible)).to.equal(0x1b0404cb);
    expect(setCompact(0x207fffff).cible).to.equal(0x7fffffn << 232n);
    expect(getCompact(0x7fffffn << 232n)).to.equal(0x207fffff);
    expect(setCompact(0x01c00000).negatif).to.equal(true);
    expect(setCompact(0x01800000).negatif).to.equal(false); // mantisse nulle : jamais négatif (Bitcoin Core)
    expect(setCompact(0x23010000).debordement).to.equal(true);
    expect(setCompact(0x00000000).cible).to.equal(0n);
    // Un seul en-tête : chaînage et travail au-dessus de c = s, rien à contrôler, O-5 réussie en mode du composant.
    expect(verifierChaineEntetes(lu).statut).to.equal("reussi");
  });

  it("chaîne regtest synthétique : chaînage, travail, difficulté constante, médiane des heures ; chaque règle d'EX-10.9 éprouvée en échec", () => {
    const { document, enTetes } = chaineRegtest({ debut: 100, nombre: 30 });
    const lu = lireFichierEntetes(document);
    expect(verifierChaineEntetes(lu).statut).to.equal("reussi");
    expect(verifierChaineEntetes(lu, { ancre: { network: "regtest", checkpoint: { height: 110, hash: enTetes[10].hashAffiche }, min_confirmations: 6 } }).statut).to.equal("reussi");
    // Règle 1 : réseau.
    expect(verifierChaineEntetes(lu, { ancre: { network: "mainnet", checkpoint: { height: 110, hash: enTetes[10].hashAffiche } } }).detail).to.include("règle 1");
    expect(verifierChaineEntetes(lu, { reseau: "mainnet" }).statut).to.equal("echoue");
    // Règle 2 : chaînage rompu.
    const rompu = { ...document, headers: document.headers.map((h, i) => (i === 15 ? h.slice(0, 10) + (h[10] === "0" ? "1" : "0") + h.slice(11) : h)) };
    const r2 = verifierChaineEntetes(lireFichierEntetes(rompu));
    expect(r2.statut).to.equal("echoue");
    expect(r2.detail).to.include("règle 2");
    // Règle 3 : point de contrôle hors du fichier → non exécutée (ancre_absente) ; hachage différent → échec.
    const horsFichier = verifierChaineEntetes(lu, { ancre: { network: "regtest", checkpoint: { height: 99, hash: enTetes[0].hashAffiche } } });
    expect(horsFichier.statut).to.equal("non_execute");
    expect(horsFichier.raison).to.equal("ancre_absente");
    expect(verifierChaineEntetes(lu, { ancre: { network: "regtest", checkpoint: { height: 110, hash: enTetes[11].hashAffiche } } }).detail).to.include("règle 3");
    // Règle 4 : travail insuffisant (nonce qui ne satisfait pas la cible) au-dessus du point de contrôle, chaînage refait.
    const premiere = chaineRegtest({ debut: 100, nombre: 20 });
    const suite = chaineRegtest({ debut: 120, nombre: 10, prev0: premiere.enTetes[19].hash, nTime0: 1793880000 + 600 * 20, nBits: 0x207fffff });
    const sansTravail = { ...document, headers: [...premiere.document.headers.slice(0, 19), null, ...suite.document.headers] };
    {
      const base = N.hexVersOctets(premiere.document.headers[19], 80);
      let nonce = 0;
      for (;;) {
        base.set(Uint8Array.of(nonce & 0xff, (nonce >>> 8) & 0xff, (nonce >>> 16) & 0xff, nonce >>> 24), 76);
        const h = decomposerEnTete(base);
        if (hachageEnEntier(h.hash) > (0x7fffffn << 232n)) break;
        nonce += 1;
      }
      sansTravail.headers[19] = hex(base);
      // Recalcule le chaînage au-dessus de l'en-tête modifié.
      const rechainee = chaineRegtest({ debut: 120, nombre: 10, prev0: decomposerEnTete(base).hash, nTime0: 1793880000 + 600 * 20 });
      sansTravail.headers.splice(20, 10, ...rechainee.document.headers);
    }
    const r4 = verifierChaineEntetes(lireFichierEntetes(sansTravail));
    expect(r4.statut).to.equal("echoue");
    expect(r4.detail).to.include("règle 4");
    // Règle 5 : nBits différent de la constante regtest.
    const autreNBits = chaineRegtest({ debut: 100, nombre: 5, nBits: 0x207ffffe });
    const r5 = verifierChaineEntetes(lireFichierEntetes(autreNBits.document));
    expect(r5.statut).to.equal("echoue");
    expect(r5.detail).to.include("règle 5");
    // Règle 6 : heure qui ne dépasse pas la médiane des onze précédents.
    const heures = chaineRegtest({ debut: 100, nombre: 14 });
    const tardif = N.hexVersOctets(heures.document.headers[13], 80);
    tardif.set(Uint8Array.of(0x00, 0x00, 0x00, 0x00), 68);
    {
      let nonce = 0;
      for (;;) {
        tardif.set(Uint8Array.of(nonce & 0xff, (nonce >>> 8) & 0xff, (nonce >>> 16) & 0xff, nonce >>> 24), 76);
        if (hachageEnEntier(decomposerEnTete(tardif).hash) <= (0x7fffffn << 232n)) break;
        nonce += 1;
      }
    }
    const r6 = verifierChaineEntetes(lireFichierEntetes({ ...heures.document, headers: [...heures.document.headers.slice(0, 13), hex(tardif)] }));
    expect(r6.statut).to.equal("echoue");
    expect(r6.detail).to.include("règle 6");
  });

  it("règle 5 du réseau principal : réajustement toutes les 2016 hauteurs (arithmétique de Bitcoin Core), non applicable sans l'en-tête 2016 hauteurs plus bas", () => {
    // En-têtes non minés (la règle 4 échoue) : seule la présence ou l'absence de « règle 5 » dans le détail est observée.
    const fabriquer = (debut, nBitsListe, nTimeListe) => {
      const headers = [];
      let prev = new Uint8Array(32);
      for (let k = 0; k < nBitsListe.length; k += 1) {
        const o = new Uint8Array(80);
        o.set(prev, 4);
        const t = nTimeListe[k];
        o.set(Uint8Array.of(t & 0xff, (t >>> 8) & 0xff, (t >>> 16) & 0xff, t >>> 24), 68);
        const b = nBitsListe[k];
        o.set(Uint8Array.of(b & 0xff, (b >>> 8) & 0xff, (b >>> 16) & 0xff, b >>> 24), 72);
        prev = decomposerEnTete(o).hash;
        headers.push(hex(o));
      }
      return lireFichierEntetes({ version: 0, network: "mainnet", start_height: debut, source: "essai", headers });
    };
    // Premier réajustement du réseau principal (hauteur 32256) : Δ = nTime(32255) − nTime(30240) = 1 022 578 s,
    // 0x1d00ffff → 0x1d00d86a (valeur publique de la chaîne, indépendante de ce lot).
    expect(getCompact((setCompact(0x1d00ffff).cible * 1022578n) / 1209600n)).to.equal(0x1d00d86a);
    const debut = 2016 * 400;
    const n = 2017;
    const nBits = Array(n).fill(0x1b0404cb);
    const base = 1300000000;
    // Δ = nTime(i − 1) − nTime(i − 2016), i = debut + 2016 : les deux heures qui comptent sont celles des indices 0 et 2015.
    const heures = (delta) => Array.from({ length: n }, (_, k) => (k === 2015 ? base + delta : base + k));
    // Δ = 1 209 600 → cible inchangée.
    const inchange = verifierChaineEntetes(fabriquer(debut, nBits, heures(1209600)));
    expect(inchange.detail).to.not.include("règle 5");
    expect(inchange.detail).to.include("règle 4");
    // Blocs deux fois trop lents : la cible double (Δ = 2 419 200).
    const bons = [...nBits];
    bons[2016] = getCompact(setCompact(0x1b0404cb).cible * 2n);
    expect(verifierChaineEntetes(fabriquer(debut, bons, heures(2419200))).detail).to.not.include("règle 5");
    expect(verifierChaineEntetes(fabriquer(debut, nBits, heures(2419200))).detail).to.include("règle 5");
    // Δ ramené dans [302 400, 4 838 400] : dix fois trop lent → facteur 4 ; dix fois trop rapide → facteur 1/4.
    const plafonne = [...nBits];
    plafonne[2016] = getCompact(setCompact(0x1b0404cb).cible * 4n);
    expect(verifierChaineEntetes(fabriquer(debut, plafonne, heures(12096000))).detail).to.not.include("règle 5");
    const plancher = [...nBits];
    plancher[2016] = getCompact(setCompact(0x1b0404cb).cible / 4n);
    expect(verifierChaineEntetes(fabriquer(debut, plancher, heures(120960))).detail).to.not.include("règle 5");
    // La cible ne dépasse jamais powLimit.
    const limite = Array(n).fill(0x1d00ffff);
    expect(verifierChaineEntetes(fabriquer(debut, limite, heures(4838400))).detail).to.not.include("règle 5");
    // Hors réajustement, nBits doit être égal au précédent.
    const change = [...nBits];
    change[1000] = 0x1b0404cc;
    expect(verifierChaineEntetes(fabriquer(debut, change, heures(1209600))).detail).to.include("règle 5");
    // Réajustement sans l'en-tête 2016 hauteurs plus bas : règle non applicable → non exécutée (ancre_absente), sur une chaîne par ailleurs valable.
    const { document } = chaineRegtest({ debut: 2016 * 400 - 5, nombre: 10 });
    const faux = lireFichierEntetes({ ...document, network: "mainnet" });
    const na = verifierChaineEntetes(faux);
    expect(na.detail).to.include("règle 4"); // regtest ne satisfait pas powLimit du réseau principal
    const petit = fabriquer(2016 * 400 - 5, Array(10).fill(0x1b0404cb), Array.from({ length: 10 }, (_, k) => 1300000000 + 600 * k));
    const r = verifierChaineEntetes(petit);
    expect(r.detail).to.include("règle 5 : réajustement");
  });

  it("EX-6.9 : une preuve complète est vérifiée (O-4, O-5) contre des en-têtes dont la racine de Merkle porte le résultat de ses opérations", () => {
    const nonce = sha256(utf8("noortrace/ancrage/lot-b/nonce/essai")).subarray(0, 16);
    const branche = new Noeud();
    let n = branche.operation(OP.PREPEND, sha256(utf8("agregation")).subarray(0, 16)).operation(OP.SHA256, null);
    n = n.operation(OP.APPEND, sha256(utf8("transaction")).subarray(0, 32)).operation(OP.SHA256, null).operation(OP.SHA256, null);
    n.ajouterAttestation(attestationBitcoin(1003));
    const preuve = construirePreuve({ empreinte: K2, nonce, reponses: [branche] });
    const { attestations } = executerArbre(preuve.arbre, N.hexVersOctets(K2));
    expect(attestations).to.have.length(1);
    const racines = new Map([[1003, attestations[0].resultat]]);
    const { document, enTetes } = chaineRegtest({ debut: 990, nombre: 31, racines });
    const v = verifierOts({ octets: preuve.octets, empreinteAttendue: K2, entetes: document, reseau: "regtest" });
    expect(v.checks).to.deep.equal({ "O-1": "reussi", "O-2": "reussi", "O-3": "reussi", "O-4": "reussi", "O-5": "reussi", "O-7": "reussi" });
    expect(v.retenue).to.deep.equal({ hauteur: 1003, hash: enTetes[13].hashAffiche });
    expect(v.etat).to.equal("complete");
    expect(hauteursAttestees(preuve.arbre)).to.deep.equal({ min: 1003, max: 1003 });
    // Même preuve, en-têtes d'une autre chaîne : O-4 en échec (discordance consignée, preuve conservée).
    const autre = chaineRegtest({ debut: 990, nombre: 31 });
    const d = verifierOts({ octets: preuve.octets, empreinteAttendue: K2, entetes: autre.document });
    expect(d.checks["O-4"]).to.equal("echoue");
    expect(d.checks["O-5"]).to.equal("reussi");
    expect(d.attestations[0].statut).to.equal("echoue");
  });
});

describe("ancrage lot B : confrontation par python-opentimestamps 0.4.5 (CT-5 EX-6.3, annexe A.6)", () => {
  const condition = "un interpréteur Python qui importe « opentimestamps » (variable NOORTRACE_OTS_PYTHON, ou python3)";
  let py = null;
  let dir;
  before(() => {
    py = pythonOts();
    dir = repertoireTemporaire("ancrage-ots-python-");
  });
  after(() => {
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  const fichiersVecteurs = [
    ...OTS_JSON.cases.map((c) => path.join(CT5_OTS, c.file)),
    ...ATTENDU_CT6.proofs.filter((p) => p.python_opentimestamps.parsing === "acceptee").map((p) => path.join(CT6_OTS, p.file)),
  ];

  it(`chaque vecteur .ots accepté est relu et resérialisé à l'identique par la bibliothèque officielle, avec les mêmes attestations que ce lecteur`, function () {
    if (!py) return enAttente(this, condition);
    for (const f of fichiersVecteurs) {
      const octets = lireOctets(f);
      const r = reserialiserPython(py, f);
      expect(r.status, `${f}: ${r.erreur}`).to.equal(0);
      expect(r.description.identical, f).to.equal(true);
      expect(memesOctets(r.octets, octets), f).to.equal(true);
      const lu = lireOts(octets);
      expect(r.description.digest).to.equal(lu.empreinteHex.slice(2));
      const miennes = executerArbre(lu.arbre, lu.empreinte).attestations.map((a) => (a.genre === "bitcoin" ? `bitcoin:${a.hauteur}` : a.genre === "en_attente" ? `en_attente:${a.uri}` : "inconnue")).sort();
      const siennes = r.description.attestations.map((a) => (a.kind === "bitcoin" ? `bitcoin:${a.height}` : a.kind === "en_attente" ? `en_attente:${a.uri}` : "inconnue")).sort();
      expect(miennes).to.deep.equal(siennes);
    }
  });

  it("les vecteurs refusés par la bibliothèque officielle (octet en trop, résultat trop long) le sont ; ce lecteur refuse le premier (O-1) et lit le second (O-3 en échec, EX-10.7)", function () {
    if (!py) return enAttente(this, condition);
    for (const p of ATTENDU_CT6.proofs.filter((x) => x.python_opentimestamps.parsing === "refusee")) {
      const r = reserialiserPython(py, path.join(CT6_OTS, p.file));
      expect(r.status, p.file).to.not.equal(0);
    }
  });

  it("les preuves construites et fusionnées par ce lot (tri des attestations sœurs, branches de calendrier, arbre synthétique non trié, attestation inconnue) sont resérialisées à l'identique", function () {
    if (!py) return enAttente(this, condition);
    const nonce = N.hexVersOctets("0xa10f0dccae630a2791dde3924b507379", 16);
    const essais = [];
    const promesses = (uris) => uris.map((u) => { const n = new Noeud(); n.ajouterAttestation(attestationEnAttente(u)); return n; });
    essais.push(construirePreuve({ empreinte: K2, nonce, reponses: promesses([BOB, ALICE, "https://finney.calendar.eternitywall.com", "https://ots.btc.catallaxy.com"]) }).octets);
    const complexe = new Noeud();
    complexe.operation(OP.PREPEND, Uint8Array.of(0x02)).ajouterAttestation(attestationEnAttente(BOB));
    complexe.operation(OP.APPEND, Uint8Array.of(0x01, 0x02)).ajouterAttestation(attestationEnAttente(BOB));
    complexe.operation(OP.APPEND, Uint8Array.of(0x01)).ajouterAttestation(attestationBitcoin(1001));
    complexe.ajouterAttestation(attestationEnAttente(BOB));
    complexe.ajouterAttestation(attestationBitcoin(2000));
    complexe.ajouterAttestation(attestationEnAttente(ALICE));
    complexe.ajouterAttestation(attestationBitcoin(1000));
    complexe.ajouterAttestation({ genre: "inconnue", etiquette: N.hexVersOctets("0x06869a0d73d71901"), charge: Uint8Array.of(0xe9, 0x07), hauteur: null, uri: null });
    complexe.operation(OP.SHA256, null).ajouterAttestation(attestationEnAttente(""));
    essais.push(construirePreuve({ empreinte: K2, nonce, reponses: [complexe] }).octets);
    const avant = lireOctets(path.join(CT5_OTS, MISE_A_NIVEAU.before.file));
    const lu = lireOts(avant);
    const attentes = attestationsEnAttente(lu.arbre, lu.empreinte);
    essais.push(fusionnerOts(avant, { engagement: attentes[0].message, chemin: N.hexVersOctets(MISE_A_NIVEAU.response.der), uri: MISE_A_NIVEAU.calendar }).octets);
    essais.forEach((octets, i) => {
      const f = path.join(dir, `essai-${i}.ots`);
      fs.writeFileSync(f, octets);
      const r = reserialiserPython(py, f);
      expect(r.status, `essai ${i}: ${r.erreur}`).to.equal(0);
      expect(r.description.identical, `essai ${i}`).to.equal(true);
      expect(memesOctets(r.octets, octets), `essai ${i}`).to.equal(true);
    });
    // Un Timestamp nu (réponse de calendrier) est relu de même.
    const f = path.join(dir, "timestamp-nu.bin");
    fs.writeFileSync(f, ecrireTimestamp(complexe));
    const r = reserialiserPython(py, f, K2);
    expect(r.status, r.erreur).to.equal(0);
    expect(memesOctets(r.octets, ecrireTimestamp(complexe))).to.equal(true);
  });
});
