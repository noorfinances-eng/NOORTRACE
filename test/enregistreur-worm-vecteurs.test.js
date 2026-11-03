// Lot WORM (CT-2 §12.6, §12.11) : rejeu des vecteurs `spec/vecteurs/ct-2/worm/`
// (annexe B.9) contre leur attendu, par les modules de
// `paquets/enregistreur/src/worm/` écrits d'après le seul texte de CT-2 :
//   - worm/requetes.json : requêtes exactes d'EX-12.39 (cible, en-têtes triés,
//     corps, longueur, SHA-256, Content-MD5) ;
//   - worm/etats.json : verdict du contrôle du verrou d'EX-12.33 ;
//   - worm/perimetres.json : périmètre d'un gel d'EX-12.35 ;
//   - worm/gardes.json : règle de garde d'EX-12.38 et empreintes ;
//   - worm/levees.json : versions à lever et conservées d'EX-12.40 ;
// plus la clé de copie de l'exemple d'EX-12.29 sur le segment de
// `evenements/journal-demo`, les exemples calculés de 12.11 (liste des
// objets de 673 octets, enregistrement `pose` de 811 octets, empreintes de la
// suite, requêtes de l'exemple d'EX-12.39), les blocs annotés `worm/…` de
// CT-2 validés contre le schéma `worm-v0`, et la signature SigV4 de la
// couche d'accès S3 contre les exemples publiés par AWS (la signature est
// laissée à la couche d'accès, EX-12.39 ; le service S3 des tests ne la
// contrôle pas).

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import * as N from "@noortrace/noyau";
import {
  requeteOperation, formeRequete, controlerVerrou, calculerPerimetre, verifierGarde, versionsALever, empreinteEnregistrement,
  octetsEnregistrement, cleObjetWorm, signerSigv4, requeteS3Gel, requeteS3ConfigurationVerrou, requeteAzureGel, lireEcheance, echeanceMinimale,
  RegistreSchemasConfiguration,
} from "@noortrace/enregistreur";
import { VECTEURS_CT2, SPEC, blocApres, texteCT2 } from "./fixtures/enregistreur-coeur/outils.mjs";

const lire = (rel) => JSON.parse(fs.readFileSync(path.join(VECTEURS_CT2, rel), "utf8"));
const SCHEMA_WORM = JSON.parse(fs.readFileSync(path.join(SPEC, "schemas", "worm-v0.schema.json"), "utf8"));
const ID_WORM = SCHEMA_WORM.$id;
// Le schéma worm-v0 emploie `propertyNames` : validateur du paquet (src/schema.mjs).
const registre = new RegistreSchemasConfiguration();
registre.ajouter(SCHEMA_WORM);

describe("lot WORM : vecteurs spec/vecteurs/ct-2/worm (annexe B.9) rejoués contre leur attendu", function () {
  for (const f of ["worm/requetes.json", "worm/etats.json", "worm/perimetres.json", "worm/gardes.json", "worm/levees.json"]) {
    it(`${f} est valide pour le schéma worm-v0`, function () {
      const r = registre.valider(ID_WORM, lire(f));
      expect(r.valide, JSON.stringify(r.erreurs)).to.equal(true);
    });
  }

  describe("worm/requetes.json (EX-12.39)", function () {
    const d = lire("worm/requetes.json");
    for (const c of d.cases) {
      it(`${c.id} : requête exacte`, function () {
        expect(formeRequete(requeteOperation(c.input))).to.deep.equal(c.expected);
      });
    }
    it("les dix-sept cas obligatoires de B.9 sont présents", function () {
      expect(d.cases.map((c) => c.id)).to.include.members([
        "s3-gel-pose", "s3-gel-levee", "s3-lire-gel", "s3-etat-version", "s3-liste-premiere-page", "s3-liste-page-suivante",
        "s3-configuration-verrou-4018", "s3-lire-configuration", "s3-copie", "s3-copie-gel-a-l-ecriture", "s3-cle-a-encoder",
        "azure-gel-pose", "azure-gel-levee", "azure-etat-version", "gcs-gel-pose", "gcs-gel-levee", "gcs-etat-version",
      ]);
    });
  });

  describe("worm/etats.json (EX-12.33)", function () {
    for (const c of lire("worm/etats.json").cases) {
      it(`${c.id} : ${c.expected.verdict}${c.expected.reasons.length ? ` (${c.expected.reasons.join(", ")})` : ""}`, function () {
        const r = controlerVerrou({
          type: c.input.type,
          entetes: c.input.headers,
          json: c.input.json,
          mode: "compliance",
          echeanceMin: N.decoderHorodatage(c.input.expected_lock.retain_until_min),
          gelAttendu: c.input.expected_lock.hold === true,
        });
        expect(r).to.deep.equal(c.expected);
      });
    }
    it("retain_until_min = copied_at + retain_days × 86 400 s − 3 600 s (copie du 2026-11-10T11:00:05.412Z, 4 018 jours)", function () {
      expect(N.ecrireHorodatage(echeanceMinimale(N.decoderHorodatage("2026-11-10T11:00:05.412Z"), 4018))).to.equal("2037-11-10T10:00:05.412Z");
    });
  });

  describe("worm/perimetres.json (EX-12.35)", function () {
    for (const c of lire("worm/perimetres.json").cases) {
      it(`${c.id} : ${c.expected.count} objet(s), ${c.expected.anomalies.length} anomalie(s)`, function () {
        const i = c.input;
        const r = calculerPerimetre({ prefix: i.prefix, from: i.from, to: i.to, versions: i.versions, manifests: i.manifests, pieces: i.pieces, piecesPurgeables: i.pieces_purgeable === true });
        expect({ objects: r.objects, objects_sha256: r.objects_sha256, count: r.count, anomalies: r.anomalies }).to.deep.equal(c.expected);
      });
    }
  });

  describe("worm/gardes.json (EX-12.38)", function () {
    for (const c of lire("worm/gardes.json").cases) {
      it(`${c.id} : ${c.expected.valid ? "valide" : c.expected.errors.map((e) => `${e.code}@${e.n}`).join(", ")}`, function () {
        expect(verifierGarde(c.input.records)).to.deep.equal(c.expected);
      });
    }
  });

  describe("worm/levees.json (EX-12.40)", function () {
    for (const c of lire("worm/levees.json").cases) {
      it(`${c.id} : ${c.expected.lift.length} levée(s), ${c.expected.keep.length} conservée(s)`, function () {
        expect(versionsALever(c.input.objects, c.input.other_holds)).to.deep.equal(c.expected);
      });
    }
  });

  describe("exemples calculés de 12.6 et 12.11", function () {
    it("EX-12.29 : clé de copie du segment de evenements/journal-demo, sha256 et longueur de la ligne d'exemple", function () {
      const seg = fs.readFileSync(path.join(VECTEURS_CT2, "evenements", "journal-demo", "segment.ndjson"));
      const entete = JSON.parse(seg.toString("utf8").split("\n")[0]);
      const nom = `seg-${String(entete.first_seq).padStart(16, "0")}-${String(entete.epoch).padStart(20, "0")}.ndjson`;
      const ligne = JSON.parse(blocApres(texteCT2(), "<!-- schema: worm/ligne_copie -->").texte);
      expect(cleObjetWorm("journal-demo/", `segments/${nom}`)).to.equal(ligne.key);
      expect(N.sha256Hex(new Uint8Array(seg))).to.equal(ligne.sha256);
      expect(seg.length).to.equal(ligne.length);
      const r = registre.valider(`${ID_WORM}#/$defs/ligne_copie`, ligne);
      expect(r.valide, JSON.stringify(r.erreurs)).to.equal(true);
    });

    it("EX-12.35 : la liste des objets de l'exemple fait 673 octets, empreinte 0x0a24…083c", function () {
      const c = lire("worm/perimetres.json").cases.find((x) => x.id === "exemple-ex-12-35");
      const r = calculerPerimetre({ ...c.input, piecesPurgeables: false });
      expect(r.octets.length).to.equal(673);
      expect(r.objects_sha256).to.equal("0x0a24b97a14bf984ea5e8864e940ef45a5aad5eb8a1be9ec176affbe37a41083c");
    });

    it("EX-12.37 : enregistrements de l'exemple (pose : 811 octets, 0x4b88…eb1a ; suite imprimée en 12.11) ; blocs annotés valides", function () {
      const texte = texteCT2();
      const pose = JSON.parse(blocApres(texte, "<!-- schema: worm/enregistrement_gel -->").texte);
      expect(octetsEnregistrement(pose).length).to.equal(811);
      expect(empreinteEnregistrement(pose)).to.equal("0x4b88f9b3b618a27835988b98bb3e146e99177e370eb6cd3af219a7ba4634eb1a");
      const ligneLevee = texte.indexOf("<!-- schema: worm/enregistrement_gel -->") + 10;
      const levee = JSON.parse(blocApres(texte, "<!-- schema: worm/enregistrement_gel -->", texte.slice(0, ligneLevee).split("\n").length).texte);
      expect(levee.kind).to.equal("levee");
      expect(empreinteEnregistrement(levee)).to.equal("0x3543164e9f59156aeff461bcaf1334a5a678a98fa239f1162f6df970bf0e8482");
      for (const r of [pose, levee]) {
        const v = registre.valider(`${ID_WORM}#/$defs/enregistrement_gel`, r);
        expect(v.valide, JSON.stringify(v.erreurs)).to.equal(true);
      }
      const suite = lire("worm/gardes.json").cases.find((c) => c.id === "suite-valide");
      expect(suite.expected.record_sha256).to.deep.equal([
        "0x4b88f9b3b618a27835988b98bb3e146e99177e370eb6cd3af219a7ba4634eb1a",
        "0xb7d1457d111588b55d7d235d313a6d6aabb32ff6c82e75c82c351beed67cc744",
        "0xe9d87eb97309d57d4d2241d12b8d3debe220a9d782fd541b92299eecc30c3af7",
        "0x3543164e9f59156aeff461bcaf1334a5a678a98fa239f1162f6df970bf0e8482",
        "0x1fa25acb0f9f78211f2abdbbd2217233f4b134a69534e2975fc3828dfe892c05",
      ]);
      expect(verifierGarde(suite.input.records).record_sha256).to.deep.equal(suite.expected.record_sha256);
    });

    it("EX-12.39 : gel et levée du segment de l'exemple, rétention de 4 018 jours, cible Azure", function () {
      const k = "journal-demo/segments/seg-0000000000000001-00000000000000000001.ndjson";
      const g = requeteS3Gel(k, "3/L4kqtJl40Nr8X8gdRQBpUMLUo", true);
      expect(g.target).to.equal(`/${k}?legal-hold&versionId=3%2FL4kqtJl40Nr8X8gdRQBpUMLUo`);
      expect(g.headers).to.deep.equal([["Content-Length", "128"], ["Content-MD5", "PabGSMHFuZL/pMW6ZUAWbQ=="]]);
      expect(requeteS3Gel(k, "3/L4kqtJl40Nr8X8gdRQBpUMLUo", false).headers).to.deep.equal([["Content-Length", "129"], ["Content-MD5", "dUbasAU9gptvOryKx8wHGQ=="]]);
      expect(requeteS3ConfigurationVerrou(4018).headers).to.deep.equal([["Content-Length", "273"], ["Content-MD5", "MrEn2+g7Ii+EumTicoW97w=="]]);
      expect(requeteAzureGel("noortrace-demo-worm", k, "2026-11-10T11:00:05.1234567Z", true).target).to.equal(
        "/noortrace-demo-worm/journal-demo/segments/seg-0000000000000001-00000000000000000001.ndjson?comp=legalhold&versionid=2026-11-10T11%3A00%3A05.1234567Z",
      );
    });

    it("EX-12.33 : formes d'échéance admises (RFC 3339 avec ou sans fraction, Z ou décalage ; IMF-fixdate), les autres illisibles", function () {
      const ms = (t) => (lireEcheance(t) === null ? null : N.ecrireHorodatage(lireEcheance(t)));
      expect(ms("2037-11-10T11:00:05Z")).to.equal("2037-11-10T11:00:05.000Z");
      expect(ms("2037-11-10T11:00:05.5Z")).to.equal("2037-11-10T11:00:05.500Z");
      expect(ms("2037-11-10T09:00:05.1239999-02:00")).to.equal("2037-11-10T11:00:05.123Z");
      expect(ms("Tue, 10 Nov 2037 11:00:05 GMT")).to.equal("2037-11-10T11:00:05.000Z");
      for (const t of ["10/11/2037", "2037-11-10", "2037-02-30T00:00:00Z", "2037-11-10T24:00:00Z", "Tue, 10 Nov 2037 11:00:05 UTC", "", "2037-11-10T11:00:05+25:00"]) expect(ms(t), t).to.equal(null);
    });
  });

  describe("signature SigV4 de la couche d'accès S3 (exemples publiés par AWS)", function () {
    const id = { access_key_id: "AKIAIOSFODNN7EXAMPLE", secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", session_token: null };
    const base = { hote: "examplebucket.s3.amazonaws.com", region: "us-east-1", identifiants: id, instant: Date.UTC(2013, 4, 24), corps: null };
    it("GET Object avec Range", function () {
      const h = signerSigv4({ ...base, methode: "GET", chemin: "/test.txt", requete: "", entetes: [["Range", "bytes=0-9"]] });
      expect(h.authorization).to.match(/SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41$/);
    });
    it("GET Bucket Lifecycle (paramètre sans valeur) et List Objects (paramètres triés)", function () {
      expect(signerSigv4({ ...base, methode: "GET", chemin: "/", requete: "lifecycle", entetes: [] }).authorization).to.match(/Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543$/);
      expect(signerSigv4({ ...base, methode: "GET", chemin: "/", requete: "max-keys=2&prefix=J", entetes: [] }).authorization).to.match(/Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7$/);
    });
  });
});
