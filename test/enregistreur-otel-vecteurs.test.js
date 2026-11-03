// Rejeu des vecteurs `spec/vecteurs/ct-2/otel/` (CT-2 annexe B.8) par
// l'ingestion OpenTelemetry du démon (`src/otel/`), de bout en bout : la
// requête OTLP publiée (`requete.json`, `requete.pb` ou `requete.brut`, avec
// `requete-entetes.json`) est envoyée en HTTP au serveur OTLP réel
// (`ServeurOtel`) de l'ingestion ; la réponse (statut, type de contenu, corps
// JSON ou protobuf octet pour octet, `Retry-After`), la forme normalisée de
// chaque span (EX-6.31), les issues et raisons (EX-6.32 à EX-6.34), les pièces
// stockées (octets, sha256, longueur, `redacted`, `media_type`), les
// événements scellés (chaîne propre au cas : `seq_start`, `prev_hash` et `ts`
// de `source.json`, clé de test rec-test-01, hash et signature) et `lag_ms`
// sont comparés à `attendu.json`. Les tables de doublons et de recouvrement
// sont celles du cas (`seen`, `recorded`) ; la politique de rédaction est
// `pii-v1` (`redaction/politique-pii-v1.json`). Écrit d'après le seul texte
// de CT-2 6.8 et les données des vecteurs.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import http from "node:http";
import * as N from "@noortrace/noyau";
import {
  IngestionOtel, ServeurOtel, TableDoublons, RegistreRecouvrement, Redacteur, JournalExploitation, Metriques,
  envelopper, validerAvantSignature, decoderJson, decoderProtobuf, normaliser, jcsIntegral, retardReception,
} from "@noortrace/enregistreur";
import { VECTEURS_CT2, configurationExemple, graine } from "./fixtures/enregistreur-coeur/outils.mjs";

const R = path.join(VECTEURS_CT2, "otel");
// Les 48 cas de la famille (B.8), nommés : un cas ajouté ou retiré fait échouer le premier essai.
const CAS_NOMMES = [
  "otel/deflate-refuse",
  "otel/deflate-trop-grand",
  "otel/gzip-json",
  "otel/json-champ-inconnu",
  "otel/json-cle-double",
  "otel/json-contenu-chaine-non-json",
  "otel/json-contenu-hors-span",
  "otel/json-doublon-deja-vu",
  "otel/json-doublon-meme-requete",
  "otel/json-entier-fractionnaire",
  "otel/json-entiers-64-bits",
  "otel/json-enum-en-chaine",
  "otel/json-exemple-6-8-16",
  "otel/json-fin-nulle",
  "otel/json-identifiant-non-hexadecimal",
  "otel/json-identifiants-invalides",
  "otel/json-inference-erreur",
  "otel/json-inference-fournisseur",
  "otel/json-inference-gemini",
  "otel/json-inference-prompt-inline",
  "otel/json-inference-sans-contenu",
  "otel/json-lot-vide",
  "otel/json-non-analysable",
  "otel/json-operation-renommee",
  "otel/json-outil-erreur",
  "otel/json-outil-gabarit-effets",
  "otel/json-outil-mcp-tools-call",
  "otel/json-outil-nom-invalide",
  "otel/json-outil-sans-contenu",
  "otel/json-recouvrement-conserve",
  "otel/json-recouvrement-mcp",
  "otel/json-recouvrement-passerelle",
  "otel/json-retard",
  "otel/json-run-id-refuse",
  "otel/json-sorte-desactivee",
  "otel/json-spans-ignores",
  "otel/json-valeurs-diverses",
  "otel/non-authentifie",
  "otel/non-authentifie-type-texte",
  "otel/non-chemin-normalisable",
  "otel/pb-champ-double",
  "otel/pb-champ-inconnu",
  "otel/pb-exemple-6-8-16",
  "otel/pb-identifiants-invalides",
  "otel/pb-tronque",
  "otel/trop-grand",
  "otel/trop-grand-apres-decompression",
  "otel/type-de-contenu-inconnu",
];
const CAS = CAS_NOMMES.map((c) => c.slice("otel/".length));
const lireJson = (f) => JSON.parse(fs.readFileSync(f, "utf8"));
const ms = (t) => N.decoderHorodatage(t);
const JETON = "jeton-de-test-otel";
const PII = lireJson(path.join(VECTEURS_CT2, "redaction", "politique-pii-v1.json"));

/** Configuration d'un cas : l'exemple de 15.3, la source et les options de `source.json`. */
function configurationCas(src) {
  const c = configurationExemple();
  const o = src.options;
  c.limits.json_max_depth = o.json_max_depth;
  c.limits.json_max_members = o.json_max_members;
  c.model.prompt_in_request = o.prompt_in_request;
  c.model.prompt_system = o.prompt_system;
  c.policy.version = src.policy_version;
  c.policy.redaction = PII;
  c.policy.otel = { semconv: "1.41.1", sources: { [src.alias]: src.policy_source } };
  const hote = { ...c.otel.hosts[0], ...src.host, alias: src.alias, match: { static_token: c.otel.static_tokens[0].id } };
  c.otel = { ...c.otel, encodings: o.encodings, max_body_bytes: o.max_body_bytes, dedup_window_ms: o.dedup_window_ms, overlap_window_ms: o.overlap_window_ms, retry_after_s: o.retry_after_s, hosts: [hote] };
  return c;
}

function envoyer(adresse, entetes, corps) {
  return new Promise((resoudre, rejeter) => {
    const h = { "content-type": entetes["content-type"] };
    if (entetes["content-encoding"]) h["content-encoding"] = entetes["content-encoding"];
    if (entetes.token_id) h["x-noortrace-token"] = JETON;
    h["content-length"] = String(corps.length);
    const req = http.request({ host: adresse.address, port: adresse.port, method: entetes.method, path: entetes.path, headers: h }, (res) => {
      const m = [];
      res.on("data", (x) => m.push(x));
      res.on("end", () => resoudre({ statut: res.statusCode, entetes: res.headers, corps: Buffer.concat(m) }));
    });
    req.on("error", rejeter);
    req.end(corps);
  });
}

describe("enregistreur, ingestion OpenTelemetry : vecteurs otel/ (B.8) rejoués de bout en bout", function () {
  this.timeout(60000);
  const cle = graine("rec-test-01");

  it("la famille otel/ publiée est exactement celle des cas nommés", function () {
    expect(fs.readdirSync(R).sort()).to.deep.equal(CAS);
  });

  for (const cas of CAS) {
    it(`otel/${cas}`, async function () {
      const dir = path.join(R, cas);
      const src = lireJson(path.join(dir, "source.json"));
      const ent = lireJson(path.join(dir, "requete-entetes.json"));
      const att = lireJson(path.join(dir, "attendu.json"));
      const nomCorps = ["requete.json", "requete.pb", "requete.brut"].find((f) => fs.existsSync(path.join(dir, f)));
      const corps = fs.readFileSync(path.join(dir, nomCorps));
      const cfg = configurationCas(src);
      // Journal des vecteurs (celui de `journal-demo`, 6.8.16) : identifiants lus dans les événements publiés.
      const publie = att.spans.find((s) => s.event)?.event;
      if (publie) Object.assign(cfg.recorder, { org_id: publie.org_id, journal_id: publie.journal_id });
      const journal = new JournalExploitation({});
      const metriques = new Metriques();
      const redacteur = new Redacteur({ politique: PII, fils: 0, journal, metriques });
      const pieces = new Map();
      const scelles = [];
      let prev = src.chain.prev_hash;
      const tRecep = ms(src.t_reception);
      const doublons = new TableDoublons({ fenetreMs: cfg.otel.dedup_window_ms });
      for (const v of [...src.seen].sort((a, b) => ms(a.at) - ms(b.at))) doublons.inscrire(TableDoublons.cle(src.alias, v.trace_id, v.span_id), null, ms(v.at));
      const recouvrement = new RegistreRecouvrement({ fenetreMs: cfg.otel.overlap_window_ms });
      for (const r of src.recorded) {
        recouvrement.inscrire({ genre: r.kind === "appel_outil" ? "appel" : "echange", host_group: r.host_group, nom: r.seen_name ?? null, modele: r.model ?? null, t: ms(r.t), seq: r.seq });
      }
      const ingestion = new IngestionOtel({
        config: () => cfg,
        journal,
        metriques,
        redacteur,
        jetons: new Map([[cfg.otel.static_tokens[0].id, new Uint8Array(Buffer.from(JETON))]]),
        monotone: () => tRecep,
        ecrirePiece: async (p) => {
          pieces.set(p.sha256, p);
          return p.reference;
        },
        // Chaîne propre au cas (B.8) : seq_start, prev_hash, ts de l'écrivain.
        sceller: async (partiel) => {
          const k = scelles.length;
          const e = envelopper(partiel, { seq: src.chain.seq_start + k, ts: src.chain.ts[k], org_id: cfg.recorder.org_id, journal_id: cfg.recorder.journal_id, recorder_key_id: "rec-test-01", prev_hash: prev });
          e.hash = N.hacherEvenement(e);
          validerAvantSignature(e);
          e.sig = N.octetsVersHex(N.signerEd25519(cle, N.messageSignatureEvenement(e)));
          prev = e.hash;
          scelles.push(e);
          return e;
        },
        panne: () => null,
        version: () => ({ policy_version: src.policy_version, recorder: "0.1.0", nomRedaction: PII.name }),
        doublons,
        recouvrement,
      });
      const serveur = new ServeurOtel({ ingestion, config: () => cfg, journal });
      cfg.otel.listen = "127.0.0.1:0";
      await serveur.ecouter();
      let r;
      try {
        r = await envoyer(serveur.adresse(), ent, corps);
      } finally {
        await serveur.fermer();
      }
      // Réponse (EX-6.27).
      expect(r.statut, "statut").to.equal(att.status);
      expect(r.entetes["content-type"]).to.equal(att.response.content_type);
      expect(r.entetes["retry-after"] ?? null).to.equal(att.response.retry_after === null ? null : String(att.response.retry_after));
      if ("body_json" in att.response) expect(JSON.parse(r.corps.toString("utf8"))).to.deep.equal(att.response.body_json);
      else expect(r.corps.toString("hex")).to.equal(att.response.body_hex);
      if (att.status === 200) {
        if ("body_json" in att.response) expect(r.corps.toString("utf8"), "corps JSON octet pour octet").to.equal(JSON.stringify(att.response.body_json));
      }
      // Issues (EX-6.32 à EX-6.34) : ligne otel_request.
      const ligne = journal.lignes.map((l) => (typeof l === "string" ? JSON.parse(l) : l)).find((l) => l.event === "otel_request");
      expect(ligne.data.issues, "comptes").to.deep.equal(att.counts);
      expect(att.rejected_spans).to.equal(att.counts.rejete);
      // Forme normalisée (EX-6.31) : recalculée sur le corps décodé.
      if (att.spans.length) {
        const octets = ent["content-encoding"] === "gzip" ? new Uint8Array((await import("node:zlib")).gunzipSync(corps)) : new Uint8Array(corps);
        const bornes = { profondeurMax: cfg.limits.json_max_depth, membresMax: cfg.limits.json_max_members };
        const req = ent["content-type"] === "application/x-protobuf" ? decoderProtobuf(octets, bornes) : decoderJson(octets, bornes);
        const n = normaliser(req, { profondeurMax: bornes.profondeurMax });
        for (const s of att.spans) {
          const x = n.spans.find((y) => y.path.join() === s.path.join());
          expect(x, `span ${s.path}`).to.not.equal(undefined);
          if (s.normalized !== null) expect(jcsIntegral(x.N), `forme normalisée ${s.path}`).to.equal(jcsIntegral(s.normalized));
        }
      }
      // Événements et pièces des spans scellés, dans l'ordre (EX-6.35, EX-6.36, EX-6.38).
      const scelleAttendus = att.spans.filter((s) => s.issue === "scelle");
      expect(scelles.length, "événements scellés").to.equal(scelleAttendus.length);
      scelleAttendus.forEach((s, k) => {
        expect(scelles[k], `événement ${s.path}`).to.deep.equal(s.event);
        for (const [nom, ref] of Object.entries(s.pieces)) {
          if (ref === null) continue;
          const p = pieces.get(ref.sha256);
          expect(p, `pièce ${nom} de ${s.path}`).to.not.equal(undefined);
          expect(Buffer.from(p.octets).toString("utf8"), `octets ${nom}`).to.equal(ref.bytes);
          const { bytes: _b, ...r0 } = ref;
          expect(p.reference, `référence ${nom}`).to.deep.equal(r0);
        }
        expect(N.verifierSignatureEvenement(scelles[k], N.clePubliqueEd25519(cle)), "signature").to.equal(true);
      });
      for (const s of att.spans) {
        if (s.issue !== "scelle") {
          expect(s.event).to.equal(null);
          if (s.issue === "recouvrement") {
            const l = journal.lignes.map((x) => (typeof x === "string" ? JSON.parse(x) : x)).find((x) => x.event === "otel_span_overlap" && x.data.span_id === s.span_id);
            expect(l?.data.seq, "overlap_seq").to.equal(s.overlap_seq);
          }
        }
        // Retard de réception (EX-6.41) : ts moins la fin déclarée, null si la fin vaut 0.
        if (s.issue === "scelle") {
          expect(retardReception(s.event.ts, s.normalized.end_time_unix_nano), "lag_ms").to.equal(s.lag_ms);
        }
      }
      await redacteur.fermer();
    });
  }
});
