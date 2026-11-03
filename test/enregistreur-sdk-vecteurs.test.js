// Rejeu des vecteurs `spec/vecteurs/ct-2/pieces-modele/gemini-sdk-*` (CT-2
// annexe B.5, EX-6.8) de bout en bout : un agent déclare l'échange par le SDK
// JavaScript (`noortrace-sdk`, `session.echangeModele`) au point d'entrée SDK
// du démon (prise Unix, cœur, rédacteur `pii-v1` de l'exemple de 15.3) ; les
// pièces stockées (octets, sha256, longueur, `redacted`, `media_type`), la
// forme consolidée, `code.model`, `code.prompt_version`, `intent`,
// `is_error`, les membres retirés (`sdk_member_removed`) et la pièce de
// déclaration de source en `context[0]` (EX-7.7) sont comparés à
// `attendu.json`. Écrit d'après le seul texte de CT-2 et les données des
// vecteurs.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import { jcsIntegral, analyserJsonIntegral, pieceDeclarationSource } from "@noortrace/enregistreur";
import { VECTEURS_CT2 } from "./fixtures/enregistreur-coeur/outils.mjs";
import { demarrerDemonSdk } from "./fixtures/enregistreur-sdk/outils.mjs";

const CAS = ["pieces-modele/gemini-sdk-erreur-declaree", "pieces-modele/gemini-sdk-morceaux"].map((c) => c.slice("pieces-modele/".length));
const lire = (cas, f) => JSON.parse(fs.readFileSync(path.join(VECTEURS_CT2, "pieces-modele", cas, f), "utf8"));

describe("enregistreur, SDK : vecteurs pieces-modele/gemini-sdk-* (B.5, EX-6.8) rejoués de bout en bout", function () {
  this.timeout(60000);
  for (const cas of CAS) {
    it(`pieces-modele/${cas}`, async function () {
      const att = lire(cas, "attendu.json");
      const ech = lire(cas, "echange-sdk.json");
      const requete = lire(cas, "requete.json");
      const morceaux = lire(cas, "reponse-morceaux.json");
      const d = await demarrerDemonSdk({
        modifier: (c) => {
          c.model.prompt_in_request = att.options.prompt_in_request;
          c.model.prompt_system = att.options.prompt_system;
        },
      });
      try {
        const s = await d.client().ouvrir({});
        const r = await s.echangeModele({ format: ech.format, providerLabel: ech.provider_label, request: requete, response: morceaux, status: ech.status, durationMs: ech.duration_ms, isError: ech.is_error });
        await s.fermer();
        const e = (await d.evenements()).find((x) => x.seq === r.seq);
        expect(e.hash).to.equal(r.hash);
        expect(e.execution.tool).to.equal("noortrace.modele.echange");
        // Pièces (§8, EX-6.8) : octets et références.
        const lirePiece = async (sha) => Buffer.from(await d.coeur.pieces.lire(sha)).toString("utf8");
        const egal = async (ref, p) => {
          const { bytes, ...r0 } = p;
          expect(ref).to.deep.equal(r0);
          expect(await lirePiece(ref.sha256)).to.equal(bytes);
        };
        await egal(e.execution.arguments, att.pieces.request);
        await egal(e.execution.result, att.pieces.response);
        // Forme consolidée (EX-5.35, EX-6.8 point 2) : la pièce « réponse » non rédigée est son JCS intégral.
        if (!att.pieces.response.redacted) expect(jcsIntegral(analyserJsonIntegral(att.pieces.response.bytes))).to.equal(jcsIntegral(att.consolidated));
        // Pièce « prompt système » (8.2, EX-8.6) : stockée, `prompt_version` est son sha256.
        if (att.pieces.system_prompt) expect(await lirePiece(att.pieces.system_prompt.sha256)).to.equal(att.pieces.system_prompt.bytes);
        expect(e.code.prompt_version).to.equal(att.prompt_version);
        expect(e.code.model).to.equal(att.code_model);
        expect(e.intent).to.equal(att.intent);
        expect(e.execution.is_error).to.equal(att.is_error);
        expect(e.execution.duration_ms).to.equal(ech.duration_ms);
        // EX-6.8 point 3 : membres retirés, consignés.
        expect(d.lignes("sdk_member_removed").map((l) => l.data.member)).to.deep.equal(att.removed_members);
        // EX-7.7 : context[0] porte la pièce de déclaration de source du SDK, seule.
        const source = pieceDeclarationSource("sdk", "agent-local");
        expect(e.context).to.deep.equal([source.referenceContexte("autre")]);
        expect(await lirePiece(source.sha256)).to.equal('{"noortrace_capture":{"channel":"sdk","source":"agent-local"}}');
        expect(att.via).to.equal("sdk");
      } finally {
        await d.arreter();
      }
    });
  }
});
