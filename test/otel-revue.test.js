// Revue de sécurité interne de l'étape 8 : correction de la bibliothèque
// de référence de CT-2 scripts/lib/otel.mjs, d'après le texte de CT-2 seul.
//
//    classification EX-6.32 : une opération au nom d'une propriété
//   d'Object.prototype n'a pas de sorte ; le span est ignoré, raison
//   operation_non_retenue, sorte null (jamais une fonction ni un objet).
import { expect } from "chai";
import * as OT from "../scripts/lib/otel.mjs";

const span = (op) => ({ attributes: OT.attributs([{ key: "gen_ai.operation.name", value: { type: "string", value: op } }]).valeur, trace_id: "ab".repeat(16), span_id: "cd".repeat(8), parent_span_id: null });
const SOURCE = { ingest: ["inference", "outil"] };

describe("revue de sécurité de l'étape 8 : otel.mjs, classification EX-6.32", function () {
  it("CT-2 EX-6.32 : gen_ai.operation.name prototypal (constructor, toString, valueOf, hasOwnProperty, __proto__) : ignore / operation_non_retenue, sorte null, comme embeddings", function () {
    expect(OT.classer(span("embeddings"), SOURCE)).to.deep.equal({ sorte: null, issue: "ignore", raison: "operation_non_retenue" });
    for (const op of ["constructor", "toString", "valueOf", "hasOwnProperty", "__proto__", "__defineGetter__"]) {
      const r = OT.classer(span(op), SOURCE);
      expect(r, op).to.deep.equal({ sorte: null, issue: "ignore", raison: "operation_non_retenue" });
      expect(r.sorte, op).to.equal(null);
    }
  });

  it("CT-2 EX-6.32 : les quatre opérations retenues gardent leur sorte et operation() lit une clé prototypale comme toute chaîne", function () {
    for (const [op, sorte] of [["chat", "inference"], ["generate_content", "inference"], ["text_completion", "inference"], ["execute_tool", "outil"]]) expect(OT.classer(span(op), SOURCE), op).to.deep.equal({ sorte, issue: "retenu", raison: null });
    expect(OT.operation(span("constructor"))).to.equal("constructor");
    expect(OT.classer(span("chat"), { ingest: ["outil"] })).to.deep.equal({ sorte: "inference", issue: "ignore", raison: "sorte_desactivee" });
  });
});
