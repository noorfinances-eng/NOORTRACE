import { expect } from "chai";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { PROJECT_ROOT } from "../scripts/lib/noortrace.mjs";
import * as J from "../scripts/lib/journal.mjs";
import { ADR } from "../scripts/vecteurs/generer-ct3.mjs";
import { ORIGINE } from "../scripts/vecteurs/ct3/annuaire.mjs";
import * as N from "../scripts/vecteurs/ct3/notifications.mjs";
import { PREFIXE_SIGNATURE, signerNotification } from "@noortrace/approbation";

// Vecteurs des notifications de CT-3 (13.19 ; EX-13.40, EX-13.41), famille
// notifications/ du générateur scripts/vecteurs/generer-ct3.mjs : un document
// par nature, son corps envoyé au webhook (JCS, UTF-8) et l'en-tête
// NOORTRACE-Signature. La famille est reconstruite en mémoire par le
// générateur ; chaque attendu est recalculé ici par node:crypto, sans le
// générateur, puis confronté à la fonction de signature du service
// d'approbation (paquets/approbation), qui n'a pas servi à les produire.

const MD = fs.readFileSync(path.join(PROJECT_ROOT, "spec", "CT-3-approbations.md"), "utf8");
const FAMILLE = N.familleNotifications({ ADR, ORIGINE, MD });
const F = FAMILLE.fichier;
const hmac = (cle, ...morceaux) => {
  const h = crypto.createHmac("sha256", Buffer.from(cle, "ascii"));
  for (const m of morceaux) h.update(m);
  return h.digest("hex");
};
const SCHEMAS = ["evenement-v0", "ticket-v0", "annuaire-approbateurs-v0", "configuration-approbation-v0"].map((f) => JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, "spec", "schemas", `${f}.schema.json`), "utf8")));
const REGISTRE = J.registreSchemas(SCHEMAS);
const conforme = (document) => J.validerSchema(document, REGISTRE["https://noortrace.example/schemas/v0/configuration-approbation.schema.json"], { registre: REGISTRE, fragment: "#/$defs/notification" });

describe("CT-3 13.19 : vecteurs des notifications (EX-13.40, EX-13.41), famille notifications/ du générateur de ct-3", function () {
  it("constantes : préfixe « noortrace/notification/v0\\n » (26 octets), clé de l'exemple d'EX-13.41 (49 caractères), en-tête NOORTRACE-Signature ; le service signe avec le même préfixe", function () {
    expect(F.prefix).to.equal("noortrace/notification/v0\n");
    expect(Buffer.from(F.prefix, "utf8").length).to.equal(26);
    expect(F.prefix_hex).to.equal(Buffer.from(F.prefix, "utf8").toString("hex"));
    expect(F.key).to.have.length(49);
    expect(MD).to.include(`\`${F.key}\` (49 caractères`);
    expect(F.header).to.equal("NOORTRACE-Signature");
    expect(MD).to.include("`NOORTRACE-Signature: sha256=<s>`");
    expect(PREFIXE_SIGNATURE).to.equal(F.prefix);
  });

  it("EX-13.40 : un cas au moins par nature de la table ; chaque document est conforme à $defs/notification, a un identifiant distinct, et ne porte aucune identité de personne", function () {
    const [entete, ...natures] = [...MD.split("**EX-13.40**")[1].split("**EX-13.41**")[0].matchAll(/^\| `([a-z_]+)` \|/gm)].map((m) => m[1]);
    expect(entete).to.equal("kind");
    expect(natures).to.deep.equal(["ouverture", "escalade", "nouveau_gel", "seuil_inatteignable", "vote_inscrit", "operation_annuaire", "plafond_atteint"]);
    expect([...new Set(F.cases.map((c) => c.document.kind))]).to.have.members(natures);
    expect(new Set(F.cases.map((c) => c.document.id)).size).to.equal(F.cases.length);
    for (const c of F.cases) {
      expect(conforme(c.document), c.id).to.deep.equal([]);
      expect(c.document.id, c.id).to.equal(`ntf-${J.sha256(Buffer.from(`noortrace/vecteurs/ct3/notification/${c.id}`, "utf8")).slice(2, 34)}`);
      expect(Object.keys(c.document), c.id).to.deep.equal(["version", "id", "kind", "created_at", "recipients", "ticket", "tool", "deadline", "link", "details"]);
      expect(c.expected.body, c.id).to.not.match(/oidc |@|launched_by|session_identity|display_name|external_id|reason/);
      if (c.document.link !== null) expect(c.document.link.startsWith(`${ORIGINE}/`), c.id).to.equal(true);
    }
    // Les trois cibles d'une étape d'escalade (EX-7.13).
    expect(F.cases.filter((c) => c.document.kind === "escalade")).to.have.length(3);
    // Un document refusé par le schéma : destinataires vides (une notification sans destinataire n'est ni formée ni inscrite).
    const vide = structuredClone(F.cases[0].document);
    vide.recipients = { entries: [], roles: [] };
    expect(conforme(vide)).to.not.deep.equal([]);
  });

  it("EX-13.40 : le corps de chaque cas est le JCS de son document, en UTF-8 ; taille et SHA-256 publiés ; l'empreinte de D_A d'un vote porte U+2026, trois octets", function () {
    for (const c of F.cases) {
      const corps = J.octetsJCS(c.document);
      expect(corps.toString("utf8"), c.id).to.equal(c.expected.body);
      expect(JSON.parse(c.expected.body), c.id).to.deep.equal(c.document);
      expect(corps.length, c.id).to.equal(c.expected.body_size);
      expect("0x" + crypto.createHash("sha256").update(corps).digest("hex"), c.id).to.equal(c.expected.body_sha256);
    }
    const vote = F.cases.find((c) => c.id === "vote-inscrit");
    expect(vote.document.details.digest).to.match(/^[0-9a-f]{8}…[0-9a-f]{8}$/);
    expect(vote.expected.body_size).to.equal([...vote.expected.body].length + 2);
  });

  it("EX-13.41 : la signature de chaque cas est sha256= suivi de HMAC-SHA256(K, préfixe ‖ corps), recalculée par node:crypto et par signerNotification du service d'approbation", function () {
    for (const c of F.cases) {
      const corps = Buffer.from(c.expected.body, "utf8");
      const attendu = hmac(F.key, Buffer.from(F.prefix, "utf8"), corps);
      expect(c.expected.signature, c.id).to.equal(`sha256=${attendu}`);
      expect(c.expected.signature, c.id).to.match(/^sha256=[0-9a-f]{64}$/);
      expect(signerNotification(F.key, corps), c.id).to.equal(attendu);
    }
  });

  it("EX-13.41 : chaque corps de refusals porte une signature qui n'est pas celle que le relais recalcule ; la signature attendue est celle du service ; K est le secret dépouillé de ses espaces", function () {
    expect(F.refusals.map((r) => r.id)).to.deep.equal(["corps-altere", "prefixe-omis", "autre-cle", "cle-avec-saut-de-ligne"]);
    for (const r of F.refusals) {
      const corps = Buffer.from(r.body, "utf8");
      const recalculee = `sha256=${signerNotification(F.key, corps)}`;
      expect(r.expected, r.id).to.deep.equal({ accepted: false, signature: recalculee });
      expect(r.signature, r.id).to.match(/^sha256=[0-9a-f]{64}$/).and.to.not.equal(recalculee);
    }
    const base = F.cases.find((c) => c.id === "vote-inscrit");
    const corps = Buffer.from(base.expected.body, "utf8");
    const parId = Object.fromEntries(F.refusals.map((r) => [r.id, r]));
    expect(parId["prefixe-omis"].signature).to.equal(`sha256=${hmac(F.key, corps)}`);
    expect(parId["cle-avec-saut-de-ligne"].signature).to.equal(`sha256=${hmac(`${F.key}\n`, Buffer.from(F.prefix, "utf8"), corps)}`);
    expect(parId["corps-altere"].signature).to.equal(base.expected.signature);
    expect(parId["corps-altere"].body).to.not.equal(base.expected.body);
    expect(N.macNotification(`  ${F.key}\n`, corps)).to.equal(base.expected.signature.slice(7));
  });

  it("exemple du texte (EX-13.40, EX-13.41) : le document annoté donne un corps de 472 octets, celui que le texte imprime, et la signature imprimée, par le générateur, par node:crypto et par le service", function () {
    const document = JSON.parse(/<!-- exemple: configuration-approbation\/notification -->\n```json\n([\s\S]*?)\n```/.exec(MD)[1]);
    const corps = J.octetsJCS(document);
    expect(corps.length).to.equal(472);
    expect(MD).to.include(`\`\`\`text\n${corps.toString("utf8")}\n\`\`\``);
    const imprimee = /porte `NOORTRACE-Signature:\s+sha256=([0-9a-f]{64})`/.exec(MD)[1];
    expect(FAMILLE.exemple).to.deep.equal({ taille: 472, signature: `sha256=${imprimee}` });
    expect(hmac(F.key, Buffer.from(F.prefix, "utf8"), corps)).to.equal(imprimee);
    expect(signerNotification(F.key, corps)).to.equal(imprimee);
  });
});
