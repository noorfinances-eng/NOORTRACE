// Rejeu de bout en bout des vecteurs du frontal modèle (CT-2 annexe B.5,
// B.6) par la passerelle du démon (@noortrace/enregistreur, lot « frontal
// modèle », src/modele/), écrite d'après le seul texte de la spécification :
//
//   - pieces-modele/* : chaque cas traverse la passerelle réelle (HTTP sur
//     127.0.0.1) vers un fournisseur simulé qui rend les octets publiés
//     (reponse.json, reponse.sse) avec le statut et le Content-Type publiés ;
//     on vérifie le refus (statut, corps, Content-Type, aucun relais, aucun
//     événement), la cible et le corps reçus par le fournisseur, les octets
//     rendus à l'hôte, la forme consolidée, les appels d'outils en clair, les
//     pièces stockées octet pour octet et les champs de l'événement scellé ;
//     les cas gemini-sdk-* (échange déclaré par le SDK, EX-6.8) sont rejoués
//     par les fonctions de dérivation du frontal (consolidation des morceaux,
//     pièces, extraction), l'entrée SDK étant au lot « SDK » ;
//   - evenements/journal-demo : échanges de seq 2, 4 et 8 (pièces, intent,
//     code, is_error de l'événement publié) et corrélation de seq 3 et 5
//     (EX-5.22) par le registre de corrélation.

import { expect } from "chai";
import fs from "node:fs";
import path from "node:path";
import {
  PasserelleModele, RegistreCorrelation, lireEvenements, jcsIntegral, consoliderMorceauxGemini, piecesRequete, pieceReponse, modeleDe,
  intentionDe, intentionBornee, appelsDemandes, Redacteur,
} from "@noortrace/enregistreur";
import { VECTEURS_CT2, repertoireTemporaire } from "./fixtures/enregistreur-coeur/outils.mjs";
import { configurationModele, valider, demarrerCoeur, JETON_MODELE, politiquePii } from "./fixtures/enregistreur-modele/outils.mjs";
import { FournisseurSimule } from "./fixtures/enregistreur-modele/fournisseur.mjs";

const lire = (rel) => fs.readFileSync(path.join(VECTEURS_CT2, rel));
const json = (rel) => JSON.parse(lire(rel).toString("utf8"));
const existe = (rel) => fs.existsSync(path.join(VECTEURS_CT2, rel));
const sansOctets = ({ bytes, ...r }) => (void bytes, r);

/** Égalité d'une référence et d'une pièce publiée (sans `bytes`). */
function egalRef(ref, publiee, quoi) {
  expect(ref, quoi).to.deep.equal(sansOctets(publiee));
}

describe("enregistreur, frontal modèle : vecteurs CT-2 rejoués de bout en bout", function () {
  this.timeout(120000);
  let dir;
  let fournisseur;
  let coeur;
  let secrets;
  let config;
  const passerelles = {};
  let observe;

  before(async function () {
    dir = repertoireTemporaire("noortrace-modele-vecteurs-");
    fournisseur = await new FournisseurSimule().demarrer();
    const c = configurationModele(dir, fournisseur.url);
    ({ config, secrets } = valider(c.config, c.env));
    ({ coeur } = await demarrerCoeur(config, secrets));
    for (const mode of ["reference", "inline"]) {
      const p = new PasserelleModele({
        coeur,
        secrets,
        config: { ...config, model: { ...config.model, prompt_in_request: mode } },
        observateur: { echange: (x) => observe.echanges.push(x), refus: (x) => observe.refus.push(x) },
      });
      await p.ecouter();
      passerelles[mode] = p;
    }
  });

  after(async function () {
    for (const p of Object.values(passerelles)) await p.arreter();
    await coeur?.arreter();
    await fournisseur?.arreter();
  });

  /** Envoie une requête à la passerelle et attend la clôture de l'échange. */
  async function envoyer(passerelle, cible, entetes, corps) {
    observe = { echanges: [], refus: [] };
    const r = await fetch(`http://127.0.0.1:${passerelle.adresse().port}${cible}`, { method: "POST", headers: entetes, body: corps });
    const octets = Buffer.from(await r.arrayBuffer());
    for (let i = 0; i < 200 && !observe.echanges.length && !observe.refus.length; i++) await new Promise((x) => setTimeout(x, 10));
    return { statut: r.status, contentType: r.headers.get("content-type"), octets, ...observe };
  }

  const cas = fs.readdirSync(path.join(VECTEURS_CT2, "pieces-modele")).sort();
  for (const nom of cas) {
    const R = `pieces-modele/${nom}`;
    const a = json(`${R}/attendu.json`);
    if (a.via === "sdk") continue;
    it(`${nom} (${a.note.split(" : ")[0].slice(0, 60)})`, async function () {
      const ligne = existe(`${R}/requete-ligne.json`) ? json(`${R}/requete-ligne.json`) : null;
      const cible = ligne ? ligne.target : a.route;
      const entetes = { ...json(`${R}/requete-entetes.json`) };
      if (!(ligne && ligne.host_known === false)) entetes["x-noortrace-token"] = JETON_MODELE;
      const corps = existe(`${R}/requete.json`) ? lire(`${R}/requete.json`) : lire(`${R}/requete.brut`);
      const flux = existe(`${R}/reponse.sse`);
      const reponse = a.refused ? null : lire(`${R}/${flux ? "reponse.sse" : "reponse.json"}`);
      const re = a.refused ? null : json(`${R}/reponse-entetes.json`);
      if (re) {
        const entetesAmont = { "content-type": re["content-type"] };
        if (re["request-id"]) entetesAmont["request-id"] = re["request-id"];
        fournisseur.prochaine({ statut: re.status, entetes: entetesAmont, morceaux: [reponse] });
      }
      const avant = fournisseur.requetes.length;
      const nAvant = (await lireEvenements(coeur.repertoire)).length;
      const r = await envoyer(passerelles[a.options.prompt_in_request], cible, entetes, corps);
      const evts = await lireEvenements(coeur.repertoire);

      if (a.refused) {
        fournisseur.scenarios.length = 0;
        expect(r.statut, "statut du refus").to.equal(a.refused.status);
        if (a.refused.body === null) expect(r.octets.length).to.equal(0);
        else expect(r.octets.toString("utf8"), "corps du refus, octets exacts").to.equal(JSON.stringify(a.refused.body));
        if ("content_type" in a.refused) expect(r.contentType).to.equal(a.refused.content_type);
        expect(fournisseur.requetes.length, "rien n'est relayé").to.equal(avant);
        expect(evts.length, "aucun événement").to.equal(nAvant);
        return;
      }
      // Relais : cible amont reconstruite, corps recopié, octets rendus à l'hôte.
      const recue = fournisseur.requetes[fournisseur.requetes.length - 1];
      expect(recue.cible).to.equal(a.upstream_target ?? a.route);
      expect(Buffer.compare(recue.brut, corps), "corps relayé = octets reçus").to.equal(0);
      expect(r.statut).to.equal(re.status);
      expect(Buffer.compare(r.octets, reponse), "réponse relayée octet pour octet").to.equal(0);
      // Échange scellé.
      expect(evts.length).to.equal(nAvant + 1);
      const e = evts[evts.length - 1];
      const x = r.echanges[0];
      expect(e.execution.tool).to.equal("noortrace.modele.echange");
      expect(e.execution.status).to.equal("executee");
      expect(e.policy.decision).to.equal("sans_objet");
      expect(e.context).to.deep.equal([]);
      expect(e.effects).to.deep.equal([]);
      egalRef(e.execution.arguments, a.pieces.request, "pièce requête");
      egalRef(e.execution.result, a.pieces.response, "pièce réponse");
      for (const [k, p] of Object.entries(a.pieces)) {
        if (!p) continue;
        const stockee = await coeur.pieces.lire(p.sha256);
        expect(Buffer.from(stockee).toString("utf8"), `pièce ${k} stockée`).to.equal(p.bytes);
      }
      expect(e.code.model).to.equal(a.code_model);
      expect(e.code.prompt_version).to.equal(a.prompt_version);
      if (a.pieces.system_prompt) expect(x.pieces.prompt.reference).to.deep.equal(sansOctets(a.pieces.system_prompt));
      else expect(x.pieces.prompt).to.equal(null);
      expect(e.intent).to.deep.equal(a.intent);
      if (a.pieces.intent) egalRef(e.intent, a.pieces.intent, "pièce intention");
      expect(e.execution.is_error).to.equal(a.is_error);
      expect(x.incomplet).to.equal(a.incomplete);
      const redige = [e.execution.arguments, e.execution.result, e.intent].some((v) => v && typeof v === "object" && v.redacted === true);
      expect(e.policy.redaction).to.equal(redige ? "pii-v1" : null);
      // Forme consolidée en clair et appels d'outils demandés (5.4, 5.5).
      if (flux && re.status < 400) expect(jcsIntegral(x.consolidee?.forme ?? null)).to.equal(jcsIntegral(a.consolidated));
      else expect(a.consolidated).to.equal(null);
      expect(x.appels.map((c) => ({ id: c.id, name: c.name, arguments: c.arguments }))).to.deep.equal(a.tool_calls);
    });
  }

  describe("gemini-sdk-* : dérivation de l'échange déclaré (EX-6.8 pas 2 à 5, EX-5.35)", function () {
    const redacteur = new Redacteur({ politique: politiquePii(), fils: 0 });
    for (const nom of cas.filter((n) => n.startsWith("gemini-sdk-"))) {
      it(nom, async function () {
        const R = `pieces-modele/${nom}`;
        const a = json(`${R}/attendu.json`);
        const sdk = json(`${R}/echange-sdk.json`);
        // EX-6.8 pas 3 (entrée du SDK, lot suivant) : membres propres au SDK retirés.
        const retires = [];
        const morceaux = json(`${R}/reponse-morceaux.json`).map((m) => {
          const c = { ...m };
          for (const k of ["sdkHttpResponse", "automaticFunctionCallingHistory", "parsed"]) if (k in c) (retires.push(k), delete c[k]);
          return c;
        });
        expect([...new Set(retires)]).to.deep.equal(a.removed_members);
        const cons = consoliderMorceauxGemini(morceaux);
        expect(jcsIntegral(cons.forme)).to.equal(jcsIntegral(a.consolidated));
        const pr = await piecesRequete({ format: "gemini", valeur: json(`${R}/requete.json`), prompt_in_request: a.options.prompt_in_request, prompt_system: a.options.prompt_system, redacteur });
        const rep = await pieceReponse({ format: "gemini", statut: sdk.status, contentType: null, corps: new Uint8Array(0), flux: true, consolidee: cons, redacteur });
        expect(pr.requete.reference).to.deep.equal(sansOctets(a.pieces.request));
        expect(rep.piece.reference).to.deep.equal(sansOctets(a.pieces.response));
        expect(pr.prompt?.sha256 ?? null).to.equal(a.prompt_version);
        expect(modeleDe({ format: "gemini", label: sdk.provider_label, reponseRedigee: rep.valeurRedigee, requeteRedigee: pr.requeteRedigee, attendue: pr.attendue, segment: null })).to.equal(a.code_model);
        expect(intentionBornee(intentionDe("gemini", rep.valeurRedigee), intentionDe("gemini", rep.formeClair)).intent).to.deep.equal(a.intent);
        expect(appelsDemandes("gemini", rep.formeClair).map((c) => ({ id: c.id, name: c.name, arguments: c.arguments }))).to.deep.equal(a.tool_calls);
        expect(sdk.is_error || rep.is_error, "is_error déclaré ou calculé").to.equal(a.is_error);
      });
    }
  });

  describe("evenements/journal-demo (B.6) : échanges de seq 2, 4, 8 et corrélation de seq 3 et 5", function () {
    const R = "evenements/journal-demo";
    let entrees;
    let evenements;
    let passerelle;
    let registre;
    const produits = {};

    before(async function () {
      entrees = json(`${R}/entrees.json`);
      evenements = json(`${R}/evenements.json`);
      const h = entrees.host;
      const hote = { ...config.model.hosts[0], id: h.id, launched_by: h.launched_by, on_behalf_of: h.on_behalf_of, scope: h.scope, host_group: h.host_group, tool_name_template: h.tool_name_template, tool_name_sanitize: h.tool_name_sanitize };
      const routes = config.policy.model.routes.map((r) => (r.path === "/v1/messages" ? { ...r, provider_label: "demo" } : r));
      registre = new RegistreCorrelation({ monotone: () => coeur.horlogeBrute.monotone(), ecrirePiece: (p) => coeur.ecrirePiece(p) });
      passerelle = new PasserelleModele({
        coeur,
        secrets,
        registre,
        config: { ...config, model: { ...config.model, hosts: [hote] }, policy: { ...config.policy, model: { routes } } },
        observateur: { echange: (x) => observe.echanges.push(x), refus: (x) => observe.refus.push(x) },
      });
      await passerelle.ecouter();
      for (const ex of entrees.exchanges) {
        fournisseur.prochaine({ statut: 200, entetes: { "content-type": ex.response_content_type }, morceaux: [ex.response_body] });
        const r = await envoyer(passerelle, ex.route, { "content-type": "application/json", "anthropic-version": "2023-06-01", "x-noortrace-token": JETON_MODELE, "x-noortrace-run-id": ex.run_id }, JSON.stringify(ex.request));
        produits[ex.seq] = r.echanges[0].evenement;
      }
    });

    after(async function () {
      await passerelle?.arreter();
    });

    for (const seq of [2, 4, 8]) {
      it(`seq ${seq} : pièces, code.model, prompt_version, intent, is_error, délégation de l'événement publié`, function () {
        const e = produits[seq];
        const p = evenements[seq - 1];
        expect(e.delegation).to.deep.equal(p.delegation);
        expect(e.code.model).to.equal(p.code.model);
        expect(e.code.prompt_version).to.equal(p.code.prompt_version);
        expect(e.intent).to.deep.equal(p.intent);
        expect(e.execution.arguments).to.deep.equal(p.execution.arguments);
        expect(e.execution.result).to.deep.equal(p.execution.result);
        expect(e.execution.is_error).to.equal(p.execution.is_error);
        expect(e.policy).to.deep.equal(p.policy);
        expect(e.context).to.deep.equal(p.context);
      });
    }

    it("seq 3 et 5 : l'appel trouve le bloc tool_use de seq 2 et seq 4, intent tiré de la réponse rédigée (EX-5.22)", async function () {
      const attendu = json(`${R}/attendu.json`).correlation;
      const hoteMcp = { tool_name_template: attendu.tool_name_template, tool_name_sanitize: attendu.tool_name_sanitize };
      for (const c of entrees.calls.filter((x) => x.inherits_from_seq === null)) {
        const params = JSON.parse(c.host_line).params;
        const r = await registre.correler({ host: hoteMcp, host_group: c.host_group, run_id: c.run_id, tool_announced: params.name, arguments: params.arguments, t_recu: coeur.horlogeBrute.monotone() });
        const p = evenements[c.seq - 1];
        const ligne = attendu.calls.find((x) => x.seq === c.seq);
        expect(r.seq, `seq ${c.seq}`).to.equal(ligne.exchange_seq === 2 ? produits[2].seq : produits[4].seq);
        expect(r.intent).to.deep.equal(p.intent);
        expect(r.code).to.deep.equal({ model: p.code.model, prompt_version: p.code.prompt_version });
      }
      // Un même bloc tool_use ne sert qu'à un appel : la ré-émission de seq 7 n'en trouve plus.
      const c7 = entrees.calls.find((x) => x.seq === 7);
      const p7 = JSON.parse(c7.host_line).params;
      expect(await registre.correler({ host: hoteMcp, host_group: c7.host_group, run_id: c7.run_id, tool_announced: p7.name, arguments: p7.arguments, t_recu: coeur.horlogeBrute.monotone() })).to.equal(null);
      for (const f of ["cles.json", "pieces.json"]) lire(`${R}/${f}`);
    });
  });
});
