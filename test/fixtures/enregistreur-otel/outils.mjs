// Outils des tests de l'ingestion OpenTelemetry (test/enregistreur-otel-*.test.js) :
// démon en processus (cœur, rédacteur pii-v1 de l'exemple de 15.3, point
// d'entrée OTLP/HTTP réel, et, au besoin, point d'entrée SDK pour le
// recouvrement), envoi HTTP ; les lots OTLP sont dans `lots.mjs`.
// Répertoires sous os.tmpdir().

import http from "node:http";
import path from "node:path";
import { Coeur, Redacteur, demarrerOtel, demarrerSdk, lireEvenements, resoudreSecrets } from "@noortrace/enregistreur";
import { ServiceApprobationFactice as Factice } from "@noortrace/enregistreur/factice";
import { configurationDev, repertoireTemporaire } from "../enregistreur-coeur/outils.mjs";
import { hoteSdk } from "../enregistreur-sdk/outils.mjs";


/**
 * Démon en processus avec l'ingestion OpenTelemetry (et le SDK si demandé).
 * @param {{modifier?: (c: object) => void, sdk?: boolean, horloge?: object}} [o]
 */
export async function demarrerDemonOtel(o = {}) {
  const dir = repertoireTemporaire("noortrace-otel-");
  const { config, env } = configurationDev(dir, o.sdk ? { sdk: { hosts: [hoteSdk()] } } : {});
  if (o.sdk) config.sdk.socket = path.join(dir, "p", "sdk.sock");
  config.otel.listen = "127.0.0.1:0";
  o.modifier?.(config);
  Object.assign(process.env, env);
  const s = resoudreSecrets(config, { env: process.env });
  if (s.erreurs.length) throw new Error(JSON.stringify(s.erreurs));
  const redaction = Redacteur.depuisConfiguration(config, s.secrets, { fils: 0 });
  const service = new Factice({ org_id: config.recorder.org_id, journal_id: config.recorder.journal_id });
  const coeur = await Coeur.demarrer({ config, secrets: s.secrets, redaction, service, horloge: o.horloge });
  const otel = await demarrerOtel(coeur, s.secrets);
  const sdk = o.sdk ? await demarrerSdk(coeur, s.secrets) : null;
  const jeton = Buffer.from(s.secrets.get("/otel/static_tokens/0/token")).toString("utf8");
  const a = otel.serveur.adresse();
  const d = {
    dir,
    config,
    coeur,
    otel,
    sdk,
    jeton,
    adresse: a,
    evenements: () => lireEvenements(coeur.repertoire),
    lignes: (evenement) => coeur.journal.lignes.filter((l) => l.event === evenement),
    /**
     * Envoie une requête OTLP.
     * @param {{corps?: Uint8Array|string|object, type?: string, chemin?: string, methode?: string, entetes?: object, jeton?: string|null, codage?: string}} r
     */
    envoyer: (r = {}) => envoyer(a, { jeton, ...r }),
    async arreter() {
      await sdk?.arreter();
      await otel.arreter();
      await coeur.arreter();
      await redaction.fermer();
    },
  };
  return d;
}

/** Envoi HTTP/1.1 d'une requête OTLP au point d'entrée. */
export function envoyer(adresse, r) {
  const corps = r.corps === undefined ? Buffer.from("{}") : Buffer.isBuffer(r.corps) || r.corps instanceof Uint8Array ? Buffer.from(r.corps) : Buffer.from(typeof r.corps === "string" ? r.corps : JSON.stringify(r.corps));
  const h = { "content-type": r.type ?? "application/json", "content-length": String(corps.length), ...(r.entetes ?? {}) };
  if (r.codage) h["content-encoding"] = r.codage;
  if (r.jeton) h["x-noortrace-token"] = r.jeton;
  return new Promise((resoudre, rejeter) => {
    const req = http.request({ host: adresse.address, port: adresse.port, method: r.methode ?? "POST", path: r.chemin ?? "/v1/traces", headers: h, agent: r.agent }, (res) => {
      const m = [];
      res.on("data", (x) => m.push(x));
      res.on("end", () => {
        const b = Buffer.concat(m);
        let json = null;
        try {
          json = JSON.parse(b.toString("utf8"));
        } catch {
          json = null;
        }
        resoudre({ statut: res.statusCode, entetes: res.headers, corps: b, json });
      });
    });
    req.on("error", rejeter);
    req.end(corps);
  });
}

export { lot, span, spanOutil, spanInference, encoderProtobuf, identifiants } from "./lots.mjs";
