// Point d'entrée OTLP/HTTP du démon (CT-2 EX-6.26, EX-6.27, EX-6.40) :
// HTTP/1.1 sur `otel.listen` (TLS avec `otel.tls`), `POST` sur le chemin exact
// `otel.path` seulement ; OTLP/gRPC n'est pas servi en version 0. Le corps est
// lu dans la borne `otel.max_body_bytes` : au-delà, la lecture s'arrête, la
// requête reçoit `413` et la connexion est fermée.

import http from "node:http";
import https from "node:https";
import fs from "node:fs";

export class ServeurOtel {
  /**
   * @param {{ingestion: import("./ingestion.mjs").IngestionOtel, config: () => object, journal: object}} o
   */
  constructor(o) {
    this.ingestion = o.ingestion;
    this.configDe = o.config;
    this.journal = o.journal;
    this.serveur = null;
    this.connexions = new Set();
    this.compteur = 0;
  }

  get otel() {
    return this.configDe().otel;
  }

  async ecouter() {
    const gestion = (req, res) => {
      this._requete(req, res).catch((e) => {
        this.journal.consigner("error", "otel", "internal_error", { message: String(e?.message ?? e).slice(0, 200) });
        if (!res.headersSent) {
          res.writeHead(503, { "content-type": "application/json", "retry-after": String(this.otel.retry_after_s) });
          res.end('{"message":"noortrace: enregistreur en mode degrade"}');
        } else res.destroy();
      });
    };
    const t = this.otel.tls;
    this.serveur = t ? https.createServer({ cert: fs.readFileSync(t.cert_file), key: fs.readFileSync(t.key_file), minVersion: "TLSv1.2" }, gestion) : http.createServer(gestion);
    this.serveur.on("connection", (s) => {
      s.noortraceId = ++this.compteur;
      this.connexions.add(s);
      s.on("close", () => this.connexions.delete(s));
    });
    const [hote, port] = this.otel.listen.split(/:(?=[0-9]+$)/);
    await new Promise((res, rej) => {
      this.serveur.once("error", rej);
      this.serveur.listen(Number(port), hote.replace(/^\[|\]$/g, ""), res);
    });
  }

  /** Adresse effective (port 0 dans les essais). */
  adresse() {
    return this.serveur?.address() ?? null;
  }

  async fermer() {
    if (!this.serveur) return;
    for (const s of this.connexions) s.destroy();
    await new Promise((r) => this.serveur.close(() => r()));
  }

  async _requete(req, res) {
    const pre = await this.ingestion.prejuger({ methode: req.method, cible: req.url ?? "", entetes: req.headers, connexion: req.socket.noortraceId ?? 0 });
    if (pre.refus) {
      req.resume();
      return this._envoyer(res, this.ingestion.repondre({ statut: pre.refus.statut, raison: pre.refus.raison, etat: pre.refus.etat }), pre.refus.statut === 413);
    }
    const borne = this.otel.max_body_bytes;
    const morceaux = [];
    let recus = 0;
    let trop = false;
    await new Promise((resoudre) => {
      req.on("data", (c) => {
        recus += c.length;
        if (recus > borne) {
          trop = true;
          req.pause();
          resoudre();
          return;
        }
        morceaux.push(c);
      });
      req.on("end", resoudre);
      req.on("error", resoudre);
      req.on("aborted", resoudre);
    });
    const corps = trop ? null : new Uint8Array(Buffer.concat(morceaux));
    const issue = await this.ingestion.traiter(pre.suite, corps, recus);
    return this._envoyer(res, this.ingestion.repondre(issue), trop);
  }

  _envoyer(res, r, fermer) {
    const entetes = { ...r.entetes };
    if (fermer) entetes.connection = "close";
    res.writeHead(r.statut, entetes);
    res.end(Buffer.from(r.corps), () => {
      if (fermer) res.socket?.destroy();
    });
  }
}
