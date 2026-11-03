// Simulateur des requêtes de gel et de lecture d'état d'Azure Blob (gel de
// niveau version) et de Google Cloud Storage (`temporaryHold`, API JSON),
// fidèle à ce que CT-2 en cite (EX-12.33, EX-12.34, EX-12.39) : aucun
// émulateur de ces services ne met en œuvre le stockage immuable de niveau
// version d'Azure ni la rétention par objet de GCS. Azure : `Set Blob Legal
// Hold` (`PUT ?comp=legalhold&versionid=`, `x-ms-legal-hold`), `Get Blob
// Properties` (`HEAD ?versionid=` : `x-ms-immutability-policy-mode`,
// `x-ms-immutability-policy-until-date`, `x-ms-legal-hold` absent sans gel,
// R13-F19). GCS : `PATCH` et `GET` de la ressource objet avec `generation`
// (membres `retention`, `temporaryHold`).

import http from "node:http";

export class SimulateurAzureGcs {
  constructor() {
    this.objets = new Map();
    this.requetes = [];
  }

  /** Ajoute une version d'objet. */
  ajouter(type, cle, version) {
    this.objets.set(`${type}|${cle}|${version}`, { gel: null });
  }

  ecouter() {
    this.serveur = http.createServer((req, res) => {
      const m = [];
      req.on("data", (c) => m.push(c));
      req.on("end", () => {
        const corps = Buffer.concat(m).toString("utf8");
        this.requetes.push({ method: req.method, target: req.url, authorization: req.headers.authorization, entetes: req.headers, corps });
        const u = new URL(req.url, "http://x");
        if (!/^Bearer \S+$/.test(req.headers.authorization ?? "")) return res.writeHead(401).end();
        if (u.pathname.startsWith("/storage/v1/b/")) {
          const [, , , , bucket, , nom] = u.pathname.split("/");
          const cle = decodeURIComponent(nom);
          const o = this.objets.get(`gcs|${cle}|${u.searchParams.get("generation")}`);
          if (!o || !bucket) return res.writeHead(404, { "content-type": "application/json" }).end('{"error":{"code":404}}');
          if (req.method === "PATCH") {
            const b = JSON.parse(corps);
            if (typeof b.temporaryHold !== "boolean" || req.headers["content-type"] !== "application/json") return res.writeHead(400).end();
            o.gel = b.temporaryHold;
          } else if (req.method !== "GET") return res.writeHead(405).end();
          const r = { name: cle, generation: u.searchParams.get("generation"), retention: { mode: "Locked", retainUntilTime: "2037-11-10T11:00:05.123Z" }, temporaryHold: o.gel === true };
          return res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(r));
        }
        const morceaux = u.pathname.split("/");
        const cle = decodeURIComponent(morceaux.slice(2).join("/"));
        const o = this.objets.get(`azure|${cle}|${u.searchParams.get("versionid")}`);
        if (req.headers["x-ms-version"] !== "2020-06-12") return res.writeHead(400).end();
        if (!o) return res.writeHead(404).end();
        if (req.method === "PUT" && u.searchParams.get("comp") === "legalhold") {
          const v = req.headers["x-ms-legal-hold"];
          if (v !== "true" && v !== "false") return res.writeHead(400).end();
          o.gel = v === "true";
          return res.writeHead(200, { "x-ms-legal-hold": v }).end();
        }
        if (req.method === "HEAD") {
          const h = { "x-ms-immutability-policy-mode": "locked", "x-ms-immutability-policy-until-date": "2037-11-10T11:00:05.0000000Z" };
          if (o.gel === true) h["x-ms-legal-hold"] = "true";
          return res.writeHead(200, h).end();
        }
        return res.writeHead(405).end();
      });
    });
    return new Promise((r) => this.serveur.listen(0, "127.0.0.1", () => {
      this.origine = `http://127.0.0.1:${this.serveur.address().port}`;
      r();
    }));
  }

  fermer() {
    return new Promise((r) => this.serveur.close(() => r()));
  }
}
