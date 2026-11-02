// Client ICAP (RFC 3507) des tests du mode ICAP, et mandataire HTTP qui
// l'emploie comme le ferait le mandataire d'un client (CT-2 19.6) :
// l'agent lui envoie ses requêtes de modèle ; il soumet chaque requête au
// démon (REQMOD), relaie la requête rendue au fournisseur, soumet la réponse
// (RESPMOD) en la transmettant morceau par morceau au fil de la réception, et
// rend à l'agent ce que le démon renvoie. Messages ICAP construits octet par
// octet : ligne de requête, en-têtes, `Encapsulated` aux décalages exacts,
// sections HTTP encapsulées, corps en codage `chunked`, Preview et `ieof`.

import net from "node:net";
import tls from "node:tls";
import http from "node:http";

const pause = (ms) => new Promise((r) => setTimeout(r, ms));
const chunk = (o) => Buffer.concat([Buffer.from(`${o.length.toString(16)}\r\n`), o, Buffer.from("\r\n")]);

/** Lecteur de réponses ICAP sur une prise. */
class Lecteur {
  constructor(s) {
    this.s = s;
    this.tampon = Buffer.alloc(0);
    this.fini = false;
    this.attente = null;
    s.on("data", (d) => {
      this.tampon = Buffer.concat([this.tampon, d]);
      this.attente?.();
    });
    const f = () => {
      this.fini = true;
      this.attente?.();
    };
    s.on("end", f);
    s.on("close", f);
    s.on("error", f);
  }

  async jusqua(sep) {
    for (;;) {
      const k = this.tampon.indexOf(sep);
      if (k >= 0) {
        const x = this.tampon.subarray(0, k);
        this.tampon = this.tampon.subarray(k + sep.length);
        return x;
      }
      if (this.fini) return null;
      await new Promise((r) => (this.attente = r));
      this.attente = null;
    }
  }

  async octets(n) {
    while (this.tampon.length < n) {
      if (this.fini) return null;
      await new Promise((r) => (this.attente = r));
      this.attente = null;
    }
    const x = this.tampon.subarray(0, n);
    this.tampon = this.tampon.subarray(n);
    return x;
  }

  /** Tête d'une réponse ICAP : statut et en-têtes (noms en minuscules). */
  async tete() {
    const t = await this.jusqua("\r\n\r\n");
    if (t === null) return null;
    const lignes = t.toString("latin1").split("\r\n");
    const m = /^ICAP\/1\.0 ([0-9]{3})/.exec(lignes.shift());
    const entetes = {};
    for (const l of lignes) {
      const k = l.indexOf(":");
      entetes[l.slice(0, k).toLowerCase()] = l.slice(k + 1).trim();
    }
    return { statut: Number(m?.[1] ?? 0), entetes };
  }

  /** Sections encapsulées et corps `chunked`, chaque morceau remis à `surMorceau`. */
  async encapsule(entetes, surMorceau) {
    const entites = (entetes.encapsulated ?? "").split(",").map((x) => x.trim().split("=")).map(([n, d]) => ({ nom: n, d: Number(d) }));
    const corps = entites[entites.length - 1];
    const brut = corps.d ? await this.octets(corps.d) : Buffer.alloc(0);
    const sections = {};
    for (let k = 0; k < entites.length - 1; k++) sections[entites[k].nom] = brut.subarray(entites[k].d, entites[k + 1].d).toString("latin1");
    const morceaux = [];
    if (corps.nom === "req-body" || corps.nom === "res-body") {
      for (;;) {
        const l = await this.jusqua("\r\n");
        if (l === null) return { sections, corps: Buffer.concat(morceaux), tronque: true };
        const n = parseInt(l.toString("latin1").split(";")[0], 16);
        if (n === 0) {
          await this.jusqua("\r\n");
          break;
        }
        const o = await this.octets(n);
        await this.octets(2);
        morceaux.push(o);
        surMorceau?.(o);
      }
    }
    return { sections, corps: Buffer.concat(morceaux), nomCorps: corps.nom };
  }
}

/** Ouvre une connexion ICAP (ou ICAPS). */
export function connecter(adresse, o = {}) {
  return new Promise((res, rej) => {
    const s = o.tls ? tls.connect({ host: adresse.address, port: adresse.port, ...o.tls }) : net.connect(adresse.port, adresse.address);
    s.once(o.tls ? "secureConnect" : "connect", () => res(s));
    s.once("error", rej);
  });
}

/**
 * Une transaction ICAP complète.
 * @param {{address: string, port: number}} adresse
 * @param {object} t
 * @param {"OPTIONS"|"REQMOD"|"RESPMOD"|string} t.methode
 * @param {string} t.service `/noortrace/reqmod`, `/noortrace/respmod` ou autre
 * @param {Object<string, string>} [t.entetes] en-têtes ICAP en plus
 * @param {string|null} [t.req] en-tête HTTP de la requête encapsulée (avec la ligne vide finale)
 * @param {string|null} [t.res] en-tête HTTP de la réponse encapsulée
 * @param {Buffer[]|null} [t.corps] morceaux du corps (null : null-body)
 * @param {number|null} [t.preview] octets du Preview
 * @param {number} [t.pauseMs] pause entre deux morceaux
 * @param {Function} [t.surMorceau] morceaux du corps de la réponse, au fil de l'eau
 * @param {net.Socket} [t.prise] connexion déjà ouverte (gardée ouverte)
 * @param {object} [t.tls] options TLS (ICAPS)
 */
export async function transaction(adresse, t) {
  const s = t.prise ?? (await connecter(adresse, { tls: t.tls }));
  const lecteur = t.prise?.lecteur ?? new Lecteur(s);
  if (t.prise) s.lecteur = lecteur;
  const req = t.req ? Buffer.from(t.req, "latin1") : null;
  const resh = t.res ? Buffer.from(t.res, "latin1") : null;
  const sections = [];
  let d = 0;
  if (req) {
    sections.push(`req-hdr=${d}`);
    d += req.length;
  }
  if (resh) {
    sections.push(`res-hdr=${d}`);
    d += resh.length;
  }
  const corps = t.corps ?? null;
  if (t.methode === "OPTIONS" && !req && !resh) sections.length = 0;
  else sections.push(corps === null ? `null-body=${d}` : `${t.res ? "res" : "req"}-body=${d}`);
  const lignes = [`${t.methode} icap://${adresse.address}:${adresse.port}${t.service} ICAP/1.0`, `Host: ${adresse.address}`];
  if (sections.length) lignes.push(`Encapsulated: ${sections.join(", ")}`);
  if (t.preview !== undefined && t.preview !== null) lignes.push(`Preview: ${t.preview}`);
  for (const [n, v] of Object.entries(t.entetes ?? {})) lignes.push(`${n}: ${v}`);
  s.write(`${lignes.join("\r\n")}\r\n\r\n`);
  if (req) s.write(req);
  if (resh) s.write(resh);
  let tete = null;
  if (corps !== null) {
    const tout = Buffer.concat(corps);
    if (t.preview !== undefined && t.preview !== null) {
      const p = tout.subarray(0, t.preview);
      const ieof = tout.length <= t.preview;
      if (p.length) s.write(chunk(p));
      s.write(ieof ? "0; ieof\r\n\r\n" : "0\r\n\r\n");
      if (!ieof) {
        tete = await lecteur.tete();
        if (tete?.statut !== 100) return { statut: tete?.statut ?? 0, entetes: tete?.entetes ?? {}, sections: {}, corps: Buffer.alloc(0), avantContinue: true };
        const reste = tout.subarray(t.preview);
        if (reste.length) s.write(chunk(reste));
        s.write("0\r\n\r\n");
      }
      tete = null;
    } else {
      // Lecture de la réponse en parallèle de l'envoi (RESPMOD au fil de l'eau).
      const envoi = (async () => {
        for (const m of corps) {
          if (m.length) s.write(chunk(m));
          if (t.pauseMs) await pause(t.pauseMs);
        }
        if (!t.sansFin) s.write("0\r\n\r\n");
        else if (t.couper) {
          // Coupure du mandataire au milieu du corps : les octets écrits partent d'abord.
          await pause(100);
          s.destroy();
        }
      })();
      tete = await lecteur.tete();
      const x = tete && tete.statut === 200 ? await lecteur.encapsule(tete.entetes, t.surMorceau) : { sections: {}, corps: Buffer.alloc(0) };
      await envoi;
      if (!t.prise) s.end();
      return { statut: tete?.statut ?? 0, entetes: tete?.entetes ?? {}, ...x };
    }
  }
  tete = await lecteur.tete();
  if (!tete) return { statut: 0, entetes: {}, sections: {}, corps: Buffer.alloc(0) };
  const x = tete.entetes.encapsulated && tete.statut === 200 ? await lecteur.encapsule(tete.entetes, t.surMorceau) : { sections: {}, corps: Buffer.alloc(0) };
  if (!t.prise) s.end();
  return { statut: tete.statut, entetes: tete.entetes, ...x };
}

/** Message HTTP de requête (en-tête) à partir d'une ligne et d'une liste. */
export function enteteRequete(depart, entetes) {
  return `${depart}\r\n${entetes.map(([n, v]) => `${n}: ${v}\r\n`).join("")}\r\n`;
}

/** Lit un en-tête HTTP encapsulé rendu par le démon. */
export function lireEntete(texte) {
  const lignes = texte.replace(/\r\n\r\n$/, "").split("\r\n");
  const depart = lignes.shift();
  return { depart, entetes: lignes.map((l) => [l.slice(0, l.indexOf(":")), l.slice(l.indexOf(":") + 1).trim()]) };
}

/**
 * Mandataire HTTP du client, client ICAP du démon.
 * @param {{icap: {address: string, port: number}, fournisseur: string, adresseClient?: string, enteteAdresse?: string,
 *   reqHdrRespmod?: "adaptee"|"originale"|"absente", tls?: object}} o
 */
export async function demarrerMandataire(o) {
  const amont = new URL(o.fournisseur);
  const journal = [];
  const serveur = http.createServer(async (req, rep) => {
    const morceaux = [];
    for await (const c of req) morceaux.push(c);
    const corps = Buffer.concat(morceaux);
    const entetes = [];
    for (let k = 0; k < req.rawHeaders.length; k += 2) {
      const n = req.rawHeaders[k];
      if (["host", "connection", "content-length", "transfer-encoding"].includes(n.toLowerCase())) continue;
      entetes.push([n, req.rawHeaders[k + 1]]);
    }
    entetes.unshift(["Host", amont.host]);
    entetes.push(["Content-Length", String(corps.length)]);
    const reqHdr = enteteRequete(`${req.method} ${req.url} HTTP/1.1`, entetes);
    const ident = { [o.enteteAdresse ?? "X-Client-IP"]: o.adresseClient ?? "127.0.0.1" };
    const r1 = await transaction(o.icap, { methode: "REQMOD", service: "/noortrace/reqmod", entetes: { ...ident, Allow: "204" }, req: reqHdr, corps: corps.length ? [corps] : null, tls: o.tls });
    journal.push({ methode: "REQMOD", statut: r1.statut, encapsulated: r1.entetes.encapsulated });
    if (r1.statut !== 200) {
      rep.writeHead(502).end();
      return;
    }
    if (r1.sections["res-hdr"]) {
      // Requête bloquée : la réponse encapsulée est rendue à l'agent.
      const h = lireEntete(r1.sections["res-hdr"]);
      rep.writeHead(Number(h.depart.split(" ")[1]), Object.fromEntries(h.entetes.filter(([n]) => n.toLowerCase() !== "content-length"))).end(r1.corps);
      return;
    }
    const adaptee = lireEntete(r1.sections["req-hdr"]);
    const [methode, cible] = adaptee.depart.split(" ");
    const versAmont = Object.fromEntries(adaptee.entetes.filter(([n]) => !["host", "content-length"].includes(n.toLowerCase())));
    const ar = http.request({ host: amont.hostname, port: amont.port, path: cible, method: methode, headers: { ...versAmont, "content-length": r1.corps.length } });
    ar.on("error", () => rep.destroy());
    ar.on("response", async (ra) => {
      const resEntetes = [];
      for (let k = 0; k < ra.rawHeaders.length; k += 2) {
        if (["transfer-encoding", "connection", "keep-alive"].includes(ra.rawHeaders[k].toLowerCase())) continue;
        resEntetes.push([ra.rawHeaders[k], ra.rawHeaders[k + 1]]);
      }
      const resHdr = `HTTP/1.1 ${ra.statusCode} ${ra.statusMessage}\r\n${resEntetes.map(([n, v]) => `${n}: ${v}\r\n`).join("")}\r\n`;
      const reqRespmod = o.reqHdrRespmod === "absente" ? null : o.reqHdrRespmod === "originale" ? reqHdr : enteteRequete(adaptee.depart, adaptee.entetes);
      // RESPMOD au fil de l'eau : chaque morceau du fournisseur part aussitôt vers le démon.
      const s = await connecter(o.icap, { tls: o.tls });
      const lecteur = new Lecteur(s);
      const req2 = reqRespmod ? Buffer.from(reqRespmod, "latin1") : null;
      const res2 = Buffer.from(resHdr, "latin1");
      const enc = req2 ? `req-hdr=0, res-hdr=${req2.length}, res-body=${req2.length + res2.length}` : `res-hdr=0, res-body=${res2.length}`;
      s.write(`RESPMOD icap://${o.icap.address}:${o.icap.port}/noortrace/respmod ICAP/1.0\r\nHost: ${o.icap.address}\r\n${Object.entries(ident).map(([n, v]) => `${n}: ${v}\r\n`).join("")}Encapsulated: ${enc}\r\n\r\n`);
      if (req2) s.write(req2);
      s.write(res2);
      ra.on("data", (c) => s.write(chunk(c)));
      ra.on("end", () => s.write("0\r\n\r\n"));
      const tete = await lecteur.tete();
      journal.push({ methode: "RESPMOD", statut: tete?.statut, encapsulated: tete?.entetes.encapsulated });
      let ecrit = false;
      const x = await lecteur.encapsule(tete.entetes, (m) => {
        if (!ecrit) {
          ecrit = true;
          const h = lireEntete(xEntete());
          rep.writeHead(Number(h.depart.split(" ")[1]), Object.fromEntries(h.entetes.filter(([n]) => n.toLowerCase() !== "content-length")));
        }
        rep.write(m);
      });
      function xEntete() {
        return resHdr;
      }
      if (!ecrit) {
        const h = lireEntete(x.sections["res-hdr"] ?? resHdr);
        rep.writeHead(Number(h.depart.split(" ")[1]), Object.fromEntries(h.entetes.filter(([n]) => n.toLowerCase() !== "content-length")));
      }
      rep.end();
      s.end();
    });
    ar.end(r1.corps);
  });
  await new Promise((r) => serveur.listen(0, "127.0.0.1", r));
  return {
    url: `http://127.0.0.1:${serveur.address().port}`,
    journal,
    async arreter() {
      serveur.closeAllConnections?.();
      await new Promise((r) => serveur.close(() => r()));
    },
  };
}
