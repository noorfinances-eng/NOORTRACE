// Service d'approbation factice, pour les tests et la démonstration du cœur.
// Il tient la place du service de CT-3 (lot suivant) : il répond aux sept
// messages de CT-3 §12 avec les formes exactes de `ticket-v0`, tient un état
// de ticket minimal (nouveau, en attente, approuvé, refusé, expiré, consommé)
// et fabrique des remises signées par des clés d'approbateurs données
// (EIP-191, CT-1 §6.3). Il n'évalue aucune règle de CT-3 §6 : la décision
// d'un appel est fixée par une fonction du test. Jamais en production.

import http from "node:http";
import { adresseDepuisClePrivee, hexVersOctets, signerApprobation } from "@noortrace/noyau";
import { ErreurServiceApprobation, ServiceApprobation } from "./approbations.mjs";
import { analyserJsonIntegral, jcsIntegral } from "./jcs-integral.mjs";

/** Clés privées publiques des comptes Hardhat 1 à 3 (CT-1 §13) : sans valeur, tests seulement. */
export const CLES_HARDHAT = Object.freeze([
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
  "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
  "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
]);

export class ServiceApprobationFactice extends ServiceApprobation {
  /**
   * @param {{org_id: string, journal_id: string, decider?: (requete: object) => {decision: string, rule: string|null},
   *   cles?: string[], seuil?: number, source?: string}} p
   *   `decider` : décision pour une demande sans ticket connu (défaut : autorise)
   */
  constructor(p) {
    super();
    this.org_id = p.org_id;
    this.journal_id = p.journal_id;
    this.decider = p.decider ?? (() => ({ decision: "autorise", rule: null }));
    this.cles = (p.cles ?? CLES_HARDHAT).map((c) => hexVersOctets(c, 32));
    const membres = this.cles.map((c) => adresseDepuisClePrivee(c)).sort();
    this.jeu = {
      threshold: { required: p.seuil ?? 2, size: membres.length },
      members: membres,
      source: p.source ?? "jeu statique de la politique de test",
    };
    this.compteur = 0;
    /** demande (outil + arguments en JCS intégral) → ticket */
    this.parDemande = new Map();
    /** ticket → { etat, request, rule, sealed, remises } */
    this.tickets = new Map();
    this.fileRemises = [];
    this.messages = [];
    this.panne = null;
  }

  enregistrer(methode, corps) {
    this.messages.push({ methode, corps });
    if (this.panne) throw new ErreurServiceApprobation(this.panne);
  }

  async charger(r) {
    this.enregistrer("charger", r);
    const candidats = r.tools.filter((t) => this.decider({ tool_announced: t.tool_announced, arguments: {} }).decision !== "autorise");
    return { policy_version: r.policy_version, policy_sha256: r.policy_sha256, approval_candidates: candidats.map((t) => t.tool_announced).sort() };
  }

  async evaluer(r) {
    this.enregistrer("evaluer", r);
    const cle = `${r.tool_announced}\u0000${jcsIntegral(r.arguments)}`;
    const ticket = this.parDemande.get(cle);
    if (ticket) {
      const t = this.tickets.get(ticket);
      if (t.etat === "approuve" || t.etat === "consomme") {
        return { rule: t.rule, decision: "autorise", ticket, ticket_state: "approuve", approval: t.sealed, approver_set: null };
      }
      if (t.etat === "refuse" || t.etat === "expire") {
        return { rule: t.rule, decision: "refuse", ticket, ticket_state: t.etat, approval: t.sealed, approver_set: null };
      }
      return { rule: t.rule, decision: "a_approuver", ticket, ticket_state: "en_attente", approval: null, approver_set: null };
    }
    const d = this.decider(r);
    if (d.decision !== "a_approuver") return { rule: d.rule ?? null, decision: d.decision, ticket: null, ticket_state: null, approval: null, approver_set: null };
    this.compteur++;
    const id = `apr-test-${String(this.compteur).padStart(4, "0")}`;
    this.parDemande.set(cle, id);
    this.tickets.set(id, { etat: "reserve", request: null, rule: d.rule, sealed: null, remises: 0 });
    return { rule: d.rule, decision: "a_approuver", ticket: id, ticket_state: "nouveau", approval: null, approver_set: this.jeu };
  }

  async ouvrir(r) {
    this.enregistrer("ouvrir", r);
    const t = this.tickets.get(r.ticket);
    if (!t) throw new ErreurServiceApprobation("ticket_inconnu");
    if (t.request && t.request.request_hash !== r.request_hash) throw new ErreurServiceApprobation("ticket_deja_ouvert", { request_hash: t.request.request_hash });
    t.request = r;
    if (t.etat === "reserve") t.etat = "ouvert";
    return { ticket: r.ticket, state: t.etat, deadline: null };
  }

  /**
   * Prépare la remise d'une décision (comme si les approbateurs avaient voté).
   * @param {string} ticket
   * @param {{decision?: "approuve"|"refuse"|"expire", signataires?: number[], reason?: string|null, jeu?: object}} [o]
   */
  decider_ticket(ticket, o = {}) {
    const t = this.tickets.get(ticket);
    if (!t?.request) throw new Error("ticket non ouvert");
    const decision = o.decision ?? "approuve";
    const A = { decision, journal_id: this.journal_id, org_id: this.org_id, request_hash: t.request.request_hash, ticket };
    const idx = decision === "expire" ? [] : (o.signataires ?? [0, 1]);
    t.remises++;
    const remise = {
      remise_id: `${ticket}/${t.remises}`,
      ticket,
      approval: {
        decision,
        ticket,
        request_hash: t.request.request_hash,
        threshold: { ...this.jeu.threshold },
        approvers: idx.map((k) => adresseDepuisClePrivee(this.cles[k])),
        signatures: idx.map((k) => signerApprobation(this.cles[k], A)),
        reason: o.reason === undefined ? null : o.reason,
      },
      approver_set: o.jeu ?? this.jeu,
    };
    this.fileRemises.push(remise);
    return remise;
  }

  async decisions(r) {
    this.enregistrer("decisions", r);
    const remises = this.fileRemises.splice(0);
    return { remises };
  }

  async acquitter(r) {
    this.enregistrer("acquitter", r);
    const t = this.tickets.get(r.ticket);
    if (!t) throw new ErreurServiceApprobation("ticket_inconnu");
    if (r.result === "scelle") {
      t.sealed = r.approval;
      t.etat = r.decision;
    } else if (r.result === "temporaire") {
      // représentée plus tard
    }
    return { ticket: r.ticket, state: t.etat };
  }

  async consommer(r) {
    this.enregistrer("consommer", r);
    const t = this.tickets.get(r.ticket);
    if (!t) throw new ErreurServiceApprobation("ticket_inconnu");
    t.etat = "consomme";
    return { ticket: r.ticket, state: "consomme" };
  }

  async expiration(r) {
    this.enregistrer("expiration", r);
    const t = this.tickets.get(r.ticket);
    if (t) {
      t.sealed = r.approval;
      t.etat = "expire";
    }
    return { ticket: r.ticket, state: "expire" };
  }

  /**
   * Sert le service en HTTP sur 127.0.0.1 (pour éprouver le canal d'EX-7.14).
   * @param {number} [port] 0 : port éphémère
   * @returns {Promise<http.Server>}
   */
  servir(port = 0) {
    const serveur = http.createServer((req, res) => {
      const morceaux = [];
      req.on("data", (m) => morceaux.push(m));
      req.on("end", async () => {
        const methode = (req.url ?? "").replace(/^\/v0\//, "");
        try {
          const corps = analyserJsonIntegral(new Uint8Array(Buffer.concat(morceaux)));
          if (typeof this[methode] !== "function" || !["charger", "evaluer", "ouvrir", "decisions", "acquitter", "consommer", "expiration"].includes(methode)) {
            throw new ErreurServiceApprobation("requete_invalide");
          }
          const r = await this[methode](corps);
          res.writeHead(200, { "content-type": "application/json" }).end(jcsIntegral(r));
        } catch (e) {
          const code = e instanceof ErreurServiceApprobation ? e.code : "requete_invalide";
          res.writeHead(400, { "content-type": "application/json" }).end(jcsIntegral({ error: { code, message: code, data: e?.data ?? {} } }));
        }
      });
    });
    return new Promise((resoudre) => serveur.listen(port, "127.0.0.1", () => resoudre(serveur)));
  }
}
