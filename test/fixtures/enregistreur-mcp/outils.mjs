// Outils des tests du frontal MCP (test/enregistreur-mcp*.test.js) :
// configuration de développement adaptée au frontal (serveurs d'outils de
// démonstration, connexion d'hôte « agent-demo »), rédacteur de test (une
// seule règle : une chaîne entière de la forme d'un IBAN devient
// `[REDIGE:iban]`), service d'approbation de test à réponse fixée, minuteur
// virtuel, enfant stdio factice qui rejoue une transcription `amont.jsonl`
// et pompe qui fait avancer l'horloge et les entrées dans l'ordre des
// horodatages (annexe B.4).

import { EventEmitter } from "node:events";
import { decoderHorodatage } from "@noortrace/noyau";
import { pieceJson, ServiceApprobation } from "@noortrace/enregistreur";
import { configurationDev } from "../enregistreur-coeur/outils.mjs";

export { configurationDev };

/** Entrée de connexion d'hôte des vecteurs (journal-demo, entrees.json). */
export function hoteDemo(o = {}) {
  return {
    id: o.id ?? "agent-demo",
    match: o.match ?? { peer_user: "agent-demo" },
    launched_by: o.launched_by ?? "agent-demo",
    scope: "sinistres:lecture,paiement",
    on_behalf_of: "service-sinistres",
    accept_declared_delegation: true,
    allowed_on_behalf_of: [],
    tool_name_template: "{tool_announced}",
    tool_name_sanitize: false,
    prompt_version_name: null,
    host_group: "demo",
    quota: o.quota ?? { max_concurrent: 32, piece_bytes_per_minute: 268435456, received_bytes_per_minute: 268435456, redaction_ms_per_minute: 30000 },
    alias: null,
  };
}

/** Serveur stdio de la configuration. */
export function serveurStdio(commande, o = {}) {
  return {
    transport: { type: "stdio", command: commande, cwd: null, env: o.env ?? {}, sandbox: null, user: null, integrity: null },
    protocol: o.protocol ?? "auto",
    class_default: o.class_default ?? null,
    timeout_ms: o.timeout_ms ?? null,
    tools: o.tools ?? {},
    uri_prefixes: [],
    relay: o.relay ?? null,
  };
}

/** Réglages d'un outil. */
export function reglageOutil(o = {}) {
  return { class: o.class ?? null, timeout_ms: o.timeout_ms ?? null, effects: o.effects ?? null, failure: o.failure ?? null };
}

/**
 * Configuration du frontal MCP : celle du cœur (15.3 adaptée), serveurs et
 * hôtes du frontal remplacés.
 */
export function configurationMcp(dir, o = {}) {
  const { config, env } = configurationDev(dir, { journal_id: o.journal_id, mcp: true });
  config.mcp.socket = o.socket ?? `${dir}/prise/mcp.sock`;
  config.mcp.http = o.http ?? null;
  config.mcp.hosts = o.hosts ?? [hoteDemo()];
  config.policy.servers = o.servers;
  config.policy.approval.mode = o.mode ?? "erreur";
  if (o.limits) Object.assign(config.limits, o.limits);
  if (o.tools) Object.assign(config.tools, o.tools);
  // Les règles d'approbation de l'exemple de 15.3 visent les outils `sap__*` :
  // le service de test décide lui-même ; la politique reste valide.
  return { config, env };
}

const IBAN = /^[A-Z]{2}[0-9]{2}(?: ?[0-9A-Z]{4}){2,7}(?: ?[0-9A-Z]{1,3})?$/;

/**
 * Rédacteur de test (crochets de la section e d'INTERFACES.md) : une seule
 * règle, une chaîne entière de la forme d'un IBAN devient `[REDIGE:iban]`.
 * Il tient la place du lot de rédaction pour les tests du frontal.
 */
export class RedacteurTest {
  constructor(o = {}) {
    this.appels = [];
    /** Pièces rendues, dans l'ordre (le test lit celle du pas 4 d'un appel sans événement). */
    this.pieces = [];
    this.budgetDepasse = o.budgetDepasse ?? (() => false);
    this.runIdRefuse = o.runIdRefuse ?? (() => false);
  }

  _rediger(v) {
    let n = 0;
    const r = (x) => {
      if (typeof x === "string" && IBAN.test(x)) {
        n++;
        return "[REDIGE:iban]";
      }
      if (Array.isArray(x)) return x.map(r);
      if (x !== null && typeof x === "object") return Object.fromEntries(Object.entries(x).map(([k, y]) => [k, r(y)]));
      return x;
    };
    const valeur = r(v);
    return { valeur, redacted: n > 0 };
  }

  async _piece(portee, valeur, o) {
    this.appels.push({ portee, outil: o.outil });
    if (this.budgetDepasse(portee, valeur, o)) {
      const { pieceNonRedigeable } = await import("@noortrace/enregistreur");
      const p = pieceNonRedigeable({ content_type: null, length: 10, reason: "budget_redaction" });
      return { piece: p, valeur: undefined, redacted: true, non_redigeable: "budget_redaction", comptes: [] };
    }
    const r = this._rediger(valeur);
    const piece = pieceJson(r.valeur, { redacted: r.redacted });
    this.pieces.push({ portee, piece });
    return { piece, valeur: r.valeur, redacted: r.redacted, non_redigeable: null, comptes: [] };
  }

  redigerArguments(valeur, o = {}) {
    return this._piece("arguments", valeur ?? {}, o);
  }

  redigerResultat(valeur, o = {}) {
    return this._piece("resultat", valeur, o);
  }

  async admettreRunId(v) {
    return !this.runIdRefuse(v);
  }
}

/** Service d'approbation de test : réponse d'`evaluer` fixée par une fonction. */
export class ServiceFixe extends ServiceApprobation {
  constructor(repondre, candidats = []) {
    super();
    this.repondre = repondre;
    this.candidats = candidats;
    this.messages = [];
  }

  async charger(r) {
    this.messages.push({ methode: "charger", corps: r });
    return { policy_version: r.policy_version, policy_sha256: r.policy_sha256, approval_candidates: this.candidats.filter((c) => r.tools.some((t) => t.tool_announced === c)) };
  }

  async evaluer(r) {
    this.messages.push({ methode: "evaluer", corps: r });
    return this.repondre(r);
  }

  async ouvrir(r) {
    this.messages.push({ methode: "ouvrir", corps: r });
    return { ticket: r.ticket, state: "en_attente", deadline: null };
  }

  async decisions() {
    return { remises: [] };
  }

  async acquitter(r) {
    this.messages.push({ methode: "acquitter", corps: r });
    return { ticket: r.ticket, state: "x" };
  }

  async consommer(r) {
    this.messages.push({ methode: "consommer", corps: r });
    return { ticket: r.ticket, state: "consomme" };
  }
}

/** Réponse `autorise` sans ticket. */
export const AUTORISE = Object.freeze({ rule: null, decision: "autorise", ticket: null, ticket_state: null, approval: null, approver_set: null });

/** Minuteur virtuel : les minuteurs du frontal partent quand l'horloge les atteint. */
export class MinuteurVirtuel {
  constructor(horloge) {
    this.horloge = horloge;
    this.taches = new Set();
  }

  planifier(ms, f) {
    const t = { echeance: this.horloge.monotone() + ms, f };
    this.taches.add(t);
    return t;
  }

  annuler(t) {
    this.taches.delete(t);
  }

  /** Prochaine échéance (monotone), ou null. */
  prochaine() {
    let m = null;
    for (const t of this.taches) if (m === null || t.echeance < m) m = t.echeance;
    return m;
  }

  /** Lance les tâches échues. */
  lancerEchues() {
    const maintenant = this.horloge.monotone();
    for (const t of [...this.taches]) {
      if (t.echeance <= maintenant) {
        this.taches.delete(t);
        t.f();
      }
    }
  }
}

/** Laisse tourner la boucle d'événements (promesses, fichiers). */
export async function laisserTourner(ms = 15) {
  for (let k = 0; k < 5; k++) await new Promise((r) => setImmediate(r));
  await new Promise((r) => setTimeout(r, ms));
  for (let k = 0; k < 5; k++) await new Promise((r) => setImmediate(r));
}

/**
 * Enfant stdio factice : ce que le frontal écrit sur son entrée standard est
 * noté ; ce que le test lui fait écrire part sur sa sortie standard.
 */
export class EnfantFactice extends EventEmitter {
  constructor(surEcriture) {
    super();
    this.ecrit = [];
    this.stdout = new EventEmitter();
    this.stderr = new EventEmitter();
    this.pid = 4242;
    this.exitCode = null;
    this.stdin = {
      write: (s) => {
        for (const l of String(s).split("\n").filter((x) => x.length)) {
          this.ecrit.push(l);
          surEcriture?.(l, this);
        }
        return true;
      },
      end: () => {
        this.stdout.emit("end");
      },
      on: () => {},
    };
  }

  repondre(ligne) {
    this.stdout.emit("data", Buffer.from(ligne + "\n", "utf8"));
  }

  finDeFichier() {
    this.stdout.emit("end");
  }

  kill() {}
}

/** Horodatage d'une enveloppe de transcription, en ms UNIX. */
export const t = (x) => decoderHorodatage(x);
