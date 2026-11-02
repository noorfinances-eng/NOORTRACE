// Rédaction avant hachage, côté démon (CT-2 §10) : le rédacteur que les
// frontaux appellent avant toute pièce, les crochets que le cœur attend
// (`redigerMotif`, `executerExtract`, `evaluerEffets`, `verifierPolitique`,
// `lier`, `recharger` ; INTERFACES.md, section e), les contrôles de
// configuration de la rédaction (EX-15.4 pas 3 et 4 : EX-10.6, EX-10.23
// opération 4, coffre d'EX-10.22) et le groupe de fils de calcul d'EX-3.6.
//
// Le rédacteur reçoit une valeur analysée (ou des octets) et une portée, et
// rend la pièce rédigée de §8 avec sa référence et le drapeau `redacted`
// d'EX-10.16 ; le cœur ne voit jamais une pièce non rédigée. Les comptes
// vont au journal d'exploitation (`redaction_applied`) et aux métriques,
// jamais les valeurs ni leurs positions (EX-10.17).

import os from "node:os";
import { Worker } from "node:worker_threads";
import { egaliteJson } from "@noortrace/noyau";
import { ErreurEnregistreur } from "./erreurs.mjs";
import { Piece, pieceNonRedigeable } from "./pieces.mjs";
import { registreSchemas, IDS } from "./schema.mjs";
import { estPointeur } from "./effets.mjs";
import { PolitiqueCompilee, executerOperation, executerExtract, TYPES_NOMMES, TYPE_PROMPT } from "./redaction-moteur.mjs";
import { controlerMotif, executerSousBorne, DepassementBudget } from "./redaction-motifs.mjs";
import { detecterRegex } from "./redaction-detecteurs.mjs";
import { CoffreOriginaux, estSous } from "./coffre.mjs";

/** Borne de référence de la configuration (EX-10.23). */
export const BUDGET_REDACTION_DEFAUT = 1000;
/** Motif d'un `run_id` déclaré (EX-7.2). */
export const MOTIF_RUN_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
/** Motif d'un nom de prompt déclaré (EX-8.6). */
export const MOTIF_NOM_PROMPT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

const echapperPointeur = (s) => String(s).replace(/~/g, "~0").replace(/\//g, "~1");

// ------------------------------------------------------------ contrôles (EX-10.6, EX-15.4)

/**
 * Jetons de remplacement possibles d'une politique (EX-10.6) : `[REDIGE:<t>]`
 * et `[PSEUDO:<t>:000000000000]` pour chaque type, nom de motif ou étiquette
 * `champ`, et `prompt-systeme`.
 * @param {object} doc
 * @returns {string[]}
 */
export function jetonsPossibles(doc) {
  const types = new Set([...TYPES_NOMMES, TYPE_PROMPT, ...Object.keys(doc.named_patterns ?? {})]);
  for (const r of doc.rules ?? []) for (const d of r.detectors ?? []) if (d.type === "champ") types.add(d.label);
  return [...types].flatMap((t) => [`[REDIGE:${t}]`, `[PSEUDO:${t}:000000000000]`]);
}

/**
 * Contrôles d'une politique de rédaction que le schéma n'exprime pas
 * (EX-10.6) et contrôle des jetons de chaque motif nommé sous la borne
 * (EX-10.23 opération 4).
 * @param {object} doc document `politique-redaction-v0`, valide contre son schéma
 * @param {{budgetMs?: number, pointeur?: string}} [o]
 * @returns {{erreurs: object[], avertissements: object[]}}
 */
export function controlerPolitiqueRedaction(doc, o = {}) {
  const base = o.pointeur ?? "";
  const budget = o.budgetMs ?? BUDGET_REDACTION_DEFAUT;
  const erreurs = [];
  const avertissements = [];
  const err = (p, regle, valeur) => erreurs.push({ pointeur: `${base}${p}`, regle, valeur });
  const motifs = doc.named_patterns ?? {};
  const compiles = new Map();
  for (const [nom, m] of Object.entries(motifs)) {
    const c = controlerMotif(m.pattern);
    if (!c.admis) err(`/named_patterns/${echapperPointeur(nom)}/pattern`, `motif hors du sous-ensemble commun (EX-10.6) : ${c.raison}`, m.pattern);
    else compiles.set(nom, c.regexp);
  }
  const ids = new Set();
  (doc.rules ?? []).forEach((r, k) => {
    const ici = `/rules/${k}`;
    if (ids.has(r.id)) err(`${ici}/id`, "identifiant de règle en double (EX-10.6)", r.id);
    ids.add(r.id);
    const champ = r.detectors.some((d) => d.type === "champ");
    if (champ && r.path === undefined) err(`${ici}/path`, "un détecteur champ exige path (EX-10.6)", null);
    if (r.action.kind === "supprimer") {
      if (r.path === undefined) err(`${ici}/path`, "l'action supprimer exige path (EX-10.6)", null);
      if (r.detectors.length !== 1 || r.detectors[0].type !== "champ") err(`${ici}/detectors`, "l'action supprimer exige le seul détecteur champ (EX-10.6)", r.detectors.map((d) => d.type));
    }
    if (r.action.kind === "pseudonyme" && (doc.pseudonym_key === null || doc.pseudonym_key === undefined)) {
      err(`${ici}/action/kind`, "l'action pseudonyme exige pseudonym_key non nul (EX-10.6)", "pseudonyme");
    }
    r.detectors.forEach((d, j) => {
      if (d.type === "regex" && !Object.prototype.hasOwnProperty.call(motifs, d.name)) err(`${ici}/detectors/${j}/name`, "motif nommé inexistant (EX-10.6)", d.name);
    });
  });
  // Aucun motif nommé ne fait correspondre un jeton de remplacement (EX-10.6),
  // motif par motif sous la borne (EX-10.23 opération 4).
  const jetons = jetonsPossibles(doc);
  for (const [nom, re] of compiles) {
    try {
      const touche = executerSousBorne(() => jetons.find((j) => detecterRegex(re, j, 0, j.length).length > 0) ?? null, budget, "jetons");
      if (touche !== null) err(`/named_patterns/${echapperPointeur(nom)}/pattern`, `le motif fait correspondre le jeton ${touche} (EX-10.6)`, motifs[nom].pattern);
    } catch (e) {
      if (!(e instanceof DepassementBudget)) throw e;
      err(`/named_patterns/${echapperPointeur(nom)}/pattern`, "motif trop coûteux sur les jetons (EX-10.23 opération 4)", motifs[nom].pattern);
    }
  }
  return { erreurs, avertissements };
}

/**
 * Contrôle d'une politique de rédaction seule (schéma puis EX-10.6), par
 * exemple `spec/vecteurs/ct-2/redaction/politique-*.json`.
 * @param {object} doc
 * @param {{budgetMs?: number}} [o]
 * @returns {{valide: boolean, erreurs: object[], avertissements: object[]}}
 */
export function validerPolitiqueRedaction(doc, o = {}) {
  const s = registreSchemas().valider(IDS.redaction, doc);
  if (!s.valide) return { valide: false, erreurs: s.erreurs, avertissements: [] };
  const r = controlerPolitiqueRedaction(doc, o);
  return { valide: r.erreurs.length === 0, ...r };
}

/** Chemins visés par une règle `champ` (avertissement d'EX-7.6). */
function cheminsChamp(doc) {
  const s = new Set();
  for (const r of doc.rules ?? []) if (r.path !== undefined && r.detectors.some((d) => d.type === "champ")) s.add(r.path);
  return s;
}

/**
 * Règle supplémentaire de `validerConfiguration` (EX-15.4 pas 3) pour la
 * rédaction : EX-10.6 et EX-10.23 opération 4 sur `policy.redaction`,
 * `extract` des gabarits d'effets dans le sous-ensemble commun et ses
 * règles a) à c) (EX-7.6), avertissement d'un pointeur de gabarit qui
 * désigne un chemin visé par une règle `champ`, coffre (EX-10.22).
 * @param {object} c document de configuration valide contre le schéma
 * @returns {{erreurs: object[], avertissements: object[]}}
 */
export function controleRedaction(c) {
  const budget = c.limits?.redaction_budget_ms ?? BUDGET_REDACTION_DEFAUT;
  const doc = c.policy.redaction;
  const r = controlerPolitiqueRedaction(doc, { budgetMs: budget, pointeur: "/policy/redaction" });
  const erreurs = [...r.erreurs];
  const avertissements = [...r.avertissements];
  const champs = cheminsChamp(doc);
  for (const [a, serveur] of Object.entries(c.policy.servers ?? {})) {
    for (const [nom, outil] of Object.entries(serveur.tools ?? {})) {
      (outil.effects ?? []).forEach((g, k) => {
        const ici = `/policy/servers/${echapperPointeur(a)}/tools/${echapperPointeur(nom)}/effects/${k}`;
        if (g.extract !== null && g.extract !== undefined) {
          const x = controlerMotif(g.extract);
          if (!x.admis) erreurs.push({ pointeur: `${ici}/extract`, regle: `extract hors du sous-ensemble commun (EX-7.6, EX-10.6) : ${x.raison}`, valeur: g.extract });
        }
        for (const champ of ["object", "amount", "currency"]) {
          const v = g[champ];
          if (!estPointeur(v)) continue;
          const sous = v.replace(/^\/(arguments|result)/, "");
          for (const p of champs) {
            if (sous === p || sous.startsWith(`${p}/`)) {
              avertissements.push({ pointeur: `${ici}/${champ}`, regle: "pointeur vers un chemin visé par une règle champ : la valeur sera un jeton, ou absente (EX-7.6)" });
              break;
            }
          }
        }
      });
    }
  }
  const v = c.storage?.vault;
  if (v?.enabled === true) {
    if (v.path === null) erreurs.push({ pointeur: "/storage/vault/path", regle: "chemin du coffre exigé quand il est activé (EX-10.22)", valeur: null });
    if (v.key === null) erreurs.push({ pointeur: "/storage/vault/key", regle: "clé du coffre exigée quand il est activé (EX-10.22)", valeur: null });
    if (v.path !== null && (estSous(v.path, c.storage.root) || estSous(c.storage.root, v.path))) {
      erreurs.push({ pointeur: "/storage/vault/path", regle: "coffre hors du répertoire des segments et des pièces (EX-10.22)", valeur: v.path });
    }
    const ops = c.supervision?.ops_log?.path;
    if (v.path !== null && typeof ops === "string" && estSous(ops, v.path)) {
      erreurs.push({ pointeur: "/storage/vault/path", regle: "le journal d'exploitation ne va pas dans le coffre (EX-10.22)", valeur: v.path });
    }
    if (v.key !== null && JSON.stringify(v.key) === JSON.stringify(c.signer?.backend?.passphrase ?? null)) {
      erreurs.push({ pointeur: "/storage/vault/key", regle: "clé du coffre distincte de celle du signataire (EX-10.22)", valeur: undefined, secret: true });
    }
  }
  return { erreurs, avertissements };
}

/**
 * Pas 4 d'EX-15.4 pour la rédaction : clé du coffre de 32 octets après
 * décodage (EX-10.22) ; la clé de pseudonymisation est vérifiée par
 * `resoudreSecrets` (EX-10.12).
 * @param {object} c
 * @param {Map<string, Uint8Array>} secrets
 * @returns {object[]} erreurs
 */
export function controleSecretsRedaction(c, secrets) {
  const erreurs = [];
  if (c.storage?.vault?.enabled === true) {
    const k = secrets.get("/storage/vault/key");
    if (!k || k.length !== 32) erreurs.push({ pointeur: "/storage/vault/key", regle: "32 octets après décodage (EX-10.22)", secret: true });
  }
  return erreurs;
}

/**
 * EX-10.21 et 10.2.1 : toute modification des règles de rédaction change
 * `redaction.name`. Refus si une version annoncée porte le même nom avec un
 * autre document.
 * @param {object} politique ensemble de politique à annoncer
 * @param {Map<string, object>} annoncees ensembles de politique des versions annoncées
 * @returns {string|null} raison du refus
 */
export function verifierChangementRedaction(politique, annoncees) {
  const doc = politique?.redaction;
  if (!doc) return null;
  for (const [version, p] of annoncees ?? []) {
    if (p?.redaction?.name === doc.name && !egaliteJson(p.redaction, doc)) {
      return `règles de rédaction ${doc.name} changées sans changer redaction.name (EX-10.21, version ${version})`;
    }
  }
  return null;
}

// ------------------------------------------------------------ groupe de fils de calcul (EX-3.6)

/** Taille par défaut du groupe : bornée, au moins 1. */
export function tailleGroupeDefaut() {
  const n = typeof os.availableParallelism === "function" ? os.availableParallelism() : os.cpus().length;
  return Math.max(1, Math.min(4, n - 1));
}

/** Arrêt d'un travail par le chien de garde (fil arrêté et relancé). */
class TravailArrete extends Error {
  constructor(longueur) {
    super("travail arrêté par le chien de garde");
    this.name = "TravailArrete";
    this.longueur = longueur;
  }
}

/**
 * Groupe de fils de calcul de taille bornée (EX-3.6) : chaque fil exécute un
 * travail à la fois ; un travail qui dépasse la garde fait arrêter son fil
 * (`terminate()`), qui est relancé.
 */
export class GroupeCalcul {
  /**
   * @param {{taille: number, donnees: object, gardeMs: number}} o
   */
  constructor(o) {
    this.donnees = o.donnees;
    this.gardeMs = o.gardeMs;
    this.file = [];
    this.fils = [];
    this.compteur = 0;
    this.ferme = false;
    for (let k = 0; k < o.taille; k++) this.fils.push(this._lancer());
  }

  _lancer() {
    const w = new Worker(new URL("./redaction-fil.mjs", import.meta.url), { workerData: this.donnees });
    w.unref();
    const fil = { w, travail: null };
    w.on("message", (m) => {
      const t = fil.travail;
      if (!t || m.id !== t.id) return;
      if (m.debut === true) {
        // Le fil a pris le travail : la garde court depuis cet instant.
        clearTimeout(t.minuteur);
        t.minuteur = this._garde(fil, this.gardeMs);
        return;
      }
      if (m.longueur !== undefined && m.ok === undefined) {
        t.longueur = m.longueur;
        return;
      }
      clearTimeout(t.minuteur);
      fil.travail = null;
      w.unref();
      if (m.ok) t.resoudre(m.r);
      else t.rejeter(Object.assign(new Error(m.erreur.message), { name: m.erreur.name }));
      this._distribuer();
    });
    const panne = (e) => {
      if (fil.mort) return;
      fil.mort = true;
      const t = fil.travail;
      fil.travail = null;
      if (t) {
        clearTimeout(t.minuteur);
        t.rejeter(e instanceof TravailArrete ? e : new TravailArrete(t.longueur ?? null));
      }
      if (!this.ferme) {
        const k = this.fils.indexOf(fil);
        if (k >= 0) this.fils[k] = this._lancer();
        this._distribuer();
      }
    };
    w.on("error", panne);
    w.on("exit", () => panne(new TravailArrete(fil.travail?.longueur ?? null)));
    return fil;
  }

  _garde(fil, ms) {
    const minuteur = setTimeout(() => {
      // Garde : le fil est arrêté et relancé ; le travail échoue.
      fil.mort = true;
      const tr = fil.travail;
      fil.travail = null;
      tr?.rejeter(new TravailArrete(tr.longueur ?? null));
      fil.w.terminate().catch(() => {});
      if (!this.ferme) {
        const k = this.fils.indexOf(fil);
        if (k >= 0) this.fils[k] = this._lancer();
        this._distribuer();
      }
    }, ms);
    minuteur.unref?.();
    return minuteur;
  }

  _distribuer() {
    for (const fil of this.fils) {
      if (!this.file.length) return;
      if (fil.travail || fil.mort) continue;
      const t = this.file.shift();
      fil.travail = t;
      // Avant que le fil ait pris le travail (chargement d'un fil relancé),
      // la garde laisse 30 s de plus.
      t.minuteur = this._garde(fil, this.gardeMs + 30000);
      // Un fil occupé garde le processus en vie ; au repos, il ne le retient pas.
      fil.w.ref();
      fil.w.postMessage({ type: "travail", id: t.id, op: t.op, args: t.args });
    }
  }

  /**
   * Exécute une opération du moteur dans un fil.
   * @param {string} op
   * @param {object} args
   * @returns {Promise<any>}
   */
  executer(op, args) {
    if (this.ferme) return Promise.reject(new Error("groupe de calcul fermé"));
    return new Promise((resoudre, rejeter) => {
      this.file.push({ id: ++this.compteur, op, args, resoudre, rejeter, longueur: null });
      this._distribuer();
    });
  }

  /** Change la politique de tous les fils (rechargement). */
  definir(donnees) {
    this.donnees = donnees;
    for (const fil of this.fils) fil.w.postMessage({ type: "politique", ...donnees });
  }

  async fermer() {
    this.ferme = true;
    for (const t of this.file.splice(0)) t.rejeter(new Error("groupe de calcul fermé"));
    await Promise.all(
      this.fils.map(async (fil) => {
        fil.mort = true;
        await fil.w.terminate().catch(() => {});
      }),
    );
  }
}

// ------------------------------------------------------------ rédacteur

/** Reconstitue une pièce rendue par un fil (référence déjà calculée). */
function pieceRendue(p) {
  if (p instanceof Piece) return p;
  return Object.assign(Object.create(Piece.prototype), { octets: p.octets, reference: p.reference });
}

export class Redacteur {
  /**
   * @param {object} o
   * @param {object} o.politique document `politique-redaction-v0` (contrôlé)
   * @param {Uint8Array|null} [o.cle] clé de pseudonymisation résolue
   * @param {number} [o.budgetMs] `limits.redaction_budget_ms`
   * @param {number} [o.fils] taille du groupe de fils de calcul ; 0 : fil appelant (essais)
   * @param {CoffreOriginaux|null} [o.coffre]
   * @param {object|null} [o.journal] journal d'exploitation
   * @param {object|null} [o.metriques]
   * @param {number} [o.gardeMs] garde d'un travail (défaut : max(10 × budget, 30 s))
   */
  constructor(o) {
    this.budgetMs = o.budgetMs ?? BUDGET_REDACTION_DEFAUT;
    this.coffre = o.coffre ?? null;
    this.journal = o.journal ?? null;
    this.metriques = o.metriques ?? null;
    this.taille = o.fils ?? tailleGroupeDefaut();
    this.gardeMs = o.gardeMs ?? Math.max(10 * this.budgetMs, 30000);
    this._definir(o.politique, o.cle ?? null);
    // Crochets liés : le cœur les appelle détachés de l'objet.
    this.redigerMotif = (motif) => this._redigerMotif(motif);
    this.executerExtract = (motif, texte) => this._executerExtract(motif, texte);
    this.evaluerEffets = (p) => this._evaluerEffets(p);
    this.verifierPolitique = (politique, annoncees) => verifierChangementRedaction(politique, annoncees);
    this.lier = (coeur) => this._lier(coeur);
    this.recharger = (config, secrets) => this._recharger(config, secrets);
  }

  /**
   * Rédacteur d'une configuration validée et de ses secrets résolus.
   * @param {object} config
   * @param {Map<string, Uint8Array>} secrets
   * @param {{fils?: number, journal?: object, metriques?: object}} [o]
   * @returns {Redacteur}
   */
  static depuisConfiguration(config, secrets, o = {}) {
    const v = config.storage?.vault;
    const coffre = v?.enabled === true ? new CoffreOriginaux({ chemin: v.path, cle: secrets.get("/storage/vault/key") }) : null;
    return new Redacteur({
      politique: config.policy.redaction,
      cle: secrets.get("/policy/redaction/pseudonym_key") ?? null,
      budgetMs: config.limits?.redaction_budget_ms ?? BUDGET_REDACTION_DEFAUT,
      coffre,
      ...o,
    });
  }

  _definir(doc, cle) {
    this.doc = doc;
    this.politique = new PolitiqueCompilee(doc, { cle });
    const donnees = { doc, cle: cle ? Array.from(cle) : null, budgetMs: this.budgetMs };
    if (this.taille > 0) {
      if (this.groupe) this.groupe.definir(donnees);
      else this.groupe = new GroupeCalcul({ taille: this.taille, donnees, gardeMs: this.gardeMs });
    }
  }

  /** Nom des règles en vigueur (`policy.redaction`, EX-10.20). */
  get nom() {
    return this.doc.name;
  }

  _lier(coeur) {
    this.journal = coeur.journal ?? this.journal;
    this.metriques = coeur.metriques ?? this.metriques;
    if (this.coffre) {
      this.coffre.journal = this.journal;
      this.journal?.consigner("info", "redaction", "vault_enabled", { path: this.coffre.chemin, algorithm: "AES-256-GCM" });
    }
  }

  _recharger(config, secrets) {
    this._definir(config.policy.redaction, secrets?.get?.("/policy/redaction/pseudonym_key") ?? null);
    this.journal?.consigner("info", "redaction", "redaction_policy_loaded", { name: this.nom });
  }

  async _executer(op, args) {
    if (this.taille === 0) return executerOperation(this.politique, this.budgetMs, op, args);
    return this.groupe.executer(op, args);
  }

  _depassement(operation, scope, regle) {
    this.journal?.consigner("warning", "redaction", "redaction_budget_exceeded", { operation, scope, rule: regle ?? null });
    this.metriques?.compter("noortrace_redaction_budget_exceeded_total", { operation, scope });
  }

  _consignerComptes(portee, r, ctx) {
    if (r.comptes?.length) {
      const rules = [...new Set(r.comptes.map((c) => c.rule))];
      this.journal?.consigner("info", "redaction", "redaction_applied", { scope: portee, rules, matches: r.comptes }, { seq: ctx.seq ?? null, request_id: ctx.id ?? null, host: ctx.host ?? null });
      for (const c of r.comptes) this.metriques?.compter("noortrace_redactions_total", { type: c.detector, scope: portee }, c.count);
    }
    for (const n of r.notes ?? []) {
      this.journal?.consigner("info", "redaction", "redaction_path_unresolved", { scope: portee, rule: n.rule }, { seq: ctx.seq ?? null, request_id: ctx.id ?? null });
    }
  }

  /**
   * Rédige une pièce (EX-10.1, EX-10.14, EX-10.16, EX-8.7) dans un fil de
   * calcul, sous la borne d'EX-10.23 opération 1. Le coffre reçoit
   * l'original chiffré d'une pièce rédigée (EX-10.22).
   * @param {object} demande voir `produirePiece` de redaction-moteur.mjs ; plus `avecValeur`
   *   (rend la valeur rédigée, pour les gabarits d'effets et l'intention)
   * @param {{id?: string, seq?: number, host?: string}} [ctx] identifiant de l'appel avant scellement (EX-10.17)
   * @returns {Promise<{piece: Piece, valeur?: unknown, redacted: boolean, non_redigeable: string|null, comptes: object[]}>}
   */
  async redigerPiece(demande, ctx = {}) {
    const portee = demande.genre === "contexte" ? "contexte" : demande.portee;
    const { avecValeur, ...d } = demande;
    let r;
    try {
      r = await this._executer("piece", { demande: d, avecValeur: avecValeur === true, avecOriginal: this.coffre !== null });
    } catch (e) {
      if (e?.name !== "TravailArrete") throw e;
      // Garde : la pièce est la pièce non rédigeable, sans contenu (EX-10.23).
      this._depassement("piece", portee, null);
      const p = pieceNonRedigeable({ content_type: d.content_type ?? null, length: e.longueur ?? 0, reason: "budget_redaction" });
      return { piece: p, valeur: undefined, redacted: true, non_redigeable: "budget_redaction", comptes: [] };
    }
    if (r.depassement) this._depassement("piece", portee, r.depassement.regle);
    this._consignerComptes(portee, r, ctx);
    const piece = pieceRendue(r.piece);
    if (this.coffre && r.original && piece.reference.redacted) {
      try {
        await this.coffre.deposer(piece.sha256, r.original);
      } finally {
        r.original.fill(0);
      }
    }
    return { piece, valeur: r.valeur, redacted: piece.reference.redacted, non_redigeable: r.non_redigeable ?? null, comptes: r.comptes ?? [] };
  }

  /** Pièce « arguments » d'un appel d'outil (4.4 pas 4, `debutAppel`). */
  redigerArguments(valeur, o = {}) {
    return this.redigerPiece({ genre: "json", portee: "arguments", outil: o.outil ?? null, alias: o.alias ?? null, valeur: valeur ?? {}, avecValeur: true }, o);
  }

  /** Pièce « résultat » d'un appel d'outil (4.4 pas 12, `finAppel`). */
  redigerResultat(valeur, o = {}) {
    return this.redigerPiece({ genre: "json", portee: "resultat", outil: o.outil ?? null, alias: o.alias ?? null, valeur, avecValeur: true }, o);
  }

  /** Pièce « prompt système » (8.2, EX-10.19) : texte rédigé, `text/plain`. */
  redigerPromptSysteme(texte, o = {}) {
    return this.redigerPiece({ genre: "texte", portee: "prompt_systeme", texte }, o);
  }

  /**
   * Refus avant relais d'EX-10.23 opération 1 : la pièce « arguments » d'un
   * outil d'écriture ou susceptible d'approbation, remplacée par la pièce
   * non rédigeable, quand la réponse d'`evaluer` mène à un relais ou à une
   * `retenue`. Lève ErreurEnregistreur(`redaction`, -31010), consigné et
   * compté ; sinon ne fait rien.
   * @param {{non_redigeable: string|null}} args résultat de `redigerArguments`
   * @param {{classe: string, susceptible: boolean, id?: string, host?: string}} o
   */
  bloquerArgumentsNonRedigeables(args, o) {
    if (args.non_redigeable !== "budget_redaction") return;
    if (o.classe !== "ecriture" && !o.susceptible) return;
    this.journal?.consigner("warning", "redaction", "call_blocked", { reason: "redaction", operation: "piece", scope: "arguments", class: o.classe }, { request_id: o.id ?? null, host: o.host ?? null });
    this.metriques?.compter("noortrace_calls_blocked_total", { code: "-31010", reason: "redaction", class: o.classe });
    throw new ErreurEnregistreur("redaction", "noortrace: arguments non redigeables", { code: -31010, donnees: { reason: "redaction" } });
  }

  async _ligne(valeur, quoi) {
    if (typeof valeur !== "string") return false;
    const r = await this._executer("ligne", { valeur });
    if (r.depassement) this._depassement("valeur", quoi, null);
    return r.admise;
  }

  /**
   * `run_id` déclaré (EX-7.2) : motif, puis aucun détecteur de texte de la
   * politique. Le frontal consigne le refus (`delegation_refused`), sans la
   * valeur, et applique la règle de remplacement de 7.2.
   * @param {string} valeur
   * @returns {Promise<boolean>}
   */
  async admettreRunId(valeur) {
    return typeof valeur === "string" && MOTIF_RUN_ID.test(valeur) && this._ligne(valeur, "run_id");
  }

  /**
   * Nom de prompt déclaré (EX-8.6) : motif, puis aucun détecteur de texte.
   * @param {string} valeur
   * @returns {Promise<boolean>}
   */
  async admettreNomPrompt(valeur) {
    return typeof valeur === "string" && MOTIF_NOM_PROMPT.test(valeur) && this._ligne(valeur, "prompt_version");
  }

  /**
   * Valeur en ligne quelconque (segment de modèle d'EX-5.36, par exemple) :
   * aucun détecteur de texte de la politique ne doit y trouver de
   * correspondance.
   * @param {string} valeur
   * @returns {Promise<boolean>}
   */
  admettreValeurLigne(valeur) {
    return this._ligne(valeur, "valeur");
  }

  /**
   * Effets déclarés par le SDK (EX-6.6) : `system` et `object` rédigés par
   * les détecteurs de texte des règles de portée `arguments` de l'outil.
   * @param {object[]} effets forme de CT-1 §5.3, déjà validée
   * @param {{outil: string, alias?: string|null}} o
   * @returns {Promise<{effets: object[], omis: object[]}>}
   */
  async redigerEffetsDeclares(effets, o) {
    const r = await this._executer("effets_declares", { effets, outil: o.outil, alias: o.alias ?? null });
    for (const x of r.omis) {
      this._depassement("valeur", "arguments", null);
      this.journal?.consigner("info", "noyau", "effect_omitted", { gabarit: x.index, raison: x.raison });
    }
    this._consignerComptes("arguments", { comptes: r.comptes }, {});
    return { effets: r.effets, omis: r.omis };
  }

  /** Crochet `redigerMotif` du cœur (EX-10.24). */
  async _redigerMotif(motif) {
    if (motif === null || motif === undefined) return null;
    const r = await this._executer("motif", { motif });
    if (r.depassement) this._depassement("valeur", "motif", null);
    return r.motif;
  }

  /**
   * Crochet `executerExtract` du cœur (EX-7.6 pas 3, EX-10.23 opération 2),
   * dans le fil appelant, sous la borne. Un dépassement lève une erreur
   * `budget: true`, qu'`evaluerEffets` traduit en effet omis.
   */
  _executerExtract(motif, texte) {
    try {
      return executerExtract(motif, texte, this.budgetMs);
    } catch (e) {
      if (e instanceof DepassementBudget) this._depassement("extract", "effets", null);
      throw e;
    }
  }

  /**
   * Crochet `evaluerEffets` du cœur : gabarit d'effets évalué dans un fil de
   * calcul (EX-3.6), `extract` sous la borne (EX-10.23 opération 2).
   * @param {object} p paramètres d'`evaluerEffets` (sans `executerExtract`)
   * @returns {Promise<{effets: object[], omis: object[]}>}
   */
  async _evaluerEffets(p) {
    const { executerExtract: _, ...params } = p;
    void _;
    const r = await this._executer("effets", { params });
    for (const x of r.omis) if (x.raison === "budget_redaction") this._depassement("extract", "effets", null);
    return r;
  }

  /** Arrête les fils de calcul et efface la clé du coffre. */
  async fermer() {
    await this.groupe?.fermer();
    this.coffre?.effacer();
  }
}

