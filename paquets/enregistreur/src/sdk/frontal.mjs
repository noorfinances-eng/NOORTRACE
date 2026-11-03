// Point d'entrée SDK du démon (CT-2 §3.1, §6.1 à §6.3, §6.7, EX-6.1 à
// EX-6.8, EX-7.7, EX-12.12, EX-12.15) : méthodes JSON-RPC `noortrace/sdk/*`
// de la table de 6.2, reçues sur la prise locale (une ligne par message,
// 4.7.1). Le SDK ne capture rien : il déclare. Le démon fait le reste —
// délégation (7.2), corrélation (5.6), politique (EX-7.4, EX-6.7, matrice de
// 14.2 par le moteur de politique), rédaction (section 10), pièces (§8),
// intention durable avant la réponse de `debutAppel` (EX-6.3, EX-12.12),
// événement durable avant la réponse de `finAppel`, reprise d'un appel resté
// ouvert à la clôture de la session (EX-12.15, à chaud) — par les crochets du
// cœur, sans rien sceller lui-même.
//
// Une session appartient à la connexion qui l'a ouverte (EX-6.6 : contexte
// « dans la même session seulement » ; un `call` n'est connu que de sa
// connexion) ; une connexion perdue clôt ses sessions (EX-6.13), et leurs
// identifiants ne sont jamais réutilisés (époque du bail et compteur).

import { ErreurEnregistreur, ErreurConstruction } from "../erreurs.mjs";
import { VERSION_ENREGISTREUR } from "../coeur.mjs";
import { Piece, pieceJson, pieceTexte, pieceDeclarationSource, typeMediaNormalise } from "../pieces.mjs";
import { partielAppelOutil } from "../capture.mjs";
import { evaluerEffets } from "../effets.mjs";
import { analyserJsonIntegral } from "../jcs-integral.mjs";
import { CODES, reponseErreur, reponseResultat } from "../mcp/messages.mjs";
import { analyserTexte, decoderUtf8Strict, ErreurTexteJson, membre, valeurDe, premierNombreNonRepresentable } from "../mcp/json-texte.mjs";
import { QuotasHote } from "../mcp/quotas.mjs";
import { resoudreDelegation } from "../mcp/delegation.mjs";
import { intentionBornee } from "../modele/extraction.mjs";
import { deriverEchangeSdk } from "./echange.mjs";
import {
  ErreurEntree, controlerParametres, nomOutilSdk, controlerEffets, controlerIntention, controlerClasse, controlerContexte,
  controlerTypeMedia, decoderBase64Strict, controlerDuree, controlerBooleen, controlerStatut, controlerIdentifiant,
  SORTES_CONTEXTE, FORMATS_SDK, MOTIF_LIBELLE,
} from "./validation.mjs";

/** Préfixe des méthodes (6.2). */
export const PREFIXE_METHODES = "noortrace/sdk/";
/** Méthodes servies. */
export const METHODES_SDK = Object.freeze(["ouvrir", "declarerContexte", "debutAppel", "finAppel", "echangeModele", "fermer"]);
/** Méthodes soumises aux quotas de la connexion d'hôte (EX-4.47) ; `finAppel` et `fermer` ne le sont jamais (lecture du LISEZMOI). */
const SOUS_QUOTA = new Set(["ouvrir", "declarerContexte", "debutAppel", "echangeModele"]);

/**
 * Compteurs des identifiants de session et d'appel, propres au processus :
 * avec l'époque du bail, un identifiant n'est jamais réutilisé, même si le
 * point d'entrée est redémarré sans redémarrer le démon (EX-6.13).
 */
const COMPTEURS = { session: 0, appel: 0 };

/** Erreur à rendre telle quelle. */
class Rendu extends Error {
  constructor(texte) {
    super("rendu");
    this.texte = texte;
  }
}

/**
 * Classe d'un appel déclaré par le SDK (table de 6.2, EX-6.15, EX-6.18) : la
 * classe de la configuration du démon prime ; une classe déclarée ne peut que
 * la renforcer (`lecture` → `ecriture`) ; sans classe configurée, la
 * déclarée, à défaut `ecriture`.
 * @param {"lecture"|"ecriture"|null} configuree
 * @param {"lecture"|"ecriture"|null} declaree
 * @returns {{classe: "lecture"|"ecriture", ecart: boolean}} `ecart` : une classe déclarée plus faible a été refusée
 */
export function classeSdk(configuree, declaree) {
  if (configuree === null) return { classe: declaree ?? "ecriture", ecart: false };
  if (configuree === "ecriture") return { classe: "ecriture", ecart: declaree === "lecture" };
  return { classe: declaree === "ecriture" ? "ecriture" : "lecture", ecart: false };
}

/**
 * Classe configurée d'un outil déclaré par le SDK. Le schéma
 * `configuration-enregistreur-v0` ne porte aucun réglage de classe pour un
 * outil du SDK (`sdk.hosts` n'a pas de membre `tools`, `policy.sdk` n'a que
 * `aliases`, et l'alias du SDK est distinct de tout alias de
 * `policy.servers`, EX-6.6, EX-15.4) : en version 0, aucune (lecture du
 * LISEZMOI).
 * @returns {null}
 */
export function classeConfigureeSdk() {
  return null;
}

export class FrontalSdk {
  /**
   * @param {object} o
   * @param {import("../coeur.mjs").Coeur} o.coeur
   * @param {object|null} [o.redacteur] rédacteur (section e), à défaut celui du cœur
   * @param {import("../modele/correlation.mjs").RegistreCorrelation|null} [o.correlateur] registre de 5.6
   */
  constructor(o) {
    this.coeur = o.coeur;
    const r = o.redacteur ?? this.coeur.o?.redaction ?? null;
    this.redacteur = r && typeof r.redigerPiece === "function" ? r : null;
    this.correlateur = o.correlateur ?? null;
    this.quotas = new Map();
    this.connexions = new Set();
    this.compteurConnexion = 0;
    if (!this.redacteur) this.journal.consigner("warning", "redaction", "redaction_absente", { component: "sdk" });
  }

  get config() {
    return this.coeur.config;
  }

  get journal() {
    return this.coeur.journal;
  }

  get metriques() {
    return this.coeur.metriques;
  }

  monotone() {
    return this.coeur.horlogeBrute.monotone();
  }

  /** Mode observation de la version en vigueur (14.6). */
  get observation() {
    return this.coeur.politique?.observation === true;
  }

  /**
   * Entrée de `sdk.hosts` d'une identité de connexion (EX-6.1, EX-7.3).
   * @param {{peer_user?: string, static_token?: string}} match
   * @returns {object|null}
   */
  hotePour(match) {
    for (const h of this.config.sdk.hosts ?? []) {
      if (match.peer_user !== undefined && h.match?.peer_user === match.peer_user) return h;
      if (match.static_token !== undefined && h.match?.static_token === match.static_token) return h;
    }
    return null;
  }

  _quotas(hote) {
    let q = this.quotas.get(hote.id);
    if (!q) {
      q = new QuotasHote(hote.quota);
      this.quotas.set(hote.id, q);
    }
    return q;
  }

  _identifiant(prefixe, n) {
    return `${prefixe}-${String(this.coeur.ecrivain?.epoque ?? 0).padStart(20, "0")}-${String(n).padStart(12, "0")}`;
  }

  /**
   * Ouvre une connexion d'hôte authentifiée (EX-6.1).
   * @param {{hote: object, identite: object}} p
   */
  ouvrirConnexion(p) {
    const cx = { id: ++this.compteurConnexion, hote: p.hote, identite: p.identite ?? {}, sessions: new Map(), appels: new Map(), close: false };
    this.connexions.add(cx);
    this.journal.consigner("info", "sdk", "sdk_connected", { transport: p.identite?.transport ?? (p.identite?.jeton ? "tcp" : "unix") }, { host: p.hote.id });
    return cx;
  }

  /**
   * Connexion perdue (EX-6.13) : ses sessions sont closes, et chaque
   * `debutAppel` qui a écrit une intention sans `finAppel` donne son événement
   * de reprise, le démon tournant (EX-12.15).
   * @param {object} cx
   */
  async fermerConnexion(cx) {
    if (cx.close) return;
    cx.close = true;
    this.connexions.delete(cx);
    for (const s of [...cx.sessions.values()]) await this._clore(s, "connexion_perdue");
  }

  /** Arrêt du démon : rien n'est repris à chaud ; la relecture du journal d'intention le fera (EX-12.15). */
  arreter() {
    for (const cx of this.connexions) cx.close = true;
    this.connexions.clear();
  }

  // ---------------------------------------------------------------- réception

  /**
   * Traite une ligne reçue (4.7.1) et rend la ligne de réponse, ou null.
   * @param {object} cx connexion
   * @param {Uint8Array} octets ligne sans son LF
   * @returns {Promise<string|null>}
   */
  async recevoir(cx, octets) {
    const t_recu = this.monotone();
    const hote = cx.hote;
    const quotas = this._quotas(hote);
    quotas.recevoir(t_recu, octets.length);
    if (octets.includes(13)) return reponseErreur(null, -32700, { reason: "cr_dans_la_ligne" });
    const lim = this.config.limits;
    let texte;
    let noeud;
    try {
      texte = decoderUtf8Strict(octets);
      noeud = analyserTexte(texte, { profondeurMax: lim.json_max_depth, membresMax: lim.json_max_members });
    } catch (e) {
      if (!(e instanceof ErreurTexteJson)) throw e;
      if (e.raison === "non_canonisable") return reponseErreur(null, -32602, { reason: "nombre_non_canonisable" });
      return reponseErreur(null, -32700, { reason: e.raison === "syntaxe" ? "json_invalide" : e.raison });
    }
    const dureeAnalyse = this.monotone() - t_recu;
    if (noeud.t === "tableau") return reponseErreur(null, -32600, { reason: "lot_non_pris_en_charge" });
    if (noeud.t !== "objet") return reponseErreur(null, -32600);
    const id = membre(noeud, "id");
    const idValide = id && (id.t === "chaine" || id.t === "nombre");
    const idBrut = idValide ? texte.slice(id.d, id.f) : null;
    const jsonrpc = membre(noeud, "jsonrpc");
    const methodeNoeud = membre(noeud, "method");
    if (jsonrpc?.t !== "chaine" || jsonrpc.valeur !== "2.0" || methodeNoeud?.t !== "chaine" || (id && !idValide)) return reponseErreur(idBrut, -32600);
    if (!idBrut) {
      // Le SDK n'envoie aucune notification (EX-6.10) : ignorée, consignée.
      this.journal.consigner("info", "sdk", "notification_ignored", {}, { host: hote.id });
      return null;
    }
    const nomMethode = methodeNoeud.valeur;
    const methode = nomMethode.startsWith(PREFIXE_METHODES) ? nomMethode.slice(PREFIXE_METHODES.length) : null;
    if (!methode || !METHODES_SDK.includes(methode)) return reponseErreur(idBrut, -32601);
    const paramsNoeud = membre(noeud, "params");
    if (paramsNoeud && paramsNoeud.t !== "objet") return reponseErreur(idBrut, -32602, { reason: "params_non_objet" });
    const m = { texte, idBrut, methode, paramsNoeud, params: paramsNoeud ? valeurDe(paramsNoeud) : {}, t_recu };
    // Instance passive (13.4, EX-14.17) : -31010 bail_non_detenu, sauf fermer.
    if (!this.coeur.bailDetenu && methode !== "fermer") return this._bloque(m, hote, "bail_non_detenu", null);
    let compte = false;
    if (SOUS_QUOTA.has(methode)) {
      const q = quotas.depasse(t_recu, { appel: true });
      if (q && this.observation) {
        // Mode observation (EX-14.16) : un quota d'hôte ne bloque pas.
        this.coeur.politique.consignerBlocageEvite({ would: "quota", raison: "quota", host: hote.id, request_id: idBrut });
      } else if (q) {
        this.journal.consigner("warning", "sdk", "call_blocked", { code: CODES.TAILLE, reason: "quota", ...q }, { host: hote.id, request_id: idBrut });
        this.metriques.compter("noortrace_calls_blocked_total", { code: String(CODES.TAILLE), reason: "quota", class: "" });
        return reponseErreur(idBrut, CODES.TAILLE, q);
      }
      quotas.enCours++;
      compte = true;
    }
    quotas.tempsCapture(t_recu, dureeAnalyse);
    try {
      const resultat = await this[`_${methode}`](cx, m);
      return reponseResultat(idBrut, JSON.stringify(resultat));
    } catch (e) {
      if (e instanceof Rendu) return e.texte;
      if (e instanceof ErreurEntree) {
        this.journal.consigner("info", "sdk", "sdk_input_refused", { method: methode, reason: e.raison }, { host: hote.id, request_id: idBrut });
        return reponseErreur(idBrut, -32602, { reason: e.raison });
      }
      if (e instanceof ErreurEnregistreur || e instanceof ErreurConstruction) return this._bloque(m, hote, e.raison ?? "stockage", null);
      this.journal.consigner("error", "sdk", "internal_error", { method: methode, message: String(e?.message ?? e).slice(0, 200) }, { host: hote.id, request_id: idBrut });
      return reponseErreur(idBrut, -32603);
    } finally {
      if (compte) quotas.enCours--;
    }
  }

  /** -31010 (14.2) : rendu, consigné (`call_blocked`, EX-14.7) et compté. */
  _bloque(m, hote, raison, classe, nom = null) {
    this.journal.consigner("warning", "sdk", "call_blocked", { code: CODES.BLOQUE, reason: raison, tool_announced: nom, class: classe }, { host: hote.id, request_id: m.idBrut });
    this.metriques.compter("noortrace_calls_blocked_total", { code: String(CODES.BLOQUE), reason: raison ?? "", class: classe ?? "" });
    return reponseErreur(m.idBrut, CODES.BLOQUE, { reason: raison });
  }

  _session(cx, id) {
    const s = typeof id === "string" ? cx.sessions.get(id) : undefined;
    if (!s || s.close) throw new ErreurEntree("session_inconnue");
    return s;
  }

  // ---------------------------------------------------------------- ouvrir

  async _ouvrir(cx, m) {
    const p = controlerParametres("ouvrir", m.params);
    const run_id = p.run_id ?? null;
    const on_behalf_of = p.on_behalf_of ?? null;
    if (run_id !== null && typeof run_id !== "string") throw new ErreurEntree("run_id_hors_forme");
    if (on_behalf_of !== null && typeof on_behalf_of !== "string") throw new ErreurEntree("on_behalf_of_hors_forme");
    const hote = cx.hote;
    const declaree = {};
    if (run_id !== null) declaree.run_id = run_id;
    if (on_behalf_of !== null) declaree.on_behalf_of = on_behalf_of;
    let runRefuse = false;
    if (run_id !== null && hote.accept_declared_delegation === true && this.redacteur?.admettreRunId) runRefuse = !(await this.redacteur.admettreRunId(run_id));
    const delegation = resoudreDelegation({
      hote,
      identite: cx.identite,
      declaree: Object.keys(declaree).length ? declaree : undefined,
      sessionHeritee: null,
      detecte: () => runRefuse,
      refus: (champ, raison, longueur) =>
        this.journal.consigner("warning", "sdk", "delegation_refused", { component: "sdk", field: champ, reason: raison, length: longueur }, { host: hote.id, request_id: m.idBrut }),
    });
    if (delegation.launched_by === null) throw new ErreurEntree("identite_sans_lanceur");
    if (Object.keys(declaree).length && hote.accept_declared_delegation === true) {
      this.journal.consigner("info", "sdk", "delegation_declared", { fields: Object.keys(declaree) }, { host: hote.id, request_id: m.idBrut });
    }
    const id = this._identifiant("s", ++COMPTEURS.session);
    cx.sessions.set(id, { id, cx, hote, delegation, contextes: new Map(), appels: new Map(), close: false });
    this.journal.consigner("info", "sdk", "sdk_session_opened", { session: id }, { host: hote.id, request_id: m.idBrut });
    return { session: id, org_id: this.coeur.org_id, journal_id: this.coeur.journal_id, policy_version: this.coeur.versionPolitique };
  }

  // ---------------------------------------------------------------- declarerContexte

  async _declarerContexte(cx, m) {
    const p = controlerParametres("declarerContexte", m.params);
    const s = this._session(cx, p.session);
    if (!SORTES_CONTEXTE.includes(p.kind)) throw new ErreurEntree("kind_hors_forme");
    const media_type = controlerTypeMedia(p.media_type);
    const octets = decoderBase64Strict(p.bytes_base64);
    const borne = this.config.limits.piece_max_bytes;
    if (octets.length > borne) {
      this.journal.consigner("warning", "sdk", "call_blocked", { code: CODES.TAILLE, reason: "requete", length: octets.length }, { host: cx.hote.id, request_id: m.idBrut });
      throw new Rendu(reponseErreur(m.idBrut, CODES.TAILLE, { limit_bytes: borne, direction: "requete" }));
    }
    const t0 = this.monotone();
    let piece;
    if (this.redacteur) {
      piece = (await this.redacteur.redigerPiece({ genre: "contexte", outil: null, alias: cx.hote.alias, octets, media_type }, { host: cx.hote.id, id: m.idBrut })).piece;
    } else {
      piece = contexteSansRedaction(octets, media_type);
    }
    const q = this._quotas(cx.hote);
    q.tempsCapture(this.monotone(), this.monotone() - t0);
    await this.coeur.ecrirePiece(piece);
    q.piece(this.monotone(), piece.octets.length);
    s.contextes.set(piece.sha256, piece.referenceContexte(p.kind));
    this.metriques.compter("noortrace_pieces_bytes_total", { scope: "contexte" }, piece.octets.length);
    return { sha256: piece.reference.sha256, length: piece.reference.length, redacted: piece.reference.redacted };
  }

  // ---------------------------------------------------------------- debutAppel (pas 2 à 8 de 4.4)

  async _debutAppel(cx, m) {
    const p = controlerParametres("debutAppel", m.params);
    const s = this._session(cx, p.session);
    const hote = cx.hote;
    const alias = hote.alias;
    const nom = nomOutilSdk(p.tool, alias);
    const declaree = controlerClasse(p.class);
    const context = controlerContexte(p.context, s.contextes);
    const intentDeclare = controlerIntention(p.intent);
    const effetsDeclares = controlerEffets(p.effects);
    // EX-4.44 : arguments exactement représentables (le JCS intégral de la pièce les hache).
    const argsNoeud = membre(m.paramsNoeud, "arguments");
    if (argsNoeud && premierNombreNonRepresentable(m.texte, argsNoeud) !== null) throw new ErreurEntree("nombre_non_representable");
    const argumentsClair = p.arguments;
    const ctx = { host: hote.id, request_id: m.idBrut };

    // Classe (table de 6.2) : la configuration prime ; une classe déclarée ne fait que renforcer.
    const configuree = classeConfigureeSdk(this.config, alias, p.tool);
    const { classe, ecart } = classeSdk(configuree, declaree);
    if (ecart) this.journal.consigner("warning", "sdk", "sdk_class_override_refused", { alias, tool: p.tool, declared: declaree, configured: configuree }, ctx);

    // Corrélation (5.6, EX-5.22) : seuls code.model et code.prompt_version en sont tirés.
    let code = { model: null, prompt_version: null };
    if (this.correlateur) {
      const c = await this.correlateur.correler({ host: hote, host_group: hote.host_group, run_id: s.delegation.run_id, tool_announced: p.tool, arguments: argumentsClair, t_recu: m.t_recu });
      this.journal.consigner("info", "sdk", "correlation", { seq: c?.seq ?? "aucun" }, ctx);
      if (c) code = { model: c.code?.model ?? null, prompt_version: c.code?.prompt_version ?? null };
    }

    // intent déclaré (table `intent` de 7.2) : rédigé par la portée `arguments` comme une pièce texte, EX-5.21.
    const t0 = this.monotone();
    let intent = null;
    let pieceIntention = null;
    if (intentDeclare !== null) {
      if (this.redacteur) {
        const x = await this.redacteur.redigerPiece({ genre: "texte", portee: "arguments", outil: nom, alias, texte: intentDeclare, avecValeur: true }, ctx);
        if (x.non_redigeable) {
          pieceIntention = x.piece;
          intent = x.piece.reference;
        } else {
          const b = intentionBornee(x.valeur, intentDeclare);
          intent = b.intent;
          pieceIntention = b.piece;
        }
      } else {
        const b = intentionBornee(intentDeclare, intentDeclare);
        intent = b.intent;
        pieceIntention = b.piece;
      }
    }

    // Pas 3 : politique (EX-7.4, EX-6.7) par le moteur de politique.
    const moteur = this.coeur.politique;
    const blocagesEvites = [];
    let reponse;
    let observation = null;
    try {
      const issue = await moteur.evaluerAppel(
        {
          tool_announced: nom,
          tool_original: p.tool,
          server_alias: alias,
          arguments: argumentsClair,
          class: classe,
          delegation: s.delegation,
          intent,
          code: { model: code.model, prompt_version: code.prompt_version, policy_version: this.coeur.versionPolitique, recorder: VERSION_ENREGISTREUR },
          // `$defs/requete_evaluer` : éléments `context_item` de CT-1 (référence et `kind`).
          context,
        },
        { nom, classe, alias, host: hote.id, request_id: m.idBrut },
      );
      reponse = issue.reponse;
      observation = issue.observation;
      if (observation?.bloquerait) blocagesEvites.push(observation.bloquerait);
    } catch (e) {
      if (!(e instanceof ErreurEnregistreur)) throw e;
      throw new Rendu(this._bloque(m, hote, e.raison ?? "approbation", classe, nom));
    }
    const classeEffective = moteur.classeEffective(reponse, classe);
    const relaieOuRetient = reponse.decision === "autorise" || reponse.ticket_state === "nouveau";
    const susceptible = classe === "ecriture" || this.coeur.susceptible(nom);

    // Pas 7 (anticipé) : mode dégradé (14.2).
    const panne = this._etatPanne(classeEffective);
    let passant = false;
    if (panne.bloque && observation && panne.bloque !== "bail_non_detenu") {
      blocagesEvites.push(panne.bloque);
      passant = true;
    } else if (panne.bloque && reponse.ticket_state !== "en_attente") {
      throw new Rendu(this._bloque(m, hote, panne.bloque, classe, nom));
    }
    if (!passant) passant = panne.passant === true && reponse.decision === "autorise" && reponse.ticket_state === null;

    // Pas 4 : pièce « arguments » rédigée.
    let pa;
    if (this.redacteur) {
      const x = await this.redacteur.redigerArguments(argumentsClair, { outil: nom, alias, id: m.idBrut, host: hote.id });
      pa = { piece: x.piece, valeurRedigee: x.non_redigeable ? null : x.valeur ?? null, nonRedigeable: x.non_redigeable ?? null };
    } else {
      pa = { piece: pieceJson(argumentsClair), valeurRedigee: argumentsClair, nonRedigeable: null };
    }
    this._quotas(hote).tempsCapture(this.monotone(), this.monotone() - t0);
    // EX-6.7, EX-10.23 opération 1 : -31010 `redaction` avant l'intention ou la retenue.
    if (pa.nonRedigeable === "budget_redaction" && susceptible && relaieOuRetient) {
      if (!observation) throw new Rendu(this._bloque(m, hote, "redaction", classe, nom));
      blocagesEvites.push("redaction");
    }
    const piecesAEcrire = [pa.piece, ...(pieceIntention ? [pieceIntention] : [])];
    if (!passant && reponse.ticket_state !== "en_attente") {
      try {
        await this._ecrirePieces(hote, piecesAEcrire);
      } catch (e) {
        if (!(e instanceof ErreurEnregistreur)) throw e;
        if (!observation) throw new Rendu(this._bloque(m, hote, e.raison, classe, nom));
        blocagesEvites.push(e.raison);
        passant = true;
      }
    }
    const capture = {
      host: { id: hote.id, launched_by: s.delegation.launched_by, on_behalf_of: hote.on_behalf_of ?? null, scope: hote.scope },
      delegation: s.delegation,
      tool_announced: nom,
      tool_original: p.tool,
      server_alias: alias,
      class: classe,
      arguments: pa.piece.reference,
      context,
      intent,
      code,
    };

    // Pas 5 : refus (sans ticket, ou ticket refusé ou expiré, EX-7.12).
    if (reponse.decision === "refuse") {
      await this.coeur.scellerRefus(capture, reponse);
      return { call: null, decision: "refuse", ticket: reponse.ticket ?? null, ticket_state: reponse.ticket_state ?? null };
    }
    // Pas 6 : retenue (jamais de requête retenue par le SDK, EX-6.7).
    if (reponse.ticket_state === "nouveau") {
      await this.coeur.scellerRetenue(capture, reponse, argumentsClair);
      return { call: null, decision: "a_approuver", ticket: reponse.ticket, ticket_state: "nouveau" };
    }
    if (reponse.ticket_state === "en_attente") {
      this.journal.consigner("info", "politique", "approval_pending", { server: alias, tool_announced: nom }, ctx);
      return { call: null, decision: "a_approuver", ticket: reponse.ticket, ticket_state: "en_attente" };
    }
    if (reponse.decision !== "autorise") throw new Rendu(this._bloque(m, hote, "approbation", classe, nom));

    // Effets déclarés (EX-6.6, EX-7.6 pas 2 et 4) : détecteurs de la portée `arguments`.
    let effets;
    if (effetsDeclares !== null) {
      effets = this.redacteur?.redigerEffetsDeclares ? (await this.redacteur.redigerEffetsDeclares(effetsDeclares, { outil: nom, alias })).effets : effetsDeclares;
      this.journal.consigner("info", "sdk", "sdk_effects_declared", { tool_announced: nom, count: effets.length }, ctx);
    }

    // Pas 7 et 8 : RL-1 à RL-4 et intention durable avant la réponse (EX-6.3, EX-12.12).
    const call = this._identifiant("c", ++COMPTEURS.appel);
    let relais = null;
    if (!passant) {
      try {
        relais = await this.coeur.preparerRelais(capture, { reponse, argumentsEnClair: argumentsClair, upstream_id: call, effetsDeclares: effets });
      } catch (e) {
        if (!(e instanceof ErreurEnregistreur || e instanceof ErreurConstruction)) throw e;
        if (!observation) throw new Rendu(this._bloque(m, hote, e.raison ?? "stockage", classe, nom));
        blocagesEvites.push(e.raison ?? "stockage");
        passant = true;
      }
    }
    const appel = {
      call,
      session: s,
      capture,
      reponse,
      relais,
      passant,
      observation,
      blocagesEvites,
      classe,
      effets,
      pieceArguments: pa.piece,
      piecesEnAttente: passant ? piecesAEcrire : [],
      argumentsRediges: pa.valeurRedigee,
      sourceNonRedigeable: pa.nonRedigeable !== null,
      dureeDebut: this.monotone() - m.t_recu,
    };
    s.appels.set(call, appel);
    cx.appels.set(call, appel);
    this.journal.consigner(
      "info",
      "sdk",
      "sdk_call_started",
      { tool_announced: nom, class: classe, intent_id: relais?.intention?.intent_id ?? null, ticket: relais?.ticket ?? null, pending: passant },
      ctx,
    );
    return { call, decision: "autorise", ticket: reponse.ticket_state === "approuve" ? reponse.ticket : null, ticket_state: reponse.ticket_state === "approuve" ? "approuve" : null };
  }

  /** Panne au pas 7 (14.2) : `{ bloque: raison }`, `{ passant: true }` ou `{}`. */
  _etatPanne(classeEffective) {
    const c = this.coeur;
    if (!c.bailDetenu) return { bloque: "bail_non_detenu" };
    const r = c.degrade.raisons();
    for (const x of ["cle", "bail", "horloge"]) if (r.includes(x)) return { bloque: x };
    const lecturePassante = (this.config.policy.failure?.lecture ?? "passant") === "passant";
    if (r.includes("stockage") || c.intervention) {
      if (classeEffective === "ecriture" || !lecturePassante) return { bloque: "stockage" };
      if (r.includes("attente")) return { bloque: "attente" };
      return { passant: true };
    }
    if (r.includes("attente") && classeEffective !== "ecriture") return { bloque: "attente" };
    return {};
  }

  async _ecrirePieces(hote, pieces) {
    const q = this._quotas(hote);
    for (const p of pieces) {
      await this.coeur.ecrirePiece(p);
      q.piece(this.monotone(), p.octets.length);
    }
  }

  // ---------------------------------------------------------------- finAppel (pas 12 et 13)

  async _finAppel(cx, m) {
    const p = controlerParametres("finAppel", m.params);
    const call = controlerIdentifiant(p.call, "call");
    const a = cx.appels.get(call);
    // EX-6.3 : un finAppel sans debutAppel connu (de cette connexion) est refusé.
    if (!a) throw new ErreurEntree("call_inconnu");
    const is_error = controlerBooleen(p.is_error, "is_error");
    const duration_ms = controlerDuree(p.duration_ms);
    const resultat = p.result === undefined ? null : p.result;
    const hote = cx.hote;
    const ctx = { host: hote.id, request_id: m.idBrut };
    cx.appels.delete(call);
    a.session.appels.delete(call);
    const t0 = this.monotone();
    let pr;
    if (this.redacteur) {
      const x = await this.redacteur.redigerResultat(resultat, { outil: a.capture.tool_announced, alias: a.capture.server_alias, id: m.idBrut, host: hote.id });
      pr = { piece: x.piece, valeurRedigee: x.non_redigeable ? null : x.valeur ?? null, nonRedigeable: x.non_redigeable ?? null };
    } else {
      pr = { piece: pieceJson(resultat), valeurRedigee: resultat, nonRedigeable: null };
    }
    this._quotas(hote).tempsCapture(this.monotone(), this.monotone() - t0);
    const sourceNonRedigeable = a.sourceNonRedigeable || pr.nonRedigeable !== null;
    let evenement = null;
    if (a.passant) {
      this._mettreEnAttente(a, { resultat: pr.piece, resultatRedige: pr.valeurRedigee, duration_ms, is_error, sourceNonRedigeable }, ctx);
    } else {
      try {
        evenement = await this.coeur.terminerRelais(a.relais, {
          resultat: pr.piece,
          resultatRedige: pr.valeurRedigee,
          argumentsRediges: a.argumentsRediges,
          duration_ms,
          is_error,
          sourceNonRedigeable,
          effetsDeclares: a.effets,
        });
        this._quotas(hote).piece(this.monotone(), pr.piece.octets.length);
      } catch (e) {
        if (!(e instanceof ErreurEnregistreur)) throw e;
        if (a.observation) {
          // Mode observation (EX-14.16) : jamais -31017 ; l'événement est en attente, ou perdu.
          if (e.code !== CODES.NON_DURABLE) this.coeur.politique.consignerPerte(e.raison ?? "attente", 1, ctx);
          a.blocagesEvites.push(e.raison ?? "stockage");
        } else {
          this.journal.consigner("error", "sdk", "call_blocked", { code: CODES.NON_DURABLE, reason: e.raison }, ctx);
          this.metriques.compter("noortrace_calls_blocked_total", { code: String(CODES.NON_DURABLE), reason: e.raison ?? "", class: a.classe });
          throw new Rendu(reponseErreur(m.idBrut, CODES.NON_DURABLE, { intent_id: a.relais?.intention?.intent_id ?? null, reason: e.raison }));
        }
      }
    }
    this.journal.consigner(
      "info",
      "sdk",
      "sdk_call_finished",
      { tool_announced: a.capture.tool_announced, intent_id: a.relais?.intention?.intent_id ?? null, result_sha256: pr.piece.sha256, duration_ms, is_error, pending: evenement === null },
      { seq: evenement?.seq ?? null, host: hote.id, request_id: m.idBrut },
    );
    this.metriques.observer("noortrace_relay_latency_ms", { path: "sdk", class: a.classe }, Math.max(0, a.dureeDebut + this.monotone() - m.t_recu));
    if (a.observation) {
      const moteur = this.coeur.politique;
      moteur.compterMarque(a.observation.would);
      for (const raison of [...new Set(a.blocagesEvites)]) {
        moteur.consignerBlocageEvite({ would: a.observation.would, raison, alias: a.capture.server_alias, nom: a.capture.tool_announced, classe: a.classe, seq: evenement?.seq ?? null, host: hote.id, request_id: m.idBrut });
      }
    }
    // Événement en attente (14.5) : il n'a encore ni `seq` ni `hash` (lecture du LISEZMOI).
    return { seq: evenement?.seq ?? null, hash: evenement?.hash ?? null };
  }

  /** Lecture passante en mode dégradé « stockage » (EX-14.8), ou observation (EX-14.16) : événement en attente. */
  _mettreEnAttente(a, r, ctx) {
    const c = a.capture;
    const effets = a.effets ?? evaluerEffets({
      gabarit: null,
      classe: a.classe,
      alias: c.server_alias,
      nomOrigine: c.tool_original,
      arguments: a.argumentsRediges,
      resultat: r.resultatRedige,
      sourceNonRedigeable: r.sourceNonRedigeable,
    }).effets;
    const partiel = partielAppelOutil({
      delegation: c.delegation,
      code: { model: c.code.model, prompt_version: c.code.prompt_version, policy_version: this.coeur.versionPolitique, recorder: VERSION_ENREGISTREUR },
      intent: c.intent,
      tool: c.tool_announced,
      arguments: c.arguments,
      context: c.context,
      nomRedaction: this.coeur.nomRedaction,
      policy: { rule: a.reponse.rule ?? null, decision: "autorise", ticket: null },
      approval: null,
      status: "executee",
      result: r.resultat.reference,
      duration_ms: r.duration_ms,
      is_error: r.is_error,
      effects: effets,
    });
    try {
      const captured_at = this.coeur.politique?.instantCapture() ?? this.coeur.horlogeBrute.murale();
      const id = this.coeur.mettreEnAttente(partiel, [...a.piecesEnAttente, r.resultat], { captured_at, host: a.session.hote.id, genre: "appel" });
      this.journal.consigner("warning", "sdk", "call_passthrough_pending", { pending_id: id }, ctx);
    } catch (e) {
      if (!(e instanceof ErreurEnregistreur)) throw e;
      if (a.observation) this.coeur.politique.consignerPerte(e.raison ?? "attente", 1, ctx);
      else this.journal.consigner("error", "sdk", "event_lost", { reason: e.raison }, ctx);
    }
  }

  // ---------------------------------------------------------------- echangeModele

  async _echangeModele(cx, m) {
    const p = controlerParametres("echangeModele", m.params);
    const s = this._session(cx, p.session);
    const hote = cx.hote;
    if (!FORMATS_SDK.includes(p.format)) throw new ErreurEntree("format_hors_forme");
    if (typeof p.provider_label !== "string" || !MOTIF_LIBELLE.test(p.provider_label)) throw new ErreurEntree("provider_label_hors_forme");
    const status = controlerStatut(p.status);
    const duration_ms = controlerDuree(p.duration_ms);
    const is_error = controlerBooleen(p.is_error, "is_error");
    if (p.format === "gemini") {
      const r = p.response;
      const objet = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
      if (!objet(r) && !(Array.isArray(r) && r.every(objet))) throw new ErreurEntree("response_hors_forme");
    }
    const ctx = { host: hote.id, request_id: m.idBrut };
    // Colonne M de 14.2 pour un échange déclaré (lecture du LISEZMOI) : bloquant, sauf stockage
    // avec `failure.modele: "passant"` et mode observation, où l'événement est mis en attente.
    const raisons = this.coeur.intervention || !this.coeur.ecrivain ? ["stockage"] : this.coeur.degrade.raisons().filter((x) => x !== "approbation");
    let enAttente = false;
    if (raisons.length) {
      if (this.observation) enAttente = true;
      else if (raisons.every((x) => x === "stockage") && this.config.policy.failure?.modele === "passant") enAttente = true;
      else throw new Rendu(this._bloque(m, hote, raisons[0], "modele"));
    }
    const t0 = this.monotone();
    const d = await deriverEchangeSdk({
      format: p.format,
      provider_label: p.provider_label,
      request: p.request,
      response: p.response,
      status,
      is_error,
      model: this.config.model,
      nomPrompt: hote.prompt_version_name ?? null,
      redacteur: this.redacteur,
      admettreValeurLigne: this.redacteur?.admettreValeurLigne ? (v) => this.redacteur.admettreValeurLigne(v) : undefined,
      consigner: (evenement, data) => this.journal.consigner(evenement === "sdk_member_removed" ? "info" : "warning", "sdk", evenement, data, ctx),
      ctx,
    });
    this._quotas(hote).tempsCapture(this.monotone(), this.monotone() - t0);
    // EX-7.7 : context[0] porte la pièce de déclaration de source du SDK.
    const source = pieceDeclarationSource("sdk", hote.alias);
    const pieces = [...d.pieces, source];
    // Registre de corrélation (5.6) : échange déclaré, jamais préféré à un échange interposé (EX-5.22).
    let entree = null;
    if (this.correlateur && p.format !== "autre" && d.formeClair !== null) {
      entree = this.correlateur.inscrire({ host: hote, host_group: hote.host_group, run_id: s.delegation.run_id, format: p.format, formeClair: d.formeClair, interpose: false });
      this.correlateur.completer(entree, { formeRedigee: d.formeRedigee, code: d.code });
    }
    const c = {
      delegation: s.delegation,
      code: d.code,
      intent: d.intent,
      requete: d.requete,
      reponse: d.reponse,
      duration_ms,
      is_error: d.is_error,
      context: [source.referenceContexte("autre")],
      host: hote.id,
    };
    let evenement = null;
    if (enAttente) {
      this._echangeEnAttente(c, pieces, ctx);
    } else {
      try {
        await this._ecrirePieces(hote, pieces);
        evenement = await this.coeur.scellerEchange(c);
      } catch (e) {
        if (!(e instanceof ErreurEnregistreur || e instanceof ErreurConstruction)) throw e;
        if (!this.observation) throw new Rendu(this._bloque(m, hote, e.raison ?? "stockage", "modele"));
        this._echangeEnAttente(c, pieces, ctx);
      }
    }
    if (entree && evenement) this.correlateur.sceller(entree, evenement.seq);
    this.journal.consigner(
      "info",
      "sdk",
      "sdk_exchange_declared",
      { format: p.format, provider: p.provider_label, model: d.code.model, status, removed: d.retires, pieces: { request: d.requete.sha256, response: d.reponse.sha256, system_prompt: d.prompt?.sha256 ?? null, intent: d.intention?.sha256 ?? null } },
      { seq: evenement?.seq ?? null, host: hote.id, request_id: m.idBrut },
    );
    return { seq: evenement?.seq ?? null, hash: evenement?.hash ?? null };
  }

  _echangeEnAttente(c, pieces, ctx) {
    const { host: _h, ...sansHote } = c;
    const partiel = {
      delegation: { ...sansHote.delegation },
      code: { model: c.code.model, prompt_version: c.code.prompt_version, policy_version: this.coeur.versionPolitique, recorder: VERSION_ENREGISTREUR },
      intent: c.intent ?? null,
      policy: { rule: null, decision: "sans_objet", ticket: null, redaction: null },
      approval: null,
      execution: { tool: "noortrace.modele.echange", arguments: c.requete, status: "executee", result: c.reponse, duration_ms: c.duration_ms, is_error: c.is_error },
      effects: [],
      context: c.context,
    };
    const refs = [c.requete, c.reponse, ...(typeof c.intent === "object" && c.intent ? [c.intent] : []), ...c.context];
    partiel.policy.redaction = refs.some((r) => r.redacted === true) ? this.coeur.nomRedaction : null;
    try {
      const id = this.coeur.mettreEnAttente(partiel, pieces, { captured_at: this.coeur.politique?.instantCapture() ?? this.coeur.horlogeBrute.murale(), host: c.host, genre: "echange" });
      this.journal.consigner("warning", "sdk", "call_passthrough_pending", { pending_id: id, kind: "echange_modele" }, ctx);
    } catch (e) {
      if (!(e instanceof ErreurEnregistreur)) throw e;
      if (this.observation) this.coeur.politique.consignerPerte(e.raison ?? "attente", 1, ctx);
      else this.journal.consigner("error", "sdk", "exchange_lost", { reason: e.raison }, ctx);
    }
  }

  // ---------------------------------------------------------------- fermer

  async _fermer(cx, m) {
    const p = controlerParametres("fermer", m.params);
    const s = this._session(cx, p.session);
    await this._clore(s, "fermer", m.idBrut);
    return {};
  }

  /**
   * Clôt une session (6.2 `fermer`, EX-6.13) : chaque `debutAppel` qui a écrit
   * une intention (classe `ecriture`, ou approuvé) sans `finAppel` donne
   * l'événement de reprise (EX-12.15), le démon tournant ; un `debutAppel` de
   * lecture non soumis à approbation n'en donne aucun (13.5).
   */
  async _clore(s, raison, request_id = null) {
    if (s.close) return;
    s.close = true;
    s.cx.sessions.delete(s.id);
    let reprises = 0;
    for (const [call, a] of [...s.appels]) {
      s.appels.delete(call);
      s.cx.appels.delete(call);
      if (!a.relais?.intention) continue;
      try {
        const e = await this.coeur.reprendreRelais(a.relais);
        if (e) reprises++;
      } catch (err) {
        // L'intention reste ouverte : la relecture du journal d'intention la reprendra au démarrage.
        this.journal.consigner("error", "sdk", "sdk_recovery_deferred", { intent_id: a.relais.intention.intent_id, reason: err?.raison ?? "stockage" }, { host: s.hote.id });
      }
    }
    this.journal.consigner("info", "sdk", "sdk_session_closed", { session: s.id, reason: raison, recovered: reprises }, { host: s.hote.id, request_id });
  }
}

/**
 * Pièce de contexte sans rédacteur (8.2, EX-8.7) : un document JSON est
 * l'objet JCS intégral, `media_type: application/json` ; tout autre, ses
 * octets avec le type de média déclaré normalisé.
 * @param {Uint8Array} octets
 * @param {string|null} media_type
 * @returns {Piece}
 */
export function contexteSansRedaction(octets, media_type) {
  const t = typeof media_type === "string" ? media_type.split(";")[0].trim().toLowerCase() : "";
  if (t === "application/json" || /\+json$/.test(t)) {
    try {
      return pieceJson(analyserJsonIntegral(octets), { media_type: "application/json" });
    } catch {
      // document déclaré JSON qui ne s'analyse pas : octets tels quels (EX-8.7)
    }
  }
  if (t === "text/plain") {
    try {
      return pieceTexte(new TextDecoder("utf-8", { fatal: true }).decode(octets));
    } catch {
      // octets non UTF-8
    }
  }
  return new Piece(octets, { redacted: false, media_type: typeMediaNormalise(media_type) });
}

