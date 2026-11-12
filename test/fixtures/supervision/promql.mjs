// Évaluateur réduit de PromQL et des tests de `promtool test rules`, pour les
// seules constructions des règles de référence de CT-8 §10 : sélecteurs
// (=, !=, =~, !~), fenêtres, rate, increase, changes, abs, time,
// histogram_quantile, sum/max/min/avg [by (…)], opérateurs arithmétiques et
// de comparaison (sans bool) entre vecteurs et scalaires, on (…) et
// ignoring (…), and et or. Sémantique de Prometheus 3 : fenêtre ouverte à
// gauche (t - d, t], rappel d'un échantillon sur 5 min pour un vecteur
// instantané, extrapolation de rate et increase de promql/functions.go,
// clause `for` des règles d'alerte.
//
// Ce n'est pas promtool : il sert à éprouver, sans réseau, que chaque cas de
// tests-regles.yml rend l'issue attendue ; promtool 3.5.0 reste l'arbitre
// (CT-8 EX-10.10, EX-A.27).

const DUREES = { ms: 0.001, s: 1, m: 60, h: 3600, d: 86400, w: 604800, y: 31536000 };

/** Durée de Prometheus (« 5m », « 1h30m », « 7800s ») en millisecondes. */
export function dureeMs(t) {
  let total = 0;
  let reste = String(t);
  while (reste.length) {
    const m = /^([0-9]+)(ms|s|m|h|d|w|y)/.exec(reste);
    if (!m) throw new Error(`durée invalide : ${t}`);
    total += Number(m[1]) * DUREES[m[2]] * 1000;
    reste = reste.slice(m[0].length);
  }
  return total;
}

// ---------------------------------------------------------------------------
// Analyse
// ---------------------------------------------------------------------------

const AGREGATS = new Set(["sum", "max", "min", "avg", "count"]);
const FONCTIONS = new Set(["rate", "increase", "changes", "abs", "time", "histogram_quantile"]);
const PRIORITE = { or: 1, and: 2, unless: 2, "==": 3, "!=": 3, ">": 3, "<": 3, ">=": 3, "<=": 3, "+": 4, "-": 4, "*": 5, "/": 5 };

function lexer(src) {
  const t = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    if (/\s/.test(c)) { i++; continue; }
    if (c === '"') {
      let j = i + 1;
      let v = "";
      while (src[j] !== '"') {
        if (src[j] === "\\") { const e = src[j + 1]; v += e === "n" ? "\n" : e; j += 2; continue; }
        if (j >= src.length) throw new Error("chaîne non terminée");
        v += src[j++];
      }
      t.push({ k: "chaine", v });
      i = j + 1;
      continue;
    }
    const op = /^(==|!=|>=|<=|=~|!~|[-+*/(){}\[\],=<>])/.exec(src.slice(i));
    if (op) { t.push({ k: "op", v: op[1] }); i += op[1].length; continue; }
    const nb = /^[0-9]+(\.[0-9]+)?(e[+-]?[0-9]+)?/i.exec(src.slice(i));
    if (nb) {
      const du = /^[0-9]+(ms|s|m|h|d|w|y)([0-9]+(ms|s|m|h|d|w|y))*/.exec(src.slice(i));
      if (du && du[0].length > nb[0].length) { t.push({ k: "duree", v: dureeMs(du[0]) }); i += du[0].length; continue; }
      t.push({ k: "nombre", v: Number(nb[0]) });
      i += nb[0].length;
      continue;
    }
    const id = /^[A-Za-z_:][A-Za-z0-9_:]*/.exec(src.slice(i));
    if (id) { t.push({ k: "id", v: id[0] }); i += id[0].length; continue; }
    throw new Error(`caractère inattendu : ${src.slice(i, i + 10)}`);
  }
  return t;
}

/** Analyse une expression PromQL du sous-ensemble ; rend l'arbre. */
export function analyser(src) {
  const t = lexer(src);
  let i = 0;
  const voir = () => t[i];
  const prendre = (k, v) => {
    const x = t[i];
    if (!x || (k && x.k !== k) || (v !== undefined && x.v !== v)) throw new Error(`attendu ${v ?? k}, trouvé ${x ? x.v : "fin"} dans ${src}`);
    i++;
    return x;
  };
  const listeNoms = () => {
    prendre("op", "(");
    const n = [];
    while (!(voir().k === "op" && voir().v === ")")) {
      n.push(prendre("id").v);
      if (voir().v === ",") i++;
    }
    prendre("op", ")");
    return n;
  };
  const selecteur = (nom) => {
    const m = [];
    if (nom) m.push({ nom: "__name__", op: "=", v: nom });
    if (voir()?.v === "{") {
      i++;
      while (voir().v !== "}") {
        const n = prendre("id").v;
        const op = prendre("op").v;
        const v = prendre("chaine").v;
        m.push({ nom: n, op, v });
        if (voir().v === ",") i++;
      }
      i++;
    }
    let fenetre = null;
    if (voir()?.v === "[") { i++; fenetre = prendre("duree").v; prendre("op", "]"); }
    return { type: "selecteur", m, fenetre };
  };
  const primaire = () => {
    const x = voir();
    if (x.k === "nombre") { i++; return { type: "nombre", v: x.v }; }
    if (x.k === "op" && x.v === "(") { i++; const e = expr(0); prendre("op", ")"); return e; }
    if (x.k === "op" && x.v === "-") { i++; const e = primaire(); return { type: "binaire", op: "*", g: { type: "nombre", v: -1 }, d: e }; }
    if (x.k === "op" && x.v === "{") return selecteur(null);
    if (x.k === "id") {
      i++;
      if (AGREGATS.has(x.v)) {
        let par = null;
        if (voir().v === "by") { i++; par = listeNoms(); }
        prendre("op", "(");
        const e = expr(0);
        prendre("op", ")");
        if (voir()?.v === "by") { i++; par = listeNoms(); }
        return { type: "agregat", f: x.v, par, e };
      }
      if (FONCTIONS.has(x.v)) {
        prendre("op", "(");
        const args = [];
        while (voir().v !== ")") { args.push(expr(0)); if (voir().v === ",") i++; }
        i++;
        return { type: "fonction", f: x.v, args };
      }
      return selecteur(x.v);
    }
    throw new Error(`terme inattendu ${x.v} dans ${src}`);
  };
  const expr = (min) => {
    let g = primaire();
    for (;;) {
      const x = voir();
      if (!x) break;
      const op = x.k === "op" || x.k === "id" ? x.v : null;
      const p = PRIORITE[op];
      if (p === undefined || p <= min - 1 || p < min) break;
      i++;
      let on = null;
      let ignoring = null;
      if (voir()?.v === "on") { i++; on = listeNoms(); }
      else if (voir()?.v === "ignoring") { i++; ignoring = listeNoms(); }
      const d = expr(p + 1);
      g = { type: "binaire", op, g, d, on, ignoring };
    }
    return g;
  };
  const r = expr(0);
  if (i !== t.length) throw new Error(`reste après l'expression : ${t.slice(i).map((x) => x.v).join(" ")}`);
  return r;
}

// ---------------------------------------------------------------------------
// Séries de promtool
// ---------------------------------------------------------------------------

/** Analyse « nom{a="b", …} » en { étiquettes }. */
export function analyserSerie(s) {
  const m = /^([A-Za-z_:][A-Za-z0-9_:]*)?\s*(\{(.*)\})?$/.exec(s.trim());
  if (!m) throw new Error(`série invalide : ${s}`);
  const et = {};
  if (m[1]) et.__name__ = m[1];
  if (m[3]) {
    for (const p of m[3].matchAll(/([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"((?:[^"\\]|\\.)*)"/g)) et[p[1]] = p[2].replace(/\\(.)/g, "$1");
  }
  return et;
}

/** Développe la notation de promtool (« a+bxn », « a-bxn », « axn », « _ », nombres). */
export function developperValeurs(v) {
  const out = [];
  for (const mot of String(v).trim().split(/\s+/)) {
    if (mot === "_") { out.push(null); continue; }
    let m = /^(_)x([0-9]+)$/.exec(mot);
    if (m) { for (let k = 0; k < Number(m[2]); k++) out.push(null); continue; }
    m = /^([-+]?[0-9.e]+|[-+]?Inf)(?:([-+])([0-9.e]+))?x([0-9]+)$/.exec(mot);
    if (m) {
      const a = Number(m[1].replace("Inf", "Infinity"));
      const b = m[2] ? (m[2] === "-" ? -1 : 1) * Number(m[3]) : 0;
      for (let k = 0; k <= Number(m[4]); k++) out.push(a + b * k);
      continue;
    }
    if (!/^[-+]?([0-9.e]+|Inf)$/.test(mot)) throw new Error(`valeur invalide : ${mot}`);
    out.push(Number(mot.replace("Inf", "Infinity")));
  }
  return out;
}

// ---------------------------------------------------------------------------
// Évaluation
// ---------------------------------------------------------------------------

const RAPPEL_MS = 5 * 60 * 1000;
const cle = (et) => JSON.stringify(Object.keys(et).filter((k) => et[k] !== "").sort().map((k) => [k, et[k]]));
const sansNom = (et) => { const c = { ...et }; delete c.__name__; return c; };

function correspond(et, m) {
  const v = et[m.nom] ?? "";
  switch (m.op) {
    case "=": return v === m.v;
    case "!=": return v !== m.v;
    case "=~": return new RegExp(`^(?:${m.v})$`).test(v);
    case "!~": return !new RegExp(`^(?:${m.v})$`).test(v);
    default: throw new Error(`opérateur ${m.op}`);
  }
}

function extrapoler(ech, debut, fin, compteur, taux) {
  if (ech.length < 2) return null;
  const premier = ech[0];
  const dernier = ech[ech.length - 1];
  let resultat = dernier.v - premier.v;
  if (compteur) {
    let prec = premier.v;
    for (const e of ech.slice(1)) { if (e.v < prec) resultat += prec; prec = e.v; }
  }
  let versDebut = (premier.t - debut) / 1000;
  const versFin = (fin - dernier.t) / 1000;
  const intervalle = (dernier.t - premier.t) / 1000;
  const moyenne = intervalle / (ech.length - 1);
  if (compteur && resultat > 0 && premier.v >= 0) {
    const versZero = intervalle * (premier.v / resultat);
    if (versZero < versDebut) versDebut = versZero;
  }
  const seuil = moyenne * 1.1;
  let etendu = intervalle;
  etendu += versDebut < seuil ? versDebut : moyenne / 2;
  etendu += versFin < seuil ? versFin : moyenne / 2;
  let f = etendu / intervalle;
  if (taux) f /= (fin - debut) / 1000;
  return resultat * f;
}

function quantile(q, seaux) {
  const s = seaux.map((b) => ({ le: b.le === "+Inf" ? Infinity : Number(b.le), n: b.n })).sort((a, b) => a.le - b.le);
  if (!s.length || s[s.length - 1].le !== Infinity) return NaN;
  const total = s[s.length - 1].n;
  if (total === 0) return NaN;
  const rang = q * total;
  let k = s.findIndex((b) => b.n >= rang);
  if (k === s.length - 1) return s.length > 1 ? s[s.length - 2].le : NaN;
  const haut = s[k].le;
  let bas = 0;
  let nBas = 0;
  if (k > 0) { bas = s[k - 1].le; nBas = s[k - 1].n; }
  else if (haut <= 0) return haut;
  const dans = s[k].n - nBas;
  return bas + (haut - bas) * ((rang - nBas) / dans);
}

/**
 * Évalue un arbre à l'instant t (ms) sur des séries [{ et, ech: [{t, v}] }].
 * Rend un scalaire { scalaire: v } ou un vecteur [{ et, v }].
 */
export function evaluer(n, series, t) {
  switch (n.type) {
    case "nombre":
      return { scalaire: n.v };
    case "selecteur": {
      const choisies = series.filter((s) => n.m.every((m) => correspond(s.et, m)));
      if (n.fenetre !== null) return { fenetres: choisies.map((s) => ({ et: s.et, ech: s.ech.filter((e) => e.t > t - n.fenetre && e.t <= t && e.v !== null) })), debut: t - n.fenetre, fin: t };
      const out = [];
      for (const s of choisies) {
        const e = s.ech.filter((x) => x.t <= t && x.t > t - RAPPEL_MS && x.v !== null).pop();
        if (e) out.push({ et: s.et, v: e.v });
      }
      return out;
    }
    case "fonction": {
      if (n.f === "time") return { scalaire: t / 1000 };
      if (n.f === "abs") return evaluer(n.args[0], series, t).map((x) => ({ et: sansNom(x.et), v: Math.abs(x.v) }));
      if (n.f === "histogram_quantile") {
        const q = evaluer(n.args[0], series, t).scalaire;
        const v = evaluer(n.args[1], series, t);
        const groupes = new Map();
        for (const x of v) {
          const et = sansNom(x.et);
          const le = et.le;
          delete et.le;
          const k = cle(et);
          if (!groupes.has(k)) groupes.set(k, { et, seaux: [] });
          groupes.get(k).seaux.push({ le, n: x.v });
        }
        return [...groupes.values()].map((g) => ({ et: g.et, v: quantile(q, g.seaux) })).filter((x) => !Number.isNaN(x.v));
      }
      const r = evaluer(n.args[0], series, t);
      const out = [];
      for (const f of r.fenetres) {
        let v;
        if (n.f === "changes") {
          if (!f.ech.length) continue;
          v = 0;
          for (let k = 1; k < f.ech.length; k++) if (f.ech[k].v !== f.ech[k - 1].v) v++;
        } else {
          v = extrapoler(f.ech, r.debut, r.fin, true, n.f === "rate");
          if (v === null) continue;
        }
        out.push({ et: sansNom(f.et), v });
      }
      return out;
    }
    case "agregat": {
      const v = evaluer(n.e, series, t);
      const groupes = new Map();
      for (const x of v) {
        const et = {};
        for (const k of n.par ?? []) if (x.et[k] !== undefined && x.et[k] !== "") et[k] = x.et[k];
        const k = cle(et);
        if (!groupes.has(k)) groupes.set(k, { et, vs: [] });
        groupes.get(k).vs.push(x.v);
      }
      const f = { sum: (a) => a.reduce((s, x) => s + x, 0), max: (a) => Math.max(...a), min: (a) => Math.min(...a), avg: (a) => a.reduce((s, x) => s + x, 0) / a.length, count: (a) => a.length }[n.f];
      return [...groupes.values()].map((g) => ({ et: g.et, v: f(g.vs) }));
    }
    case "binaire":
      return binaire(n, evaluer(n.g, series, t), evaluer(n.d, series, t));
    default:
      throw new Error(`nœud ${n.type}`);
  }
}

const COMPARAISONS = new Set(["==", "!=", ">", "<", ">=", "<="]);
function calcul(op, a, b) {
  switch (op) {
    case "+": return a + b;
    case "-": return a - b;
    case "*": return a * b;
    case "/": return a / b;
    case "==": return a === b;
    case "!=": return a !== b;
    case ">": return a > b;
    case "<": return a < b;
    case ">=": return a >= b;
    case "<=": return a <= b;
    default: throw new Error(op);
  }
}

function signature(et, n) {
  const c = sansNom(et);
  if (n.on) return cle(Object.fromEntries(n.on.filter((k) => c[k] !== undefined).map((k) => [k, c[k]])));
  for (const k of n.ignoring ?? []) delete c[k];
  return cle(c);
}

function binaire(n, g, d) {
  const sg = g.scalaire !== undefined;
  const sd = d.scalaire !== undefined;
  if (n.op === "and" || n.op === "or") {
    if (sg || sd) throw new Error(`${n.op} entre scalaires`);
    const droite = new Set(d.map((x) => signature(x.et, n)));
    if (n.op === "and") return g.filter((x) => droite.has(signature(x.et, n)));
    const gauche = new Set(g.map((x) => signature(x.et, n)));
    return [...g, ...d.filter((x) => !gauche.has(signature(x.et, n)))];
  }
  const comp = COMPARAISONS.has(n.op);
  if (sg && sd) return { scalaire: comp ? (calcul(n.op, g.scalaire, d.scalaire) ? 1 : 0) : calcul(n.op, g.scalaire, d.scalaire) };
  if (sd || sg) {
    const vec = sd ? g : d;
    const s = sd ? d.scalaire : g.scalaire;
    const out = [];
    for (const x of vec) {
      const r = sd ? calcul(n.op, x.v, s) : calcul(n.op, s, x.v);
      if (comp) { if (r) out.push({ et: x.et, v: x.v }); }
      else out.push({ et: sansNom(x.et), v: r });
    }
    return out;
  }
  const index = new Map();
  for (const x of d) {
    const k = signature(x.et, n);
    if (index.has(k)) throw new Error(`appariement multiple à droite pour ${n.op}`);
    index.set(k, x);
  }
  const out = [];
  for (const x of g) {
    const y = index.get(signature(x.et, n));
    if (!y) continue;
    const r = calcul(n.op, x.v, y.v);
    if (comp) { if (r) out.push({ et: sansNom(x.et), v: x.v }); }
    else {
      const et = sansNom(x.et);
      if (n.on) for (const k of Object.keys(et)) if (!n.on.includes(k)) delete et[k];
      if (n.ignoring) for (const k of n.ignoring) delete et[k];
      out.push({ et, v: r });
    }
  }
  return out;
}

/**
 * Rejoue un groupe de tests de promtool sur des règles.
 * @param {{interval?: string, input_series: {series: string, values: string}[], alert_rule_test: object[]}} groupe
 * @param {{alert: string, expr: string, for?: string, labels: object, annotations: object}[]} regles
 * @param {string} [intervalleEvaluation]
 * @returns {string[]} écarts (vide si le groupe passe)
 */
export function rejouerGroupe(groupe, regles, intervalleEvaluation = "1m") {
  const pas = dureeMs(groupe.interval ?? "1m");
  const series = groupe.input_series.map((s) => ({ et: analyserSerie(s.series), ech: developperValeurs(s.values).map((v, k) => ({ t: k * pas, v })) }));
  const ecarts = [];
  const pasEval = dureeMs(intervalleEvaluation);
  for (const test of groupe.alert_rule_test) {
    const fin = dureeMs(test.eval_time);
    const r = regles.find((x) => x.alert === test.alertname);
    if (!r) { ecarts.push(`${test.alertname} : règle absente`); continue; }
    const arbre = analyser(r.expr);
    const pour = r.for ? dureeMs(r.for) : 0;
    const actives = new Map();
    let declenchees = [];
    for (let t = 0; t <= fin; t += pasEval) {
      const v = evaluer(arbre, series, t);
      if (v.scalaire !== undefined) throw new Error(`${r.alert} : scalaire`);
      const vues = new Set();
      for (const x of v) {
        const et = { ...sansNom(x.et), ...r.labels, alertname: r.alert };
        const k = cle(et);
        vues.add(k);
        if (!actives.has(k)) actives.set(k, { depuis: t, et });
      }
      for (const k of [...actives.keys()]) if (!vues.has(k)) actives.delete(k);
      declenchees = [...actives.values()].filter((a) => t - a.depuis >= pour);
    }
    const obtenues = declenchees.map((a) => cle(a.et) + "|" + cle(r.annotations)).sort();
    const attendues = (test.exp_alerts ?? []).map((a) => cle({ ...a.exp_labels, alertname: test.alertname }) + "|" + cle(a.exp_annotations ?? {})).sort();
    if (JSON.stringify(obtenues) !== JSON.stringify(attendues)) ecarts.push(`${groupe.name ?? "?"} / ${test.alertname} à ${test.eval_time} : attendu ${attendues.join(" ; ") || "aucune alerte"}, obtenu ${obtenues.join(" ; ") || "aucune alerte"}`);
  }
  return ecarts;
}
