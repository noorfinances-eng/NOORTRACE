// Revue de sécurité interne de l'étape 8 : constat EX-10.10, part de
// l'enregistreur (CT-2 §17.2 ; CT-8 §10.3). Les compteurs du démon dont les
// étiquettes sont énumérées par le texte ou par la configuration sont exposés
// à 0 dès le démarrage : une règle `increase(x[w]) > 0` voit alors la première
// occurrence (une série qui naît à 1 n'a pas d'échantillon antérieur).

import { expect } from "chai";
import * as E from "@noortrace/enregistreur";
import { configurationDev, repertoireTemporaire, secretsDev } from "./fixtures/enregistreur-coeur/outils.mjs";

const enc = (c) => new Uint8Array(Buffer.from(JSON.stringify(c)));

/** Séries d'un nom dans l'exposition texte : `{ étiquettes → valeur }`. */
function series(texte, nom) {
  const r = new Map();
  for (const ligne of texte.split("\n")) {
    const m = new RegExp(`^${nom}(\\{[^}]*\\})? ([0-9.e+-]+)$`).exec(ligne);
    if (m) r.set(m[1] ?? "", Number(m[2]));
  }
  return r;
}

describe("revue supervision : compteurs à étiquettes énumérées exposés à 0 au démarrage (CT-8 EX-10.10)", function () {
  this.timeout(60000);

  it("Metriques.declarer pose chaque combinaison d'étiquettes à 0 sans écraser une série déjà comptée ; compter puis exposer montre 0 et 1", function () {
    const m = new E.Metriques();
    m.compter("x_total", { a: "1" });
    m.declarer("x_total", "counter", [{ a: "1" }, { a: "2" }]);
    expect(m.valeur("x_total", { a: "1" })).to.equal(1);
    expect(m.valeur("x_total", { a: "2" })).to.equal(0);
    const s = series(m.exposer(), "x_total");
    expect(s.get('{a="1"}')).to.equal(1);
    expect(s.get('{a="2"}')).to.equal(0);
    expect(m.exposer()).to.match(/^# TYPE x_total counter$/m);
  });

  it("au démarrage du démon, /metrics porte à 0 : noortrace_integrity_check_failures_total pour les huit check de 17.2, noortrace_worm_lock_checks_total (verdict × when), noortrace_calls_executed_not_durable_total (lecture, ecriture), les compteurs d'approbation, d'observation et de perte, noortrace_ops_log_dropped_total, noortrace_lease_renew_failures_total{store}, et par serveur d'outils noortrace_upstream_errors_total{kind} et noortrace_tool_definition_changes_total", async function () {
    const dir = repertoireTemporaire("noortrace-revue-supervision-");
    const { config } = configurationDev(dir);
    const serveurs = Object.keys(config.policy.servers);
    expect(serveurs.length).to.be.above(0);
    const c = await E.Coeur.demarrer({ config: E.validerConfiguration(enc(config)).config, secrets: secretsDev() });
    try {
      const texte = c.metriques.exposer();
      const attendu = (nom, combinaisons) => {
        const s = series(texte, nom);
        for (const e of combinaisons) {
          const cle = Object.keys(e).length ? `{${Object.keys(e).sort().map((k) => `${k}="${e[k]}"`).join(",")}}` : "";
          expect(s.has(cle), `${nom}${cle} absente de /metrics`).to.equal(true);
          expect(s.get(cle), `${nom}${cle}`).to.equal(0);
        }
      };
      attendu("noortrace_integrity_check_failures_total", ["relecture", "copie_worm", "configuration_worm", "registre_gels", "manifeste", "signature", "continuite", "signataire"].map((check) => ({ check })));
      attendu("noortrace_worm_lock_checks_total", [{ verdict: "conforme", when: "copie" }, { verdict: "non_conforme", when: "copie" }, { verdict: "conforme", when: "releve" }, { verdict: "non_conforme", when: "releve" }]);
      attendu("noortrace_calls_executed_not_durable_total", [{ class: "lecture" }, { class: "ecriture" }]);
      attendu("noortrace_approval_signals_total", ["en_attente", "refuse", "expire"].map((state) => ({ state })));
      attendu("noortrace_approval_remises_refused_total", ["SG-1", "SG-2", "SG-3", "SG-4", "SG-5", "SG-6", "SG-7"].map((check) => ({ check })));
      attendu("noortrace_approval_relays_refused_total", ["RL-1", "RL-2", "RL-3", "RL-4", "retenue_decidee"].map((check) => ({ check })));
      attendu("noortrace_observation_marks_total", ["autorise", "a_approuver", "refuse", "inconnu"].map((would) => ({ would })));
      const raisons = ["approbation", "politique", "redaction", "quota", "stockage", "cle", "bail", "horloge", "attente"];
      attendu("noortrace_observation_would_block_total", raisons.map((reason) => ({ reason })));
      attendu("noortrace_events_lost_total", raisons.map((reason) => ({ reason })));
      attendu("noortrace_ops_log_dropped_total", [{}]);
      attendu("noortrace_lease_renew_failures_total", [{ store: config.lease.store.type }]);
      attendu("noortrace_calls_blocked_total", [{ code: "-31010", reason: "redaction", class: "lecture" }, { code: "-31010", reason: "redaction", class: "ecriture" }]);
      for (const server of serveurs) {
        attendu("noortrace_tool_definition_changes_total", [{ server }]);
        attendu("noortrace_upstream_errors_total", ["injoignable", "delai", "jsonrpc", "http_4xx", "http_5xx", "flux_incomplet"].map((kind) => ({ server, kind })));
      }
      // Une première occurrence après le démarrage : la série passe de 0 à 1 (increase > 0 la voit).
      c.metriques.compter("noortrace_integrity_check_failures_total", { check: "registre_gels" });
      expect(series(c.metriques.exposer(), "noortrace_integrity_check_failures_total").get('{check="registre_gels"}')).to.equal(1);
    } finally {
      await c.arreter();
    }
  });
});
