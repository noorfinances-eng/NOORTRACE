package main

// Garde commune des familles (revue de sécurité de l'étape 8) : une panne
// dans une famille devient une erreur consignée, les familles suivantes sont
// confrontées.

import (
	"strings"
	"testing"
)

func TestRevueProtegerFamille(t *testing.T) {
	rap := NouveauRapport("essai")
	protegerFamille(rap, "essai", func() {
		var v *Value
		_ = len(v.Arr)
	})
	suivante := false
	protegerFamille(rap, "suivante", func() { suivante = true })
	if len(rap.Erreurs) != 1 || !strings.Contains(rap.Erreurs[0], "famille essai : panne interne") || !suivante || rap.ToutConcorde() {
		t.Errorf("erreurs %v, famille suivante exécutée : %v", rap.Erreurs, suivante)
	}
}

// PremiereOccurrence, cas par cas (EX-10.6 ; arbitrage du 14 novembre : la
// forme vaut aussi pour `rate(x[w]) OP n` ; noor_* du nœud du registre, exposé
// dès le démarrage, garde la forme courte).
func TestRevuePremiereOccurrenceUnitaire(t *testing.T) {
	for e, a := range map[string]string{
		`increase(noortrace_events_lost_total[5m]) > 0`:                                                         `(increase(noortrace_events_lost_total[5m]) > 0) or ((noortrace_events_lost_total unless noortrace_events_lost_total offset 5m) > 0)`,
		`increase(noortrace_journal_lignes_total{event="x"}[1d]) > 1`:                                           `(increase(noortrace_journal_lignes_total{event="x"}[1d]) > 1) or ((noortrace_journal_lignes_total{event="x"} unless noortrace_journal_lignes_total{event="x"} offset 1d) > 1)`,
		`sum(increase(noortrace_anchoring_attempts_total[1h])) > 2 * 76`:                                        `sum(((noortrace_anchoring_attempts_total unless noortrace_anchoring_attempts_total offset 1h) or increase(noortrace_anchoring_attempts_total[1h]))) > 2 * 76`,
		`increase(noor_bft_equivocations_total[5m]) > 0`:                                                        `increase(noor_bft_equivocations_total[5m]) > 0`,
		`rate(noortrace_calls_blocked_total[5m]) > 0`:                                                           `(rate(noortrace_calls_blocked_total[5m]) > 0) or ((noortrace_calls_blocked_total unless noortrace_calls_blocked_total offset 5m) > 0)`,
		`(increase(noortrace_x_total[5m]) > 0) or ((noortrace_x_total unless noortrace_x_total offset 5m) > 0)`: `(increase(noortrace_x_total[5m]) > 0) or ((noortrace_x_total unless noortrace_x_total offset 5m) > 0)`,
	} {
		if got := PremiereOccurrence(e); got != a {
			t.Errorf("%s :\n obtenu  %s\n attendu %s", e, got, a)
		}
	}
}

// SV-6 : le seuil de la configuration modifiée remplace le défaut à chacune
// de ses occurrences ; une règle composée en forme « première occurrence »
// (fichier de référence régénéré, EX-10.6) porte la borne deux fois.
func TestRevueSV6SeuilFormeLongue(t *testing.T) {
	longue := `((noortrace_anchoring_d_registre_s_count unless noortrace_anchoring_d_registre_s_count offset 1h) or increase(noortrace_anchoring_d_registre_s_count[1h])) - ignoring (le) ((noortrace_anchoring_d_registre_s_bucket{le=~"60(\\.0)?"} unless noortrace_anchoring_d_registre_s_bucket{le=~"60(\\.0)?"} offset 1h) or increase(noortrace_anchoring_d_registre_s_bucket{le=~"60(\\.0)?"}[1h])) > 0`
	got := remplacerSeuil(longue, [2]string{`le=~"60(`, `le=~"120(`})
	if strings.Contains(got, `le=~"60(`) || strings.Count(got, `le=~"120(`) != 3 {
		t.Errorf("seuil remplacé en partie : %s", got)
	}
}
