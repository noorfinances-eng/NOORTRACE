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
