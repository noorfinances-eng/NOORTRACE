package main

// Garde commune des familles (revue de sécurité de l'étape 8) : une panne
// dans une famille devient une erreur consignée, les familles suivantes sont
// confrontées.

import (
	"strings"
	"testing"
)

func TestRevueProtegerFamille(t *testing.T) {
	r := NouveauRapport("essai", "essai", "suivante")
	protegerFamille(r, "essai", func() {
		var v *Value
		_ = len(v.Arr)
	})
	suivante := false
	protegerFamille(r, "suivante", func() { suivante = true })
	if len(r.Erreurs) != 1 || !strings.Contains(r.Erreurs[0], "famille essai : panne interne") || !suivante || r.ToutConcorde() {
		t.Errorf("erreurs %v, famille suivante exécutée : %v", r.Erreurs, suivante)
	}
}
