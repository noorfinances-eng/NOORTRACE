package main

// Garde commune des familles (revue de sécurité de l'étape 8) : une panne
// dans une famille devient une erreur consignée (discordance), les familles
// suivantes sont confrontées.

import (
	"strings"
	"testing"
)

func TestRevueProtegerFamille(t *testing.T) {
	c := &Ctx{R: NouveauRapport("essai")}
	c.protegerFamille("essai", func() {
		var v *Value
		_ = len(v.Arr)
	})
	suivante := false
	c.protegerFamille("suivante", func() { suivante = true })
	f := c.R.F("essai")
	if f.Discordantes != 1 || !strings.Contains(f.Discordances[0].Recalcule, "panne interne") || !suivante || c.R.ToutConcorde() {
		t.Errorf("discordances %v, famille suivante exécutée : %v", f.Discordances, suivante)
	}
}
