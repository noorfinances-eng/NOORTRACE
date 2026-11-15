package main

// Garde commune des familles (revue de sécurité de l'étape 8) : une panne
// dans une famille devient une erreur consignée, les familles suivantes sont
// confrontées.

import (
	"strings"
	"testing"
)

func TestRevueProtegerFamille(t *testing.T) {
	rap := &Rapport{Titre: TitreRapportCT2, Comparaisons: []Comparaison{}, Erreurs: []string{}, Notes: []string{}, Details: []string{}}
	protegerFamille(rap, "essai", func() {
		var v *Value
		_ = len(v.Obj)
	})
	suivante := false
	protegerFamille(rap, "suivante", func() { suivante = true })
	if len(rap.Erreurs) != 1 || !strings.Contains(rap.Erreurs[0], "famille essai : panne interne") || !suivante {
		t.Errorf("erreurs %v, famille suivante exécutée : %v", rap.Erreurs, suivante)
	}
}
