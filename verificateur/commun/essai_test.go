package commun

import (
	"fmt"
	"testing"
)

// TestControlesSansValeur : EX-6.25 (CT-6 6.10, complément du 2026-11-19).
func TestControlesSansValeur(t *testing.T) {
	tous := [9]bool{false, true, true, true, true, true, true, true, true}
	av := func(id, v string) Avertissement { return Avertissement{ID: id, Verification: v} }
	essai := "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
	reel := "0x00000000000000000000000000000000000000aa"
	reel2 := "0x00000000000000000000000000000000000000bb"
	cas := []struct {
		nom     string
		reussi  [9]bool
		avert   []Avertissement
		appro   []string
		requis  int64
		attendu string
	}{
		{"aucune pièce d'essai", tous, nil, []string{reel, reel2}, 2, "[]"},
		{"toutes les pièces d'essai", tous, []Avertissement{av("AV-N-1", "E-8"), av("AV-N-2", "E-9"), av("AV-T-5", "T-7"), av("AV-O-3", "O-5"), av("AV-R-4", "R-4")}, []string{essai}, 1, "[4 5 6 7 8]"},
		{"clé du manifeste seule", tous, []Avertissement{av("AV-N-1", "P-5")}, nil, 0, "[6]"},
		{"clé de chaîne", tous, []Avertissement{av("AV-N-1", "N-4")}, nil, 0, "[8]"},
		{"pièces du point seulement", tous, []Avertissement{av("AV-T-5", "K-7"), av("AV-O-3", "K-9"), av("AV-N-1", "K-3")}, nil, 0, "[]"},
		{"seuil atteint sans le compte d'essai", tous, []Avertissement{av("AV-N-2", "E-9")}, []string{reel, reel2, essai}, 2, "[]"},
		{"seuil atteint grâce au compte d'essai", tous, []Avertissement{av("AV-N-2", "E-9")}, []string{reel, essai}, 2, "[7]"},
		{"contrôle non réussi", [9]bool{}, []Avertissement{av("AV-T-5", "T-7"), av("AV-O-3", "O-5")}, nil, 0, "[]"},
	}
	for _, c := range cas {
		if got := fmt.Sprint(ControlesSansValeur(c.reussi, c.avert, c.appro, c.requis)); got != c.attendu {
			t.Errorf("%s : %s, attendu %s", c.nom, got, c.attendu)
		}
	}
	if !EstCertificatEssai("0x56AE2B379606D0AEE499F5D790F35CC9A41EE6DBC63E511F5F2C5AC73399B568") || EstChaineEssai("noortrace-2124-DEV") || EstChaineEssai("noortrace-9999-test") {
		t.Error("signes : comparaison exacte des identifiants de chaîne, insensible à la casse pour l'hexadécimal")
	}
}
