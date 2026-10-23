package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Les vecteurs publiés dans le répertoire parent, s'ils sont présents : tout
// doit concorder (EX-A.10). Une discordance fait échouer le test comme elle
// fait rendre 1 à « go run . .. ».
func TestVecteursPublies(t *testing.T) {
	if _, err := os.Stat(filepath.Join("..", "constantes.json")); err != nil {
		t.Skip("vecteurs CT-3 absents")
	}
	r := VerifierVecteurs("..")
	for _, e := range r.Erreurs {
		t.Errorf("erreur : %s", e)
	}
	for _, c := range r.Comparaisons {
		if !c.Concorde && !c.HorsPerimetre {
			t.Errorf("[%s] %s — %s : attendu %s, recalculé %s (%s)", c.Famille, c.Vecteur, c.Grandeur, tronquer(c.Attendu, 300), tronquer(c.Obtenu, 300), c.Fondement)
		}
	}
	rec, con, _, _ := r.Comptes("")
	if rec < 3000 || con == 0 {
		t.Errorf("trop peu de valeurs recalculées : %d", rec)
	}
}
