package main

// Corpus de graines de fuzzing (CT-6 EX-15.3, revue de sécurité de l'étape 8) : chaque cible
// Fuzz… du module a un répertoire testdata/fuzz/<cible>/ qui porte au moins
// une graine au format de corpus de Go ; `go test` rejoue ces graines, et
// un contre-exemple trouvé par `go test -fuzz` y est versé par Go lui-même.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ciblesFuzz : paquet et cible, la liste d'EX-15.3 et du LISEZMOI.
var ciblesFuzz = [][2]string{
	{"jsonv", "FuzzAnalyser"}, {"jcs", "FuzzCanonique"},
	{"ancres", "FuzzAncres"}, {"ancres", "FuzzEntetes"},
	{"ots", "FuzzAnalyser"},
	{"registre", "FuzzRegistre"}, {"registre", "FuzzLigne"},
	{"horodatage", "FuzzJeton"}, {"horodatage", "FuzzCertificat"}, {"horodatage", "FuzzCRL"},
}

func TestCorpusDeGrainesEX153(t *testing.T) {
	for _, c := range ciblesFuzz {
		dir := filepath.Join("..", "..", c[0], "testdata", "fuzz", c[1])
		ents, err := os.ReadDir(dir)
		if err != nil || len(ents) == 0 {
			t.Errorf("%s/%s : aucun corpus de graines sous %s (%v)", c[0], c[1], dir, err)
			continue
		}
		for _, e := range ents {
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil || !strings.HasPrefix(string(b), "go test fuzz v1\n") {
				t.Errorf("%s : graine %s hors du format de corpus de Go", dir, e.Name())
			}
		}
	}
}
