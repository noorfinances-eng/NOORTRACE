package ancres

import (
	"os"
	"testing"
)

// FuzzAncres : N-1 ne panique sur aucune entrée (CT-6 EX-15.3).
func FuzzAncres(f *testing.F) {
	if b, err := os.ReadFile(repAncres + "/ancres-test.json"); err == nil {
		f.Add(b)
	}
	f.Add([]byte(`{"version":0}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		a, d := AnalyserAncres(b, nil)
		if (a == nil) == (d == nil) {
			t.Fatal("ni ancres ni défaut, ou les deux")
		}
	})
}

// FuzzEntetes : N-2 ne panique sur aucune entrée (CT-6 EX-15.3).
func FuzzEntetes(f *testing.F) {
	if b, err := os.ReadFile("../../spec/vecteurs/ct-6/ots/entetes/chaine-courte.json"); err == nil {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		e, d := AnalyserEntetes(b)
		if (e == nil) == (d == nil) {
			t.Fatal("ni en-têtes ni défaut, ou les deux")
		}
	})
}
