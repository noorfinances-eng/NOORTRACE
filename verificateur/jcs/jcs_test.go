package jcs

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/noorfinances-eng/noortrace/verificateur/jsonv"
)

// TestCasLimites rejoue spec/vecteurs/ct-1/jcs/cas-limites.json (CT-1 §4).
func TestCasLimites(t *testing.T) {
	b, err := os.ReadFile("../../spec/vecteurs/ct-1/jcs/cas-limites.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cas []struct {
			Name      string  `json:"name"`
			Input     string  `json:"input"`
			Canonical *string `json:"canonical"`
		} `json:"cas"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cas) == 0 {
		t.Fatal("aucun cas")
	}
	for _, c := range f.Cas {
		v, err := jsonv.Analyser([]byte(c.Input))
		if err != nil {
			if c.Canonical != nil {
				t.Errorf("%s : lecture refusée : %v", c.Name, err)
			}
			continue
		}
		got, err := Canonique(v)
		switch {
		case c.Canonical == nil && err == nil:
			t.Errorf("%s : forme canonique %q, refus attendu", c.Name, got)
		case c.Canonical != nil && err != nil:
			t.Errorf("%s : refusé (%v), attendu %q", c.Name, err, *c.Canonical)
		case c.Canonical != nil && string(got) != *c.Canonical:
			t.Errorf("%s : %q, attendu %q", c.Name, got, *c.Canonical)
		}
	}
}
