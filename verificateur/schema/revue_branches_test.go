package schema

// Essai de la revue de sécurité interne de l'étape 8, suite de
// CT-6 N-1 : mots-clés du validateur sans essai Go qui les déclenche
// (maximum, minLength, minProperties, maxProperties).

import (
	"strings"
	"testing"

	"github.com/noorfinances-eng/noortrace/verificateur/jsonv"
)

// TestMotsClesBornes : CT-6 N-1. Chaque borne a son cas de rejet, et une
// instance dans les bornes est acceptée.
func TestMotsClesBornes(t *testing.T) {
	s, err := jsonv.Analyser([]byte(`{"type":"object","properties":{"n":{"type":"number","maximum":5},"s":{"type":"string","minLength":2}},"minProperties":1,"maxProperties":2}`))
	if err != nil {
		t.Fatal(err)
	}
	v := &validateur{}
	cas := []struct{ doc, erreur string }{
		{`{"n":6}`, "nombre supérieur au maximum 5"},
		{`{"s":"a"}`, "chaîne plus courte que 2"},
		{`{}`, "trop peu de membres"},
		{`{"n":1,"s":"ab","x":0}`, "trop de membres"},
	}
	for _, c := range cas {
		x, err := jsonv.Analyser([]byte(c.doc))
		if err != nil {
			t.Fatal(err)
		}
		err = v.valider(s, x, "", 0)
		if err == nil || !strings.Contains(err.Error(), c.erreur) {
			t.Errorf("%s : %v, attendu « %s »", c.doc, err, c.erreur)
		}
	}
	x, _ := jsonv.Analyser([]byte(`{"n":5,"s":"ab"}`))
	if err := v.valider(s, x, "", 0); err != nil {
		t.Errorf("instance dans les bornes refusée : %v", err)
	}
}
