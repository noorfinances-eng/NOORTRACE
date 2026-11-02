package jcs

import (
	"testing"

	"github.com/noorfinances-eng/noortrace/verificateur/jsonv"
)

// FuzzCanonique : la forme canonique d'une forme canonique est elle-même
// (idempotence), et le calcul ne panique jamais (CT-6 EX-15.3).
func FuzzCanonique(f *testing.F) {
	for _, s := range []string{`{"b":1,"a":2}`, `{"é":1,"z":2,"Z":3}`, `{"a":"x\u0001y"}`, `{"a":-0}`, `{"a😀":1}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		v, err := jsonv.Analyser(b)
		if err != nil {
			return
		}
		c, err := Canonique(v)
		if err != nil {
			return
		}
		w, err := jsonv.Analyser(c)
		if err != nil {
			t.Fatalf("forme canonique illisible : %q", c)
		}
		c2, err := Canonique(w)
		if err != nil || string(c2) != string(c) {
			t.Fatalf("forme canonique non idempotente : %q, %q", c, c2)
		}
	})
}
