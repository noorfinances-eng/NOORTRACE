// Copié sans modification du vérificateur indépendant CT-1
// (spec/vecteurs/ct-1/verificateur-independant/keccak_test.go).

package main

import (
	"bytes"
	"crypto/sha3"
	"testing"
)

// La permutation est confrontée à SHA3-256 de la bibliothèque standard (même
// Keccak-f[1600], remplissage 0x06), sur des longueurs qui couvrent 0, 1 et 2
// blocs et la frontière du débit.
func TestPermutationContreSHA3(t *testing.T) {
	for _, n := range []int{0, 1, 55, 56, 135, 136, 137, 271, 272, 273, 1000} {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i*7 + 3)
		}
		attendu := sha3.Sum256(data)
		if got := eponge256(data, 0x06); !bytes.Equal(got, attendu[:]) {
			t.Errorf("n = %d : %x ≠ %x", n, got, attendu)
		}
	}
}

func TestKeccak256Connu(t *testing.T) {
	if got := Keccak256(nil); !bytes.Equal(got, h("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")) {
		t.Fatalf("keccak256(\"\") = %x", got)
	}
	if got := Keccak256([]byte("assureur-demo")); !bytes.Equal(got, h("a581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab")) {
		t.Errorf("org_id = %x", got)
	}
	if got := Keccak256([]byte("journal-principal")); !bytes.Equal(got, h("0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b")) {
		t.Errorf("journal_id = %x", got)
	}
	fp := AnchorFingerprint(
		h("a581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab"),
		h("0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b"),
		h("a864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1"))
	if !bytes.Equal(fp, h("3200e496c555b46459191c852a7f79b1e0b4156802cac2f2df7b80b0aa9d823b")) {
		t.Errorf("anchorFingerprint = %x", fp)
	}
}
