// Copié sans modification du vérificateur indépendant CT-1
// (spec/vecteurs/ct-1/verificateur-independant/crypto_test.go).

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"math/big"
	"testing"
)

func h(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// Vecteur TEST 1 de la RFC 8032 §7.1.
func TestRFC8032Test1(t *testing.T) {
	graine := h("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	pub := h("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	sig := h("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
	if got := ClePubliqueDepuisGraine(graine); !bytes.Equal(got, pub) {
		t.Fatalf("clé publique %x", got)
	}
	if got := ed25519.Sign(ed25519.NewKeyFromSeed(graine), nil); !bytes.Equal(got, sig) {
		t.Fatalf("signature %x", got)
	}
	if err := VerifierEd25519(pub, nil, sig); err != nil {
		t.Fatal(err)
	}
	if err := VerifierEd25519(pub, []byte("x"), sig); err == nil {
		t.Fatal("signature sur un autre message acceptée")
	}
	// S + L n'est pas réduit : refus explicite.
	mauvais := append([]byte{}, sig...)
	s := new(big.Int).SetBytes(inverser(mauvais[32:]))
	s.Add(s, ordreEd25519)
	copy(mauvais[32:], inverser(s.FillBytes(make([]byte, 32))))
	if err := VerifierEd25519(pub, nil, mauvais); err != ErrSNonReduit {
		t.Fatalf("S non réduit : %v", err)
	}
}

// Points de petit ordre (encodages canoniques) : tous refusés.
func TestClesPetitOrdre(t *testing.T) {
	petits := []string{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0000000000000000000000000000000000000000000000000000000000000080",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
	}
	for _, p := range petits {
		if err := ControlerClePubliqueEd25519(h(p)); err != ErrClePetitOrdre {
			t.Errorf("%s : %v", p, err)
		}
	}
	nonCanoniques := []string{
		"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = p
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = p + 1
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // x = 0, signe 1
		"0100000000000000000000000000000000000000000000000000000000000080", // x = 0, signe 1
	}
	for _, p := range nonCanoniques {
		if err := ControlerClePubliqueEd25519(h(p)); err != ErrCleNonCanonique {
			t.Errorf("%s : %v", p, err)
		}
	}
	for _, p := range []string{
		"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
		"e2116fdce7f27ff208971b6c821f9691a4a9a29bc407224eaf0c4b60c1174045",
		"fd08757fa4798c3c8757bbf5a0db49580cbcb80075ddb30f13f881b0f47aacb3",
	} {
		if err := ControlerClePubliqueEd25519(h(p)); err != nil {
			t.Errorf("%s : %v", p, err)
		}
	}
}

// Clés et nonces de test de CT-1 §13.
func TestClesDeTestCT1(t *testing.T) {
	cas := []struct{ id, graine, pub string }{
		{"rec-test-01", "6215c33a2801ef7f21a894e98924eba8d72e3514f5fe7929ce0b595f5d39fa79", "e2116fdce7f27ff208971b6c821f9691a4a9a29bc407224eaf0c4b60c1174045"},
		{"rec-test-02", "4aa9b030b0d9dbc1eb4e2619929bb7ace43b6479678c6162ea467c84a6bda5db", "fd08757fa4798c3c8757bbf5a0db49580cbcb80075ddb30f13f881b0f47aacb3"},
	}
	for _, c := range cas {
		if g := GraineCleTest(c.id); !bytes.Equal(g, h(c.graine)) {
			t.Errorf("%s graine %x", c.id, g)
		}
		if p := ClePubliqueDepuisGraine(h(c.graine)); !bytes.Equal(p, h(c.pub)) {
			t.Errorf("%s clé publique %x", c.id, p)
		}
	}
	if n := NonceTest("periode-1"); !bytes.Equal(n, h("cfcd0a8277074d0839e4469fdced701c0fdf2855f1001e17d3fada335da05547")) {
		t.Errorf("nonce période 1 %x", n)
	}
	if n := NonceTest("periode-2"); !bytes.Equal(n, h("2b2b0095b99b60b2b3baae78815fd1590b4c01c6e63304ab0a682e5f6270f86d")) {
		t.Errorf("nonce période 2 %x", n)
	}
}

func TestPrefixesAnnexeB(t *testing.T) {
	cas := map[string][]byte{
		"6e6f6f7274726163652f6576656e656d656e742f76300a":                     PrefixeEvenement,
		"6e6f6f7274726163652f7369676e61747572652d6576656e656d656e742f76300a": PrefixeSignatureEvenement,
		"6e6f6f7274726163652f6d616e6966657374652f76300a":                     PrefixeManifeste,
		"6e6f6f7274726163652f7369676e61747572652d6d616e6966657374652f76300a": PrefixeSignatureManifeste,
		"6e6f6f7274726163652f617070726f626174696f6e2f76300a":                 PrefixeApprobation,
		"6e6f6f7274726163652f7369676e61747572652d726f746174696f6e2f76300a":   PrefixeSignatureRotation,
	}
	for hx, p := range cas {
		if !bytes.Equal(h(hx), p) {
			t.Errorf("préfixe %x ≠ %s", p, hx)
		}
	}
}

func TestEstHex(t *testing.T) {
	if !EstHex(Zero32, 32) || EstHex("0x0A", 1) || EstHex("0x", 1) || !EstHex("0x", -1) || EstHex("0xabc", -1) || EstHex("ab", -1) {
		t.Fatal("EstHex")
	}
}
