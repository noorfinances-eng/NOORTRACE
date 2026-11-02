package cryptographie

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func h(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestKeccak256(t *testing.T) {
	cas := []struct {
		entree []byte
		sortie string
	}{
		{nil, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"},
		{make([]byte, 135), "29e3704feeca7fb9ba229f0fa04d9b36449cf3ad6e1d85d9cfff3a10df9abc3e"},
		{make([]byte, 136), "3a5912a7c5faa06ee4fe906253e339467a9ce87d533c65be3c15cb231cdb25f9"},
		{make([]byte, 300), "347b017cb0632f78c0c51dfedd8e31b8d2c31e5bf282c1e8c370e45ef8b0f7f0"},
		// docType d'une période (CT-6 EX-11.18) et d'un point (CT-1 §10.6).
		{[]byte("noortrace/periode/v0"), "2970f32daf26845541b559f8505ddade17ab51994fab81cbfe0dbd81ab9671ee"},
		{[]byte("noortrace/point-de-controle/v0"), "72c486c933f8fb8fef2c726539023e8fd80113cc0ca89e3fdf1314d553932178"},
		// org_id de CT-1 §13.
		{[]byte("assureur-demo"), "a581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab"},
	}
	for _, c := range cas {
		got := Keccak256(c.entree)
		if hex.EncodeToString(got[:]) != c.sortie {
			t.Errorf("keccak256(%d octets) = %x, attendu %s", len(c.entree), got, c.sortie)
		}
	}
}

// Exemple numérique de CT-1 §6.4 : signature de l'événement seq 4.
func TestEd25519ExempleCT1(t *testing.T) {
	cle := h("e2116fdce7f27ff208971b6c821f9691a4a9a29bc407224eaf0c4b60c1174045")
	b, err := os.ReadFile("testdata/c-seq4.txt")
	if err != nil {
		t.Fatal(err)
	}
	msg := append(append([]byte{}, PrefixeSignatureEvenement...), b...)
	sig := h("cd09159db6ca010502826e1130f1415f3c07e06aa9b663bb47a8ad0bff58d5ebaae96ef204dffc490dc1684386e9d7270256b41f3f2bf4f0b75ec369276cbf00")
	if !VerifierEd25519(cle, msg, sig) {
		t.Fatal("signature de l'exemple refusée")
	}
	if got := Hex32(Sha256(PrefixeEvenement, b)); got != "0x471dab56146ae2e4c678120af7faf5eed7b1f8e5db3657226de97614bde4dc00" {
		t.Errorf("hash de l'exemple : %s", got)
	}
	// S non réduit : S + L refusé.
	l := h("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
	s := make([]byte, 32)
	copy(s, sig[32:])
	retenue := 0
	for i := 0; i < 32; i++ {
		v := int(s[i]) + int(l[i]) + retenue
		s[i] = byte(v)
		retenue = v >> 8
	}
	if VerifierEd25519(cle, msg, append(append([]byte{}, sig[:32]...), s...)) {
		t.Error("S non réduit accepté")
	}
	// Signature altérée.
	sig2 := append([]byte{}, sig...)
	sig2[63] ^= 1
	if VerifierEd25519(cle, msg, sig2) {
		t.Error("signature altérée acceptée")
	}
}

func TestClesEd25519Refusees(t *testing.T) {
	for _, p := range petitOrdre {
		if ClePubliqueEd25519Admise(h(p)) {
			t.Errorf("point de petit ordre admis : %s", p)
		}
	}
	// y ≥ p : encodage non canonique (p = 2^255 - 19, ici y = p).
	nonCanonique := h("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
	if ClePubliqueEd25519Admise(nonCanonique) {
		t.Error("y = p admis")
	}
	if ClePubliqueEd25519Admise(make([]byte, 31)) {
		t.Error("clé de 31 octets admise")
	}
}

// Exemple de CT-1 §6.4 : décision d'approbation, D_A et signatures.
func TestEIP191ExempleCT1(t *testing.T) {
	var d [32]byte
	copy(d[:], h("59b49949b9e97d7e3fd9d46a3992476dd2cc27c48e25ef77b467816d144f37a7"))
	sig1 := h("9b56cadb515c1fc18cc37f5b85bc78be8c916daef1ef9017fb3067f19dbcc8585ae2b338117e554f3ec7faa77bc615c82a17a695a4f76295383d9c931d2648a01b")
	a, err := RecouvrerEIP191(d, sig1)
	if err != nil || Hex(a[:]) != "0x70997970c51812dc3a010c7d01b50e0d17dc79c8" {
		t.Fatalf("recouvrement : %s, %v", Hex(a[:]), err)
	}
	// S haut et v complémenté : même signataire mathématique, refusé
	// (CT-1 §6.3, CT-6 EX-14.2).
	n := h("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
	haut := append([]byte{}, sig1...)
	var emprunt int
	for i := 31; i >= 0; i-- {
		v := int(n[i]) - int(sig1[32+i]) - emprunt
		emprunt = 0
		if v < 0 {
			v += 256
			emprunt = 1
		}
		haut[32+i] = byte(v)
	}
	haut[64] = 27 + 28 - sig1[64]
	if _, err := RecouvrerEIP191(d, haut); err != ErrSignatureNonCanonique {
		t.Errorf("S haut : %v", err)
	}
	mauvaisV := append([]byte{}, sig1...)
	mauvaisV[64] = 0
	if _, err := RecouvrerEIP191(d, mauvaisV); err == nil {
		t.Error("v = 0 accepté")
	}
	if _, err := RecouvrerEIP191(d, sig1[:64]); err == nil {
		t.Error("signature de 64 octets acceptée")
	}
}

func TestBase64Canonique(t *testing.T) {
	if b, err := Base64Canonique("AAE="); err != nil || len(b) != 2 {
		t.Errorf("AAE= : %v", err)
	}
	for _, s := range []string{"AAF=", "AAE", "AA E=", "AAE=\n", "A===", "AAE=AAE="} {
		if _, err := Base64Canonique(s); err == nil {
			t.Errorf("%q accepté", s)
		}
	}
}

// TestMerkle rejoue les preuves d'inclusion de spec/vecteurs/ct-1/merkle
// (CT-1 §9.3) et les preuves de cohérence (CT-1 §10.7).
func TestMerkle(t *testing.T) {
	b, err := os.ReadFile("../../spec/vecteurs/ct-1/merkle/arbres.json")
	if err != nil {
		t.Fatal(err)
	}
	var a struct {
		Arbres []struct {
			Proofs []struct {
				TreeSize  uint64   `json:"tree_size"`
				LeafIndex uint64   `json:"leaf_index"`
				LeafHash  string   `json:"leaf_hash"`
				Path      []string `json:"path"`
				Root      string   `json:"root"`
			} `json:"proofs"`
		} `json:"arbres"`
	}
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, arbre := range a.Arbres {
		for _, p := range arbre.Proofs {
			lh, _ := LireHex(p.LeafHash, 32)
			rt, _ := LireHex(p.Root, 32)
			var ch [][]byte
			for _, x := range p.Path {
				b, _ := LireHex(x, 32)
				ch = append(ch, b)
			}
			if !VerifierInclusion(lh, p.LeafIndex, p.TreeSize, ch, rt) {
				t.Errorf("preuve (%d, %d) refusée", p.LeafIndex, p.TreeSize)
			}
			if len(ch) > 0 && VerifierInclusion(lh, p.LeafIndex, p.TreeSize, ch[:len(ch)-1], rt) {
				t.Errorf("preuve tronquée (%d, %d) acceptée", p.LeafIndex, p.TreeSize)
			}
			n++
		}
	}
	if n == 0 {
		t.Fatal("aucune preuve d'inclusion")
	}
	b, err = os.ReadFile("../../spec/vecteurs/ct-1/merkle/coherence.json")
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Cases []struct {
			Name       string   `json:"name"`
			FirstSize  uint64   `json:"first_size"`
			SecondSize uint64   `json:"second_size"`
			FirstRoot  string   `json:"first_root"`
			SecondRoot string   `json:"second_root"`
			Path       []string `json:"path"`
			Valid      bool     `json:"valid"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	for _, k := range c.Cases {
		fr, _ := LireHex(k.FirstRoot, 32)
		sr, _ := LireHex(k.SecondRoot, 32)
		var ch [][]byte
		for _, x := range k.Path {
			b, _ := LireHex(x, 32)
			ch = append(ch, b)
		}
		if got := VerifierCoherence(k.FirstSize, k.SecondSize, fr, sr, ch); got != k.Valid {
			t.Errorf("%s : %v, attendu %v", k.Name, got, k.Valid)
		}
	}
}

func TestLireHex(t *testing.T) {
	if _, ok := LireHex("0xAB", 1); ok {
		t.Error("majuscules acceptées")
	}
	if _, ok := LireHex("ab", 1); ok {
		t.Error("sans préfixe accepté")
	}
	if b, ok := LireHex("0xab", 1); !ok || b[0] != 0xab {
		t.Error("0xab refusé")
	}
}
