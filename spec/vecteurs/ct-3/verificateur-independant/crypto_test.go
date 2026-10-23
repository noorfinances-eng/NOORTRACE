package main

import (
	"bytes"
	"crypto/sha3"
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

// La permutation est confrontée à SHA3-256 de la bibliothèque standard (même
// Keccak-f[1600], remplissage 0x06) : 0, 1 et 2 blocs, frontière du débit.
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

// Identifiants de CT-3 annexe A.2 et de CT-1 §13.
func TestKeccakIdentifiants(t *testing.T) {
	cas := map[string]string{
		"":                     "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		"assureur-demo":        "a581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
		"journal-approbations": "3bac546e33b4ed1872f0214f92d6fd5333ffe38df9a281e8a49260d426d11ca1",
		"journal-sinistres":    "41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164",
	}
	for e, a := range cas {
		if got := Keccak256([]byte(e)); !bytes.Equal(got, h(a)) {
			t.Errorf("keccak256(%q) = %x", e, got)
		}
	}
}

// Adresses des comptes Hardhat 1 à 4 (CT-3 annexe A.2), dérivées du
// mnémonique par BIP-39 et BIP-32, puis de la clé privée par secp256k1.
func TestComptesHardhat(t *testing.T) {
	graine, err := GraineBIP39("test test test test test test test test test test test junk")
	if err != nil {
		t.Fatal(err)
	}
	attendues := map[string]string{
		"m/44'/60'/0'/0/1": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
		"m/44'/60'/0'/0/2": "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
		"m/44'/60'/0'/0/3": "0x90f79bf6eb2c4f870365e785982e1f101e93b906",
		"m/44'/60'/0'/0/4": "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65",
	}
	for chemin, adr := range attendues {
		prive, err := DeriverBIP32(graine, chemin)
		if err != nil {
			t.Fatal(err)
		}
		a, err := AdresseDePrivee(prive)
		if err != nil {
			t.Fatal(err)
		}
		if Hex0x(a) != adr {
			t.Errorf("%s : %s ≠ %s", chemin, Hex0x(a), adr)
		}
	}
}

// Signature puis recouvrement, sur les deux parités et sur la forme à s
// haut (même adresse, EX-9.3).
func TestSignerRecouvrer(t *testing.T) {
	graine, _ := GraineBIP39("test test test test test test test test test test test junk")
	prive, _ := DeriverBIP32(graine, "m/44'/60'/0'/0/1")
	adr, _ := AdresseDePrivee(prive)
	for i := 0; i < 8; i++ {
		msg := []byte{byte(i), 1, 2, 3}
		sig, err := SignerMessage(prive, msg)
		if err != nil {
			t.Fatal(err)
		}
		s, err := DecoderSignature(sig)
		if err != nil || !s.Canonique() {
			t.Fatalf("signature non canonique : %s", sig)
		}
		got, err := AdresseRecouvree(CondenseEIP191(msg), s)
		if err != nil || got != Hex0x(adr) {
			t.Fatalf("recouvrement : %s ≠ %s (%v)", got, Hex0x(adr), err)
		}
		haut := Signature{R: s.R, S: new(big.Int).Sub(secpN, s.S), V: 55 - s.V}
		got2, err := AdresseRecouvree(CondenseEIP191(msg), haut)
		if err != nil || got2 != got {
			t.Fatalf("forme à s haut : %s ≠ %s", got2, got)
		}
		n, err := NormaliserSignature(haut.Encoder())
		if err != nil || n.Encoder() != sig {
			t.Fatalf("normalisation : %s ≠ %s", n.Encoder(), sig)
		}
	}
}

// Exemple de remise de CT-3 §12.5 : décision du ticket apr-2201 des
// vecteurs CT-1 (journal-sinistres), signée par les comptes Hardhat 1 et 2.
// Les deux signatures, copiées du texte de la spécification, recouvrent les
// deux approbateurs qu'elle nomme, sur D_A recalculé.
func TestExempleRemiseSpecification(t *testing.T) {
	a := ObjetA("approuve",
		"0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164",
		"0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab",
		"0x22a54600beeb4674976033c5a21740dfe45a1886ff1f69082b5c18141efd122d",
		"apr-2201")
	cas := [][2]string{
		{"0x70997970c51812dc3a010c7d01b50e0d17dc79c8", "0x6e8fb398cce443d4b4343245ac27679e1e460c1c441c0115a21055ec4f1dba09588f3b13b0cc7a9e0d8e1f20133ea0aac9eee9b88f8626ec3a6deafaddec41cd1b"},
		{"0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc", "0x5635ca9bfbe1f348e2d67293766fba0d055c9c5b17ddfe2278f4da25ca772cbd79f82642a21e539a1ee256d1056255899c1e8d90938c3c3aeeb0315a4cd687591b"},
	}
	for _, c := range cas {
		s, err := DecoderSignature(c[1])
		if err != nil || !s.Canonique() {
			t.Fatalf("signature non canonique %s", c[1])
		}
		got, err := AdresseVote(a, s)
		if err != nil || got != c[0] {
			t.Errorf("recouvrée %s ≠ %s (%v)", got, c[0], err)
		}
	}
}

// Adresses synthétiques de l'annexe A.2 et de l'exemple d'EX-8.9.
func TestConstantesSynthetiques(t *testing.T) {
	cas := map[string]string{
		"noortrace/vecteurs/ct3/registre": "0xff7a89fa58a8ffa1173eb70799d7c184bf4d7fe1",
		"noortrace/vecteurs/ct3/jeu/1":    "0x35312352c0065a3fc46ce14dba05df3fcee9fbc2",
	}
	for e, a := range cas {
		if got := Hex0x(SHA256Etiquette(e)[:20]); got != a {
			t.Errorf("%s : %s ≠ %s", e, got, a)
		}
	}
	if got := Hex0x(SHA256Etiquette("noortrace/vecteurs/ct3/bloc/1214")); got != "0xbbdda14682d88cba1356b88a3fa30ecf233920d3a15f4caf97dcff023d21fbca" {
		t.Errorf("bloc 1214 : %s", got)
	}
}
