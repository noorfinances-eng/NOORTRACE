package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Empreinte écrite par CT-7 (révision 0.2) pour tsa-exposant.cle.pem et
// tsa-exposant.pem (exposant 2³¹ + 1, CT-6 annexe A.9).
const empreinteExposant = "0xa3cfdccaa39200b68d9ce981156cb2a6f461e3808e93bd4b68a4600775f863e4"

// comparaisonsDe rend les comparaisons du rapport dont le vecteur commence
// par prefixe.
func comparaisonsDe(rap *Rapport, prefixe string) []Comparaison {
	var cs []Comparaison
	for _, c := range rap.Comparaisons {
		if strings.HasPrefix(c.Vecteur, prefixe) {
			cs = append(cs, c)
		}
	}
	return cs
}

// EX-A.7 (révision 0.2) : une entrée ct-6 ed25519 se contrôle comme une
// entrée rsa, par spki_sha256, public_key et address nuls. Une entrée qui
// porte la clé brute dans public_key, à la manière de ct-1 et ct-4, est
// refusée.
func TestClesCT6Ed25519ParSPKI(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	racine := t.TempDir()
	cles := filepath.Join(racine, "ct-6", "rfc3161", "cles")
	if err := os.MkdirAll(cles, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cles, "k.cle.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	ct7 := filepath.Join(racine, "ct-7")
	if err := os.MkdirAll(ct7, 0o755); err != nil {
		t.Fatal(err)
	}
	empreinte := Hex0x(SHA256(spki))
	brute := Hex0x(pub)
	cas := []struct {
		nom, entree string
		concorde    bool
	}{
		{"forme d'EX-A.7", `{"source":"ct-6","label":"rfc3161/cles/k.cle.pem","algorithm":"ed25519","public_key":null,"address":null,"spki_sha256":"` + empreinte + `"}`, true},
		{"clé brute dans public_key", `{"source":"ct-6","label":"rfc3161/cles/k.cle.pem","algorithm":"ed25519","public_key":"` + brute + `","address":null,"spki_sha256":null}`, false},
		{"algorithme faux", `{"source":"ct-6","label":"rfc3161/cles/k.cle.pem","algorithm":"rsa","public_key":null,"address":null,"spki_sha256":"` + empreinte + `"}`, false},
	}
	for _, c := range cas {
		if err := os.WriteFile(filepath.Join(ct7, "cles-de-test.json"), []byte(`{"version":0,"keys":[`+c.entree+`]}`), 0o644); err != nil {
			t.Fatal(err)
		}
		rap := NouveauRapport(ct7)
		VerifierClesDeTest(rap, ct7, nil)
		if len(rap.Erreurs) != 0 {
			t.Fatalf("%s : erreurs %v", c.nom, rap.Erreurs)
		}
		cs := comparaisonsDe(rap, "ct-6 ")
		if len(cs) != 3 {
			t.Fatalf("%s : %d comparaison(s) au lieu de 3", c.nom, len(cs))
		}
		tout := true
		for _, x := range cs {
			tout = tout && x.Concorde
		}
		if tout != c.concorde {
			t.Errorf("%s : concordance %v, %+v", c.nom, tout, cs)
		}
	}
	// Vecteurs publiés, s'ils sont présents : la clé privée Ed25519 et son
	// certificat auto-signé ont la même empreinte que le certificat.
	base := filepath.Join("..", "..", "ct-6", "rfc3161", "cles")
	if _, err := os.Stat(filepath.Join(base, "tsa-ed25519.cle.pem")); err == nil {
		var vues []string
		for _, f := range []string{"tsa-ed25519.cle.pem", "tsa-ed25519.pem", "tsa-ed25519-auto-signe.pem"} {
			s, err := spkiDePEM(filepath.Join(base, f))
			if err != nil {
				t.Fatalf("%s : %v", f, err)
			}
			if a := algorithmeDeSPKI(s); a != "ed25519" {
				t.Errorf("%s : algorithme %s", f, a)
			}
			vues = append(vues, Hex0x(SHA256(s)))
		}
		if vues[0] != vues[1] || vues[1] != vues[2] {
			t.Errorf("empreintes Ed25519 différentes : %v", vues)
		}
	}
}

// EX-A.7 (révision 0.2) : une clé privée RSA PKCS#8 d'exposant 2³¹ + 1 se
// lit dans RSAPrivateKey (RFC 8017 A.1.2), sans crypto/x509, et donne le
// SubjectPublicKeyInfo rsaEncryption à paramètres NULL de n et e.
func TestClesCT6ExposantRSA(t *testing.T) {
	cle, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	// Témoin : avec e = 65537, la construction égale celle de crypto/x509.
	derStd, err := x509.MarshalPKCS8PrivateKey(cle)
	if err != nil {
		t.Fatal(err)
	}
	spkiStd, err := x509.MarshalPKIXPublicKey(&cle.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if s, err := spkiDePKCS8(derStd); err != nil || !bytes.Equal(s, spkiStd) {
		t.Fatalf("e = 65537 : %v, SPKI différent de crypto/x509", err)
	}
	// Exposant 2³¹ + 1 : seule la structure compte (n et e), les autres
	// champs de RSAPrivateKey ne sont pas relus.
	e := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 31), big.NewInt(1))
	p, q := cle.Primes[0], cle.Primes[1]
	rsaPriv, err := asn1.Marshal(struct {
		Version                     int
		N, E, D, P, Q, Dp, Dq, Qinv *big.Int
	}{0, cle.N, e, cle.D, p, q, cle.Precomputed.Dp, cle.Precomputed.Dq, cle.Precomputed.Qinv})
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(struct {
		Version    int
		Algorithme identifiantAlgorithme
		Cle        []byte
	}{0, identifiantAlgorithme{oidRSAEncryption, asn1.NullRawValue}, rsaPriv})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		t.Log("crypto/x509 accepte ici l'exposant 2³¹ + 1 ; la lecture de ce module n'en dépend pas")
	}
	spki, err := spkiDePKCS8(der)
	if err != nil {
		t.Fatal(err)
	}
	el, err := elementsDe(spki)
	if err != nil || len(el) != 2 {
		t.Fatalf("SPKI : %v", err)
	}
	attenduAlgo := []byte{0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00}
	if !bytes.Equal(el[0].FullBytes, attenduAlgo) {
		t.Errorf("AlgorithmIdentifier %x : rsaEncryption à paramètres NULL attendu", el[0].FullBytes)
	}
	var bits asn1.BitString
	if _, err := asn1.Unmarshal(el[1].FullBytes, &bits); err != nil || bits.BitLength%8 != 0 {
		t.Fatalf("BIT STRING : %v", err)
	}
	var pubRSA struct{ N, E *big.Int }
	if r, err := asn1.Unmarshal(bits.Bytes, &pubRSA); err != nil || len(r) != 0 {
		t.Fatalf("RSAPublicKey : %v", err)
	}
	if pubRSA.N.Cmp(cle.N) != 0 || pubRSA.E.Cmp(e) != 0 {
		t.Errorf("n ou e différent : e = %v", pubRSA.E)
	}
	if a := algorithmeDeSPKI(spki); a != "rsa" {
		t.Errorf("algorithme %s", a)
	}
	// Un exposant nul est refusé.
	zero, _ := asn1.Marshal(struct {
		Version int
		N, E    *big.Int
	}{0, cle.N, big.NewInt(0)})
	if _, err := spkiDeClePriveeRSA(zero); err == nil {
		t.Error("exposant nul accepté")
	}
	// Vecteurs publiés, s'ils sont présents : l'empreinte écrite par le texte,
	// égale pour la clé privée et pour le certificat.
	base := filepath.Join("..", "..", "ct-6", "rfc3161", "cles")
	if _, err := os.Stat(filepath.Join(base, "tsa-exposant.cle.pem")); err == nil {
		for _, f := range []string{"tsa-exposant.cle.pem", "tsa-exposant.pem"} {
			s, err := spkiDePEM(filepath.Join(base, f))
			if err != nil {
				t.Fatalf("%s : %v", f, err)
			}
			if got := Hex0x(SHA256(s)); got != empreinteExposant {
				t.Errorf("%s : %s au lieu de %s", f, got, empreinteExposant)
			}
		}
	}
}
