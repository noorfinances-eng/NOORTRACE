package main

import (
	"bytes"
	"crypto/sha3"
	"math/big"
	"os"
	"strings"
	"testing"
)

// Keccak-f[1600] confronté à SHA3-256 de la bibliothèque standard (même
// permutation, remplissage 0x06), et keccak256("") de référence.
func TestKeccak(t *testing.T) {
	for _, n := range []int{0, 1, 135, 136, 137, 272, 1000} {
		d := make([]byte, n)
		for i := range d {
			d[i] = byte(i*13 + 7)
		}
		attendu := sha3.Sum256(d)
		if got := eponge256(d, 0x06); !bytes.Equal(got, attendu[:]) {
			t.Fatalf("n = %d : %x ≠ %x", n, got, attendu)
		}
	}
	if got := Hex0x(Keccak256(nil)); got != "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" {
		t.Fatal(got)
	}
}

// Cas limites de la forme canonique (CT-1 §4).
func TestJCS(t *testing.T) {
	cas := []struct{ entree, canonique string }{
		{`{"b":1,"a":2}`, `{"a":2,"b":1}`},
		{`{"é":1,"z":2,"Z":3}`, `{"Z":3,"z":2,"é":1}`},
		{`{"a😀":1}`, `{"a😀":1}`},
		{`{"a":"x\u0001y"}`, `{"a":"x\u0001y"}`},
		{`{"a":"\u007f"}`, "{\"a\":\"\x7f\"}"},
		{`{"a":"/"}`, `{"a":"/"}`},
		{`{"a":-0}`, `{"a":0}`},
		{`{"a":[],"b":{}}`, `{"a":[],"b":{}}`},
		{`{"a":" <>&"}`, "{\"a\":\" <>&\"}"},
		{`{"a":1.0}`, ""},
		{`{"a":1e3}`, ""},
		{`{"a":9007199254740993}`, ""},
		{`{"a":"\ud800"}`, ""},
		{`{"a":1,"a":2}`, ""},
	}
	for _, c := range cas {
		v, err := AnalyserJSONStrict([]byte(c.entree))
		if c.canonique == "" {
			if err == nil {
				t.Errorf("%s accepté", c.entree)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s : %v", c.entree, err)
		}
		got, err := Canonique(v)
		if err != nil || string(got) != c.canonique {
			t.Errorf("%s → %s (%v), attendu %s", c.entree, got, err, c.canonique)
		}
	}
}

// Motifs que RE2 n'accepte pas tels quels : bornes exactes respectées.
func TestMotifsLongs(t *testing.T) {
	re, err := CompilerMotif(`^0x([0-9a-f]{2}){32,4096}$`)
	if err != nil {
		t.Fatal(err)
	}
	for n, ok := range map[int]bool{31: false, 32: true, 33: true, 4096: true, 4097: false} {
		if got := re.MatchString("0x" + strings.Repeat("ab", n)); got != ok {
			t.Errorf("%d octets : %v", n, got)
		}
	}
	if re.MatchString("0x" + strings.Repeat("ab", 40) + "a") {
		t.Error("nombre impair de chiffres accepté")
	}
	re, err = CompilerMotif(`^/[^\u0000]{1,4095}$`)
	if err != nil {
		t.Fatal(err)
	}
	if !re.MatchString("/"+strings.Repeat("é", 4095)) || re.MatchString("/"+strings.Repeat("a", 4096)) || re.MatchString("/a\x00b") || re.MatchString("/") {
		t.Error("bornes de ^/[^\\u0000]{1,4095}$")
	}
	re, _ = CompilerMotif(`^https?://[^\s]+$`)
	if re.MatchString("https://a b") || !re.MatchString("https://a.b/c") {
		t.Error("\\s d'ECMAScript")
	}
}

// Instants de CT-1 §3 : date du calendrier, jamais renormalisée.
func TestInstants(t *testing.T) {
	for s, ok := range map[string]bool{
		"2027-02-30T00:00:00.000Z": false,
		"2026-02-29T00:00:00.000Z": false,
		"2028-02-29T00:00:00.000Z": true,
		"2026-11-02T08:00:00.000Z": true,
		"2026-11-02T24:00:00.000Z": false,
		"2026-11-02T08:00:60.000Z": false,
		"2026-11-02T08:00:00Z":     false,
	} {
		if _, got := AnalyserInstant(s); got != ok {
			t.Errorf("%s : %v", s, got)
		}
	}
}

// Comptes Hardhat du mnémonique public (BIP-39, BIP-32).
func TestComptes(t *testing.T) {
	cles, err := Comptes("test test test test test test test test test test test junk", 5)
	if err != nil {
		t.Fatal(err)
	}
	attendus := []string{
		"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
		"0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
		"0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
		"0x90f79bf6eb2c4f870365e785982e1f101e93b906",
		"0x15d34aaf54267db7d7c367839aaf71a00a2c6a65",
	}
	for i, k := range cles {
		a, _ := AdresseDePrivee(k)
		if Hex0x(a) != attendus[i] {
			t.Errorf("compte %d : %s", i, Hex0x(a))
		}
	}
}

// Exemple numérique de CT-7 §7.2, valeurs recopiées du texte.
func TestExemple72(t *testing.T) {
	b, err := os.ReadFile("../attestations/exemple/attestation.json")
	if err != nil {
		t.Skip("vecteurs absents")
	}
	p, err := AnalyserJSONStrict(b)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := Canonique(p)
	dp, _ := CondenseAttestation(p)
	m := MessageEIP191(dp)
	if len(c) != 3201 || Hex0x(dp) != "0x4481a2e47712539c4ca50f2eea3d6062ec11a70d497c153c1a6f707606657cfd" || Hex0x(m) != "0x6a4450a8f1729139886741854c27c710dc468ef6888ad3260a5574718d14f790" {
		t.Fatalf("JCS %d octets, D_P %x, M %x", len(c), dp, m)
	}
	cles, _ := Comptes("test test test test test test test test test test test junk", 4)
	attendues := map[int]string{
		1: "0x77cd5463cb88d5e9327bc0f31aecde620267a3a2267efd3cbf18839a57955af1793571375853490a4d494f5eaf28a90812ac70c8fae00d18a7d1edb372ee44f11c",
		2: "0x7d80f09897a9661ecd568bd94ccd75d0b53381566aa77c108b28cafa6b6bdc617ad35c56e5976232b50568f40b3901bb7d19d5e8be3d14bccd76c1b283e5f26f1c",
		3: "0x3daebe7960d9870ebf2d5a03492283474286dbf28f7e53f20b51ba60f6e01cd603332971435717c899b12c9dd0a37aa7704e9500645a67732f7821eaf034648b1c",
	}
	for i, s := range attendues {
		got, _ := Signer(cles[i], m)
		if got != s {
			t.Errorf("compte %d : %s", i, got)
		}
		a, _ := AdresseDePrivee(cles[i])
		if rec, err := RecouvrerAdresse(m, s); err != nil || rec != Hex0x(a) {
			t.Errorf("compte %d : recouvrement %s %v", i, rec, err)
		}
	}
}

func chargerSchemaTest(t *testing.T, nom string) *Schema {
	b, err := os.ReadFile("../../../schemas/" + nom + ".schema.json")
	if err != nil {
		t.Skip("schéma absent")
	}
	s, err := ChargerSchema(nom, b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Mutations du procès-verbal de 5.10 faites ici, signées à nouveau par les
// comptes de test : seule la vérification visée échoue.
func TestMutationsCeremonie(t *testing.T) {
	sch := chargerSchemaTest(t, "ceremonie-cles-v0")
	b, err := os.ReadFile("../ceremonies/valide-creation-enregistreur/proces-verbal.json")
	if err != nil {
		t.Skip("vecteurs absents")
	}
	cles, _ := Comptes("test test test test test test test test test test test junk", 5)
	parAdr := map[string][]byte{}
	for _, k := range cles {
		a, _ := AdresseDePrivee(k)
		parAdr[Hex0x(a)] = k
	}
	resigner := func(texte string) []byte {
		pv, err := AnalyserJSON([]byte(texte))
		if err != nil {
			t.Fatal(err)
		}
		dc, err := CondenseCeremonie(pv)
		if err != nil {
			t.Fatal(err)
		}
		adr := map[string]string{}
		for _, p := range pv.Get("participants").Arr {
			adr[p.Get("id").Str] = p.Get("address").Str
		}
		for _, s := range pv.Get("signatures").Arr {
			sig, _ := Signer(parAdr[adr[s.Get("participant").Str]], MessageEIP191(dc))
			s.Get("signature").Str = sig
		}
		c, _ := Canonique(pv)
		return c
	}
	if r := VerifierCeremonie(b, sch); !r.Valide() {
		t.Fatalf("exemple de 5.10 refusé : %v", r.Details)
	}
	cas := []struct {
		nom, avant, apres, echec string
	}{
		{"développement : classe D admise", `"environment": "production"`, `"environment": "developpement"`, ""},
		{"témoin qui exécute une étape de l'officiant", `"performed_by": "p1",
      "witnessed_by": [
        "p2",
        "p3"
      ],
      "at": "2026-11-02T08:02:00.000Z"`, `"performed_by": "p2",
      "witnessed_by": [
        "p2",
        "p3"
      ],
      "at": "2026-11-02T08:02:00.000Z"`, "CR-4"},
		{"constat d'une étape inexistante (l'exception n'est plus nommée)", `"step": 5,`, `"step": 9,`, "CR-4,CR-10"},
		{"constat incident résolu", `"kind": "ecart"`, `"kind": "incident"`, ""},
		{"clé de chaîne déclarée en classe sans_objet", `"custody_class": "A",
      "backend": "pkcs11",
      "public_key": "0x0420`, `"custody_class": "sans_objet",
      "backend": "pkcs11",
      "public_key": "0x0420`, "CR-6"},
		{"fin avant le début", `"ended_at": "2026-11-02T09:10:00.000Z"`, `"ended_at": "2026-11-02T07:10:00.000Z"`, "CR-3"},
	}
	for _, c := range cas {
		texte := strings.Replace(string(b), c.avant, c.apres, 1)
		if texte == string(b) {
			t.Fatalf("%s : mutation sans effet", c.nom)
		}
		r := VerifierCeremonie(resigner(texte), sch)
		if got := strings.Join(r.Echecs(), ","); got != c.echec {
			t.Errorf("%s : %q en échec, %q attendu (%v)", c.nom, got, c.echec, r.Details)
		}
	}
	// Signature en forme s haute : CR-11 seule.
	pv, _ := AnalyserJSON(b)
	sig, _ := OctetsHex(pv.Get("signatures").Arr[0].Get("signature").Str, 65)
	s := new(big.Int).SetBytes(sig[32:64])
	s.Sub(secpN, s)
	copy(sig[32:64], octets32(s))
	sig[64] ^= 0x1b ^ 0x1c
	texte := strings.Replace(string(b), pv.Get("signatures").Arr[0].Get("signature").Str, Hex0x(sig), 1)
	if r := VerifierCeremonie([]byte(texte), sch); strings.Join(r.Echecs(), ",") != "CR-11" || len(r.Signataires) != 2 {
		t.Errorf("s haut : %v %v", r.Echecs(), r.Signataires)
	}
}

// Les vecteurs publiés, s'ils sont présents, concordent tous.
func TestVecteursPublies(t *testing.T) {
	if _, err := os.Stat("../ceremonies"); err != nil {
		t.Skip("vecteurs absents")
	}
	rap := VerifierVecteurs("..")
	if !rap.ToutConcorde() {
		var sb strings.Builder
		rap.EcrireTexte(&sb, false)
		t.Fatal(sb.String())
	}
}
