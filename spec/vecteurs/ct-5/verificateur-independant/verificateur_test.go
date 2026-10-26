// Tests propres au module : briques (keccak, DER, .ots, coût, classement)
// confrontées aux valeurs que la spécification CT-5 imprime, et rejeu de la
// trace de référence quand les vecteurs publiés sont présents.

package main

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func h(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// La permutation Keccak est confrontée à SHA3-256 de la bibliothèque
// standard (même Keccak-f[1600], remplissage 0x06).
func TestKeccakContreSHA3(t *testing.T) {
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
	if got := JournalIDOf("journal-principal"); got != "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b" {
		t.Errorf("journal_id = %s", got)
	}
	if DocTypePointDeControle != "0x72c486c933f8fb8fef2c726539023e8fd80113cc0ca89e3fdf1314d553932178" {
		t.Errorf("docType point = %s", DocTypePointDeControle)
	}
}

// EX-5.1 : la requête de 69 octets sur le checkpointHash de K2 avec le nonce
// de CT-1 §13 (0x74a6f4979421411e), et sa relecture.
func TestRequeteEX51(t *testing.T) {
	nonce := NonceDepuisEtiquette("noortrace/vecteurs/v0/ct-1/nonce-tsa/point-de-controle/exemple")
	if HexNonce(nonce) != "0x74a6f4979421411e" {
		t.Fatalf("nonce = %s", HexNonce(nonce))
	}
	der, err := ConstruireRequete("0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff", nonce, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	attendu := h("30430201013031300d0609608648016503040201050004206a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff020874a6f4979421411e0101ff")
	if !bytes.Equal(der, attendu) {
		t.Fatalf("DER = %x", der)
	}
	r, err := LireRequete(der)
	if err != nil || r.PolicyOID != nil || r.Nonce.Cmp(nonce) != 0 {
		t.Fatalf("relecture : %v %v", r, err)
	}
	// nonce à bit haut : 70 octets avec un 00 de tête ; politique : 81 octets
	der70, _ := ConstruireRequete("0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1", new(big.Int).SetUint64(0xf144cca6ec50dcdb), nil, true)
	if len(der70) != 70 || !bytes.Equal(der70[56:59], []byte{0x02, 0x09, 0x00}) {
		t.Errorf("nonce à bit haut : %x", der70)
	}
	pol := "1.3.6.1.4.1.99999.1.1"
	der81, _ := ConstruireRequete("0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff", nonce, &pol, true)
	if len(der81) != 81 {
		t.Errorf("politique : %d octets", len(der81))
	}
	// refus (AN-5, AN-6)
	for _, c := range []struct {
		digest string
		nonce  *big.Int
		cert   bool
		regle  string
	}{
		{"0xabab", big.NewInt(1), true, "AN-5"},
		{"0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff", big.NewInt(0), true, "AN-6"},
		{"0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff", new(big.Int).Lsh(big.NewInt(1), 64), true, "AN-6"},
		{"0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff", big.NewInt(1), false, "AN-5"},
	} {
		_, err := ConstruireRequete(c.digest, c.nonce, nil, c.cert)
		e, ok := err.(*ErreurAncrage)
		if !ok || e.Regle != c.regle {
			t.Errorf("refus attendu (%s) : %v", c.regle, err)
		}
	}
	if _, err := LireRequete(h("30440201013031300d0609608648016503040201050004206a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff020900018032ff0d74cfda0101ff")); err == nil {
		t.Error("zéro de tête superflu accepté")
	}
}

// EX-6.4 : l'exemple minimal (195 octets, deux promesses nues triées par URI).
func TestOtsMinimalEX64(t *testing.T) {
	nonce := OctetsDepuisEtiquette("noortrace/vecteurs/v0/ct-5/ots/nonce/point-k2", 16)
	if hex.EncodeToString(nonce) != "a10f0dccae630a2791dde3924b507379" {
		t.Fatalf("nonce = %x", nonce)
	}
	bob := []*Branche{{Attestation: &Attestation{Genre: "en_attente", URI: "https://bob.btc.calendar.opentimestamps.org"}}}
	alice := []*Branche{{Attestation: &Attestation{Genre: "en_attente", URI: "https://alice.btc.calendar.opentimestamps.org"}}}
	octets, err := ConstruireOts(h("6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff"), nonce, [][]*Branche{bob, alice})
	if err != nil {
		t.Fatal(err)
	}
	if len(octets) != 195 || SHA256Hex(octets) != "0x64a62afc6526fdd0ea34c57ea70eb8e4711f2fc49ff8fc6a3c4cd38596efa8b6" {
		t.Fatalf("%d octets, %s", len(octets), SHA256Hex(octets))
	}
	p, err := LireOts(octets)
	if err != nil {
		t.Fatal(err)
	}
	_, atts, _ := Executer(p)
	if len(atts) != 2 || atts[0].URI != "https://alice.btc.calendar.opentimestamps.org" || atts[1].URI != "https://bob.btc.calendar.opentimestamps.org" {
		t.Errorf("attestations : %+v", atts)
	}
	if etat, _ := EtatPreuve(octets); etat != "en_attente" {
		t.Errorf("état %s", etat)
	}
	// resérialisation identique
	re, _ := EncoderOts(p.Empreinte, p.Arbre)
	if !bytes.Equal(re, octets) {
		t.Error("resérialisation différente")
	}
}

// Section 12.3 : premier cas de la famille cout (a = 1, second rang).
func TestCoutDefaut(t *testing.T) {
	r, err := Cout(CasCout{Journals: 1, HoursPerYear: 8760, CheckpointIntervalS: 60, Rfc3161CheckpointInterval: 300, ActivityRatio: 1, ProviderRole: "second_rang", RegistryCheckpoints: "nouveaux_evenements", UnitPriceQualified: 1, UnitPriceSecondRank: 0.2})
	if err != nil {
		t.Fatal(err)
	}
	if r.QualifiedTokensPerJournal != 8760 || r.SecondRankTokensPerJournal != 96360 || r.RegistryAnchorsPerJournal != 543120 || r.GasUpperBoundPerJournal != 55423030800 || r.CostPerJournal != 28032 || r.CostTotal != 28032 {
		t.Errorf("%+v", r)
	}
}

// EX-8.9 : attente de reprise.
func TestCalculerAttente(t *testing.T) {
	retry := Reprise{InitialMs: 5000, Factor: 2, MaxMs: 300000, JitterMs: 250}
	s503, ra := int64(503), int64(30)
	if d, r := CalculerAttente(&s503, &ra, 1, false, retry, 0); d != 30000 || r != "retry_after" {
		t.Errorf("503 : %v %s", d, r)
	}
	s408 := int64(408)
	if d, r := CalculerAttente(&s408, nil, 1, false, retry, 0); d != 0 || r != "immediat" {
		t.Errorf("408 : %v %s", d, r)
	}
	if d, r := CalculerAttente(&s408, nil, 2, true, retry, 7); d != 10007 || r != "backoff" {
		t.Errorf("408 second : %v %s", d, r)
	}
	if d, _ := CalculerAttente(nil, nil, 12, true, retry, 0); d != 300000 {
		t.Errorf("plafond : %v", d)
	}
}

// EX-8.3 : la table des transitions admises, et rien d'autre.
func TestTransitionsEX83(t *testing.T) {
	for _, c := range []struct {
		prev, suivant string
		ok            bool
	}{
		{"", "a_envoyer", true}, {"", "attente_registre", true}, {"", "envoyee", false},
		{"a_envoyer", "envoyee", true}, {"a_envoyer", "remplacee", true}, {"a_envoyer", "obtenue", false},
		{"attente_registre", "envoyee", true}, {"attente_registre", "remplacee", true},
		{"envoyee", "obtenue", true}, {"envoyee", "en_attente", true}, {"envoyee", "a_reprendre", true},
		{"envoyee", "envoyee", true}, {"envoyee", "refusee", true}, {"envoyee", "remplacee", true},
		{"envoyee", "a_envoyer", true}, {"a_reprendre", "envoyee", true}, {"obtenue", "a_reprendre", true}, {"obtenue", "a_envoyer", false}, {"a_reprendre", "remplacee", true},
		{"a_reprendre", "a_reprendre", false}, {"en_attente", "complete", true}, {"en_attente", "en_attente", true},
		{"obtenue", "envoyee", false}, {"complete", "en_attente", false}, {"remplacee", "a_envoyer", false},
	} {
		if TransitionAdmise(c.prev, c.suivant) != c.ok {
			t.Errorf("%q → %q : admise = %v, attendu %v", c.prev, c.suivant, !c.ok, c.ok)
		}
	}
}

// AN-37 : la suite d'EX-8.9 sans gigue, 5 s, 10 s, 20 s, …, plafonnée à 300 s.
func TestSuiteEX89(t *testing.T) {
	retry := Reprise{InitialMs: 5000, Factor: 2, MaxMs: 300000, JitterMs: 250}
	attendus := []float64{5000, 10000, 20000, 40000, 80000, 160000, 300000, 300000}
	for i, a := range attendus {
		if d := DelaiAttendu(retry, int64(i+1)); d != a {
			t.Errorf("k = %d : %v, attendu %v", i+1, d, a)
		}
	}
}

// Invariants de la section 8.11 sur la trace de référence de 8.10 : toutes
// les règles sont évaluées et aucune n'a d'écart.
func TestInvariantsTraceReference(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "planification", "heure-nominale-reference.json"))
	if err != nil {
		t.Skip("vecteurs publiés absents")
	}
	trace, err := ParseJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	rejeu, err := RejouerTrace(trace, nil)
	if err != nil {
		t.Fatal(err)
	}
	invariants, err := VerifierInvariants(trace, rejeu)
	if err != nil {
		t.Fatal(err)
	}
	regles := map[string]bool{}
	for _, inv := range invariants {
		regles[inv.Regle] = true
		if len(inv.Ecarts) > 0 {
			t.Errorf("%s : %v", inv.Regle, inv.Ecarts)
		}
	}
	for _, r := range []string{"AN-32", "AN-33", "AN-34", "AN-35", "AN-36", "AN-37", "AN-39", "AN-40", "AN-41", "AN-43", "A.2"} {
		if !regles[r] {
			t.Errorf("règle %s non évaluée", r)
		}
	}
	if len(rejeu.Ecritures) != len(rejeu.Lignes) {
		t.Errorf("%d écritures pour %d lignes", len(rejeu.Ecritures), len(rejeu.Lignes))
	}
}

// Rejeu de la trace de référence (8.10) et des autres traces publiées.
func TestTracesPubliees(t *testing.T) {
	dir := filepath.Join("..", "planification")
	entrees, err := os.ReadDir(dir)
	if err != nil {
		t.Skip("vecteurs publiés absents")
	}
	n := 0
	for _, e := range entrees {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		trace, err := ParseJSON(b)
		if err != nil {
			t.Fatal(err)
		}
		rejeu, err := RejouerTrace(trace, nil)
		if err != nil {
			t.Fatalf("%s : %v", e.Name(), err)
		}
		attendues := trace.Get("expected").Arr
		if len(rejeu.Actions) != len(attendues) {
			t.Fatalf("%s : %d actions, %d attendues", e.Name(), len(rejeu.Actions), len(attendues))
		}
		for i := range attendues {
			if canon(attendues[i]) != canon(rejeu.Actions[i]) {
				t.Fatalf("%s : action %d\nattendu %s\nobtenu  %s", e.Name(), i, canon(attendues[i]), canon(rejeu.Actions[i]))
			}
		}
		queue := trace.Get("queue_after").Arr
		if len(queue) != len(rejeu.File) {
			t.Fatalf("%s : file de %d demandes, %d attendues", e.Name(), len(rejeu.File), len(queue))
		}
		for i := range queue {
			if canon(queue[i]) != LigneFile(rejeu.File[i]) {
				t.Fatalf("%s : demande %d différente", e.Name(), i)
			}
		}
		n++
	}
	if n < 12 {
		t.Errorf("%d trace(s) rejouée(s), douze attendues", n)
	}
}

// Les vecteurs publiés concordent entièrement.
func TestVecteursPublies(t *testing.T) {
	if _, err := os.Stat(filepath.Join("..", "constantes.json")); err != nil {
		t.Skip("vecteurs publiés absents")
	}
	rap := VerifierVecteurs("..")
	if !rap.ToutConcorde() {
		var sb bytes.Buffer
		rap.EcrireTexte(&sb, false)
		t.Fatal(sb.String())
	}
}

// AN-61 : une ancre de point dont l'empreinte ne correspond à aucun point
// publié est orpheline ; un émetteur non inscrit et une ancre de période sont
// ignorés ; l'ordre des blocs suit celui des checkpoint_ts.
func TestVerifierCompletude(t *testing.T) {
	org := "0x" + strings.Repeat("a1", 32)
	jrn := "0x" + strings.Repeat("b2", 32)
	h1, h2 := "0x"+strings.Repeat("01", 32), "0x"+strings.Repeat("02", 32)
	cle := "0x" + strings.Repeat("c3", 20)
	journaux := []JournalPublie{{OrgID: org, JournalID: jrn, Points: []PointPublie{{h1, "2026-11-05T09:13:00.000Z"}, {h2, "2026-11-05T09:32:00.000Z"}}}}
	a1 := AncreCapturee{EmpreinteAncre(org, jrn, h1), DocTypePointDeControle, 10, 0, cle}
	a2 := AncreCapturee{EmpreinteAncre(org, jrn, h2), DocTypePointDeControle, 11, 0, cle}
	orph := AncreCapturee{EmpreinteAncre(org, jrn, "0x"+strings.Repeat("03", 32)), DocTypePointDeControle, 12, 0, cle}
	autre := AncreCapturee{orph.Fingerprint, DocTypePointDeControle, 12, 1, "0x" + strings.Repeat("d4", 20)}
	periode := AncreCapturee{orph.Fingerprint, DocTypePeriode, 13, 0, cle}
	r, err := VerifierCompletude(journaux, []AncreCapturee{a1, a2, autre, periode}, []string{cle}, 0, 20)
	if err != nil || !r.Complet || r.Rattachees != 2 {
		t.Fatalf("série complète : %+v %v", r, err)
	}
	r, _ = VerifierCompletude(journaux, []AncreCapturee{a1, a2, orph}, []string{cle}, 0, 20)
	if r.Complet || len(r.Orphelines) != 1 || r.Orphelines[0] != orph.Fingerprint {
		t.Errorf("orpheline : %+v", r)
	}
	a1.BlockNumber = 15
	r, _ = VerifierCompletude(journaux, []AncreCapturee{a1, a2}, []string{cle}, 0, 20)
	if r.Complet || len(r.HorsOrdre) != 1 || r.HorsOrdre[0] != a1.Fingerprint {
		t.Errorf("hors ordre : %+v", r)
	}
}
