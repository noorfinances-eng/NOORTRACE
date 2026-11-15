package commun

// Essais de la revue de sécurité interne de l'étape 8 : neutralisation
// des chaînes du rapport lisible (CT-6 EX-8.6) et bornes des détails
// (EX-15.1).

import (
	"strings"
	"testing"
)

func TestNeutraliser(t *testing.T) {
	cas := []struct{ in, out string }{
		{"texte ordinaire : é, 日本, —", "texte ordinaire : é, 日本, —"},
		{"a\r\x1b[2Kb", `a\u000d\u001b[2Kb`},
		{"ligne\nsuivante", `ligne\u000asuivante`},
		{"\x00\x7f\u0085\u009f", `\u0000\u007f\u0085\u009f`},
		{"\u2028\u2029\ufeff", `\u2028\u2029\ufeff`},
		{"\u202a\u202e\u2066\u2069", `\u202a\u202e\u2066\u2069`},
		{"\xff\xfeok", `\xff\xfeok`},
		{"\t", `\u0009`},
	}
	for _, c := range cas {
		if got := Neutraliser(c.in); got != c.out {
			t.Errorf("Neutraliser(%q) = %q, attendu %q", c.in, got, c.out)
		}
	}
	// Après neutralisation, aucun octet de commande ne subsiste, quel que
	// soit le texte.
	for _, s := range []string{"\x1b[8m", "\r\n", string([]byte{0x1b, 0x50, 0xc2, 0x85})} {
		n := Neutraliser(s)
		for _, r := range n {
			if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
				t.Errorf("Neutraliser(%q) = %q porte encore un caractère de commande", s, n)
			}
		}
	}
}

func TestBorner(t *testing.T) {
	var l []string
	for i := 0; i < DetailsMax+10; i++ {
		l = append(l, "x")
	}
	fr, en := BornerFr(l), BornerEn(l)
	if len(fr) != DetailsMax+1 || fr[DetailsMax] != "… et 10 autre(s)" {
		t.Fatalf("BornerFr : %d éléments, dernier %q", len(fr), fr[len(fr)-1])
	}
	if len(en) != DetailsMax+1 || en[DetailsMax] != "… and 10 more" {
		t.Fatalf("BornerEn : %d éléments, dernier %q", len(en), en[len(en)-1])
	}
	if got := BornerFr(l[:DetailsMax]); len(got) != DetailsMax {
		t.Fatalf("liste à la borne : %d", len(got))
	}
}

func TestTronquer(t *testing.T) {
	court := strings.Repeat("é", LongueurDetailMax)
	if Tronquer(court, "fr") != court {
		t.Fatal("texte à la borne tronqué")
	}
	long := court + "x"
	got := Tronquer(long, "fr")
	if !strings.HasPrefix(got, court) || !strings.HasSuffix(got, "(texte tronqué à 4096 caractères)") {
		t.Fatalf("Tronquer : %q", got[len(got)-60:])
	}
	if !strings.HasSuffix(Tronquer(long, "en"), "(text truncated at 4096 characters)") {
		t.Fatal("anglais")
	}
	bt := BornerTexte(T(long, long))
	if len([]rune(bt.Fr)) > LongueurDetailMax+64 || len([]rune(bt.En)) > LongueurDetailMax+64 {
		t.Fatal("BornerTexte")
	}
}
