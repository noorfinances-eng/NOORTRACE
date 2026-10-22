package main

// Analyseur SSE de CT-2 §5.4.1 : règles du HTML Living Standard reprises par
// EX-5.14, et invariance à la fragmentation arbitraire du flux.

import (
	"fmt"
	"math/rand"
	"testing"
)

func evenementsTexte(evs []EvenementSSE) string {
	s := ""
	for _, e := range evs {
		s += fmt.Sprintf("[%s|%q]", e.Type, e.Data)
	}
	return s
}

func TestSSERegles(t *testing.T) {
	cas := []struct{ flux, attendu string }{
		{"data: a\n\n", `[message|"a"]`},
		{"event: x\ndata: a\ndata: b\n\n", `[x|"a\nb"]`},
		{"data:a\n\n", `[message|"a"]`},                 // aucun espace à retirer
		{"data:  a\n\n", `[message|" a"]`},              // un seul espace retiré
		{": commentaire\ndata: a\n\n", `[message|"a"]`}, // commentaire ignoré
		{"data\n\n", `[message|""]`},                    // ligne sans « : » : champ à valeur vide
		{"event: x\n\n", ``},                            // tampon data vide : rien
		{"data: a\r\n\r\ndata: b\r\rdata: c\n\n", `[message|"a"][message|"b"][message|"c"]`},
		{"\xef\xbb\xbfdata: a\n\n", `[message|"a"]`}, // BOM initiale retirée
		{"data: a\n", ``},                       // pas de ligne vide finale : non distribué
		{"data: a\n\ndata: b", `[message|"a"]`}, // ligne incomplète abandonnée
		{"id: 1\nretry: 10\nfoo: bar\ndata: a\n\n", `[message|"a"]`},
		{"event: a\nevent: b\ndata: x\n\n", `[b|"x"]`},
		{"data: [DONE]\n\n", `[message|"[DONE]"]`},
	}
	for _, c := range cas {
		evs, _ := AnalyserSSE([]byte(c.flux))
		if got := evenementsTexte(evs); got != c.attendu {
			t.Errorf("%q → %s, attendu %s", c.flux, got, c.attendu)
		}
	}
}

// fluxEssai mêle CRLF, CR, LF, commentaires, ping, UTF-8 multioctet et une
// BOM, pour que chaque coupure tombe au pire endroit.
const fluxEssai = "\xef\xbb\xbfevent: message_start\r\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"content\":[]}}\r\n\r\n" +
	": keep-alive\n\nevent: ping\ndata: {\"type\": \"ping\"}\r\r" +
	"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\n" +
	"data: \"delta\":{\"type\":\"text_delta\",\"text\":\"Régler é€😀\"}}\n\n" +
	"data: [DONE]\n\n"

func TestSSEFragmentation(t *testing.T) {
	ref, _ := AnalyserSSE([]byte(fluxEssai))
	attendu := evenementsTexte(ref)
	if len(ref) != 4 {
		t.Fatalf("%d événements : %s", len(ref), attendu)
	}
	b := []byte(fluxEssai)
	// toutes les coupures en deux
	for i := 0; i <= len(b); i++ {
		a := &AnalyseurSSE{}
		a.Ecrire(b[:i])
		a.Ecrire(b[i:])
		if got := evenementsTexte(a.Fin()); got != attendu {
			t.Fatalf("coupure à %d : %s", i, got)
		}
	}
	// octet par octet
	a := &AnalyseurSSE{}
	for i := range b {
		a.Ecrire(b[i : i+1])
	}
	if got := evenementsTexte(a.Fin()); got != attendu {
		t.Fatalf("octet par octet : %s", got)
	}
	// fragmentations aléatoires (graine fixe : déterministe)
	r := rand.New(rand.NewSource(20261022))
	for k := 0; k < 2000; k++ {
		a := &AnalyseurSSE{}
		for i := 0; i < len(b); {
			n := 1 + r.Intn(9)
			if i+n > len(b) {
				n = len(b) - i
			}
			if r.Intn(5) == 0 {
				a.Ecrire(nil) // fragment vide
			}
			a.Ecrire(b[i : i+n])
			i += n
		}
		if got := evenementsTexte(a.Fin()); got != attendu {
			t.Fatalf("fragmentation %d : %s", k, got)
		}
	}
}

// Une BOM coupée entre fragments est retirée ; un flux plus court qu'une BOM
// n'en est pas une.
func TestSSEBOMCoupee(t *testing.T) {
	a := &AnalyseurSSE{}
	a.Ecrire([]byte{0xef})
	a.Ecrire([]byte{0xbb})
	a.Ecrire([]byte{0xbf})
	a.Ecrire([]byte("data: a\n\n"))
	if got := evenementsTexte(a.Fin()); got != `[message|"a"]` {
		t.Errorf("BOM coupée : %s", got)
	}
}
