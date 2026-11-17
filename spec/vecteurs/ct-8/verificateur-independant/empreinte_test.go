package main

import (
	"strings"
	"testing"
)

// TestEmpreinteAutrePaquet : option --empreinte d'un cas dont la table
// d'EX-A.13 ne donne qu'un préfixe (« l'empreinte d'un autre paquet »). Le
// jugement reste strict (préfixe du texte et empreinte de l'archive du cas),
// et le détail d'un échec nomme l'archive de la famille que l'option désigne
// et celle que le préfixe du texte désigne, ou l'absence d'une telle archive.
func TestEmpreinteAutrePaquet(t *testing.T) {
	archives := map[string][]byte{"a.tar": []byte("a"), "b.tar": []byte("b")}
	ha, hb := SHA256Hex(archives["a.tar"]), SHA256Hex(archives["b.tar"])

	if ok, d := empreinteAutrePaquet(hb[:18], hb, "a.tar", archives); !ok {
		t.Fatalf("préfixe de b.tar, option de b.tar, archive a.tar : refusé (%s)", d)
	}

	// Préfixe du texte qui ne désigne aucune archive de la famille.
	perime := "0xb41b49dbe9b529f9"
	if strings.HasPrefix(ha, perime) || strings.HasPrefix(hb, perime) {
		t.Fatal("préfixe d'essai mal choisi")
	}
	ok, d := empreinteAutrePaquet(perime, hb, "a.tar", archives)
	if ok {
		t.Fatal("préfixe du texte sans archive : accepté")
	}
	for _, m := range []string{hb, "b.tar", perime + "…", "aucune archive de la famille"} {
		if !strings.Contains(d, m) {
			t.Fatalf("détail %q sans %q", d, m)
		}
	}

	// Préfixe du texte qui désigne une autre archive que l'option.
	ok, d = empreinteAutrePaquet(ha[:18], hb, "b.tar", archives)
	if ok || !strings.Contains(d, "désigne a.tar") || !strings.Contains(d, "SHA-256 de b.tar") {
		t.Fatalf("préfixe de a.tar, option de b.tar : %v (%s)", ok, d)
	}

	// Option égale à l'empreinte de l'archive du cas : PR-2 réussirait.
	ok, d = empreinteAutrePaquet(ha[:18], ha, "a.tar", archives)
	if ok || !strings.Contains(d, "archive du cas") {
		t.Fatalf("option égale à l'empreinte du cas : %v (%s)", ok, d)
	}
}
