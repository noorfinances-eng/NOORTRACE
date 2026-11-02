//go:build unix

package moteur

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestEntreesAPartNonOrdinaires : un second manifeste en lien symbolique
// (même vers un manifeste conforme) ou une pièce qui est un tube nommé ne
// sont ni suivis ni ouverts : entrée inutilisable, code 2, en temps borné
// (EX-4.12, EX-15.2 ; LISEZMOI.md, « Lectures », point 23).
func TestEntreesAPartNonOrdinaires(t *testing.T) {
	base, err := filepath.Abs(racineCT1 + "/valide-seq-7")
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	lien := filepath.Join(tmp, "second.json")
	if err := os.Symlink(filepath.Join(base, "manifeste.json"), lien); err != nil {
		t.Fatal(err)
	}
	// Une pièce référencée par l'événement prouvé, remplacée par un tube.
	b, _ := os.ReadFile(filepath.Join(base, "evenement.json"))
	var ev struct {
		Execution struct {
			Arguments struct {
				Sha256 string `json:"sha256"`
			} `json:"arguments"`
		} `json:"execution"`
	}
	if err := json.Unmarshal(b, &ev); err != nil || !strings.HasPrefix(ev.Execution.Arguments.Sha256, "0x") {
		t.Fatalf("référence des arguments introuvable : %v", err)
	}
	pieces := filepath.Join(tmp, "pieces")
	os.Mkdir(pieces, 0o755)
	if err := syscall.Mkfifo(filepath.Join(pieces, ev.Execution.Arguments.Sha256[2:]), 0o644); err != nil {
		t.Skipf("mkfifo impossible ici : %v", err)
	}
	for nom, o := range map[string]Options{
		"second manifeste en lien": {Repertoire: base, SecondManifeste: lien},
		"pièce en tube nommé":      {Repertoire: base, Pieces: pieces},
	} {
		o.Langue, o.Version = "fr", "0.0.0"
		fini := make(chan *Resultat, 1)
		go func() { fini <- Verifier(o) }()
		select {
		case res := <-fini:
			if res.Code != 2 || res.Erreur == nil || res.Erreur.Genre != "entree_illisible" {
				t.Errorf("%s : code %d, %+v", nom, res.Code, res.Erreur)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s : lecture bloquée", nom)
		}
	}
}
