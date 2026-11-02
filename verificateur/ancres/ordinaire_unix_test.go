//go:build unix

package ancres

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestEntreesNonOrdinaires : un fichier d'ancres ou d'en-têtes qui est un
// lien symbolique (même vers un fichier conforme) ou un tube nommé n'est ni
// suivi ni ouvert : entrée inutilisable (N-1, N-2, code 2), en temps borné.
func TestEntreesNonOrdinaires(t *testing.T) {
	rep := t.TempDir()
	vrai, err := filepath.Abs(filepath.Join(repAncres, "ancres-test.json"))
	if err != nil {
		t.Fatal(err)
	}
	lien := filepath.Join(rep, "lien.json")
	if err := os.Symlink(vrai, lien); err != nil {
		t.Fatal(err)
	}
	tube := filepath.Join(rep, "tube.json")
	if err := syscall.Mkfifo(tube, 0o644); err != nil {
		t.Skipf("mkfifo impossible ici : %v", err)
	}
	for _, c := range []string{lien, tube} {
		fini := make(chan [2]*Defaut, 1)
		go func() {
			_, d1 := Lire(c, nil)
			_, d2 := LireEntetes(c)
			fini <- [2]*Defaut{d1, d2}
		}()
		select {
		case d := <-fini:
			if d[0] == nil || d[0].Verification != "N-1" || d[0].Genre != "ancres_inutilisables" {
				t.Errorf("%s : N-1 %+v", filepath.Base(c), d[0])
			}
			if d[1] == nil || d[1].Verification != "N-2" || d[1].Genre != "entree_illisible" {
				t.Errorf("%s : N-2 %+v", filepath.Base(c), d[1])
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s : lecture bloquée", filepath.Base(c))
		}
	}
}
