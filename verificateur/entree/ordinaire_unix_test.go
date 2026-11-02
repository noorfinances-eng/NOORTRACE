//go:build unix

package entree

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestNonOrdinaire : un tube nommé, un lien symbolique (vers un fichier
// ordinaire ou vers un tube) ne sont jamais ouverts ni suivis ; la lecture
// rend Absent avec ErrNonOrdinaire, en temps borné (EX-4.13, EX-15.2).
func TestNonOrdinaire(t *testing.T) {
	rep := t.TempDir()
	tube := filepath.Join(rep, "tube")
	if err := syscall.Mkfifo(tube, 0o644); err != nil {
		t.Skipf("mkfifo impossible ici : %v", err)
	}
	ordinaire := filepath.Join(rep, "ordinaire")
	if err := os.WriteFile(ordinaire, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	lien := filepath.Join(rep, "lien")
	lienTube := filepath.Join(rep, "lien-tube")
	if err := os.Symlink(ordinaire, lien); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(tube, lienTube); err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{tube, lien, lienTube} {
		fini := make(chan Lecture, 1)
		go func() { fini <- Lire(c, 100) }()
		select {
		case l := <-fini:
			if l.Etat != Absent || !errors.Is(l.Err, ErrNonOrdinaire) {
				t.Errorf("%s : état %v, %v", filepath.Base(c), l.Etat, l.Err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s : lecture bloquée", filepath.Base(c))
		}
		if _, _, err := Empreinte(c, 100); !errors.Is(err, ErrNonOrdinaire) {
			t.Errorf("%s : empreinte %v", filepath.Base(c), err)
		}
	}
	// Le fichier ordinaire lui-même se lit.
	if l := Lire(ordinaire, 100); l.Etat != Lu || string(l.Octets) != "{}" {
		t.Errorf("fichier ordinaire : état %v", l.Etat)
	}
	// ouvrirSansLien refuse un lien même sans le Lstat préalable.
	if _, err := ouvrirSansLien(lien); !lienRefuse(err) {
		t.Errorf("ouverture d'un lien sans O_NOFOLLOW effectif : %v", err)
	}
}
