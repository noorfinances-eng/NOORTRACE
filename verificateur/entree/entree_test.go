package entree

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLimite(t *testing.T) {
	rep := t.TempDir()
	f := filepath.Join(rep, "f")
	if err := os.WriteFile(f, make([]byte, 101), 0o644); err != nil {
		t.Fatal(err)
	}
	l := Lire(f, 100)
	if l.Etat != TropGrand || len(l.Octets) != 100 {
		t.Errorf("limite : état %v, %d octets", l.Etat, len(l.Octets))
	}
	l = Lire(f, 101)
	if l.Etat != Lu || len(l.Octets) != 101 {
		t.Errorf("dans la limite : état %v", l.Etat)
	}
	if Lire(filepath.Join(rep, "absent"), 10).Etat != Absent {
		t.Error("fichier absent")
	}
	if Lire(rep, 10).Etat != Illisible {
		t.Error("un répertoire lu comme un fichier")
	}
}

func TestEmpreintePlafond(t *testing.T) {
	rep := t.TempDir()
	f := filepath.Join(rep, "creux")
	g, err := os.Create(f)
	if err != nil {
		t.Fatal(err)
	}
	// Fichier creux de 64 Mio + 1 octet : lu en flux sans être conservé.
	if err := g.Truncate(PlafondAttestation + 1); err != nil {
		t.Fatal(err)
	}
	g.Close()
	if _, _, err := Empreinte(f, PlafondAttestation); err != ErrTaille {
		t.Errorf("plafond : %v", err)
	}
	if _, n, err := Empreinte(f, PlafondAttestation+1); err != nil || n != PlafondAttestation+1 {
		t.Errorf("sous le plafond : %d, %v", n, err)
	}
}
