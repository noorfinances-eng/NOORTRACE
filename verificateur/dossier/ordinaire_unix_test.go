//go:build unix

package dossier

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/noorfinances-eng/noortrace/verificateur/commun"
)

// TestPartiesNonOrdinaires : une partie déclarée présente qui est un tube
// nommé ou un lien symbolique (même vers le bon fichier) n'est ni ouverte ni
// suivie : elle compte comme absente du répertoire, D-2 en échec, les
// vérifications qui en dépendent non exécutées, en temps borné (EX-4.12,
// EX-4.13, EX-15.2).
func TestPartiesNonOrdinaires(t *testing.T) {
	base := racineCT1 + "/valide-seq-7"
	cas := []struct {
		nom, fichier, dependante string
		fabriquer                func(t *testing.T, rep, chemin string)
	}{
		{"tube nommé", "evenement.json", "E-1", func(t *testing.T, rep, chemin string) {
			os.Remove(chemin)
			if err := syscall.Mkfifo(chemin, 0o644); err != nil {
				t.Skipf("mkfifo impossible ici : %v", err)
			}
		}},
		{"lien vers le bon fichier", "chemin.json", "M-2", func(t *testing.T, rep, chemin string) {
			vrai := filepath.Join(rep, "copie-chemin")
			if err := os.Rename(chemin, vrai); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(vrai, chemin); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			rep := copier(t, base)
			c.fabriquer(t, rep, filepath.Join(rep, c.fichier))
			type sortie struct {
				a *Analyse
				m map[string]commun.Verification
			}
			fini := make(chan sortie, 1)
			go func() {
				a, m := analyser(t, rep)
				fini <- sortie{a, m}
			}()
			var s sortie
			select {
			case s = <-fini:
			case <-time.After(10 * time.Second):
				t.Fatal("lecture bloquée")
			}
			if l := echecs(s.a); strings.Join(l, ",") != "D-2" {
				t.Errorf("échecs %v, attendu [D-2]", l)
			}
			if !strings.Contains(s.m["D-2"].Detail.Fr, c.fichier+" déclaré présent mais qui n'est pas un fichier ordinaire") {
				t.Errorf("détail de D-2 : %s", s.m["D-2"].Detail.Fr)
			}
			attendre(t, s.m, c.dependante, commun.NonExecute, commun.PrerequisEnEchec)
		})
	}
	// dossier.json qui est un lien : entrée inutilisable (code 2).
	rep := copier(t, base)
	idx := filepath.Join(rep, "dossier.json")
	os.Rename(idx, filepath.Join(rep, "index"))
	os.Symlink(filepath.Join(rep, "index"), idx)
	if _, def := Ouvrir(rep); def == nil || def.Genre != "dossier_illisible" {
		t.Errorf("dossier.json en lien : %+v", def)
	}
}
