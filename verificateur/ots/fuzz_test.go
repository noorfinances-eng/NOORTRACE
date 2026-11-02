package ots

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/noorfinances-eng/noortrace/verificateur/ancres"
	"github.com/noorfinances-eng/noortrace/verificateur/entree"
)

// FuzzAnalyser : l'analyseur .ots (O-1) et la vérification complète (O-1 à
// O-7) ne paniquent sur aucune entrée et rendent un résultat de forme
// conforme (CT-6 EX-15.3). Graines : les preuves de l'annexe A.4 et des
// fichiers construits.
func FuzzAnalyser(f *testing.F) {
	noms, _ := filepath.Glob(filepath.Join(repOTS, "preuves", "*.ots"))
	for _, n := range noms {
		if b, err := os.ReadFile(n); err == nil {
			f.Add(b)
		}
	}
	f.Add(fichierOTS(empreinteTest, fourche(), []byte{opRIPEMD160}, attBitcoin(1001), opAp([]byte{1}), opSHA(), attAttente("")))
	f.Add(fichierOTS(empreinteTest, chaineOps(MaxOperationsChemin, opSHA(), attBitcoin(1))))
	f.Add([]byte{})
	var entetes *ancres.Entetes
	if b, err := os.ReadFile(filepath.Join(repOTS, "entetes", "chaine.json")); err == nil {
		entetes, _ = ancres.AnalyserEntetes(b)
	}
	var ancre *ancres.Bitcoin
	if b, err := os.ReadFile(filepath.Join(repAncres, "ancres-test.json")); err == nil {
		if a, _ := ancres.AnalyserAncres(b, nil); a != nil {
			ancre = a.Bitcoin
		}
	}
	empreinte := hex32(&testing.T{}, periodHash1)
	f.Fuzz(func(t *testing.T, b []byte) {
		p, d := Analyser(b)
		if (p == nil) == (d == nil) {
			t.Fatal("ni preuve ni défaut, ou les deux")
		}
		for _, u := range []Usage{Cloture, Point} {
			e := Entree{Usage: u, Etat: entree.Lu, Preuve: b, EmpreinteAttendue: empreinte, EmpreinteDisponible: true, Entetes: entetes, Ancre: ancre}
			verifierForme(t, e, Verifier(e))
		}
	})
}
