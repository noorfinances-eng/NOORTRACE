package moteur

// Essai de la revue de sécurité interne de l'étape 8 : CT-6 EX-12.4,
// révision 0.9. N-3 compare chaque clé employée par
// le verdict ; une clé employée sans ancre dans recorders rend N-3 non
// exécutée (ancre_absente) et le contrôle 6 avec elle.

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noorfinances-eng/noortrace/verificateur/commun"
)

const ancresTestP = "../../spec/vecteurs/ct-6/ancres/ancres-test.json"

func TestN3CleEmployeeSansAncreP(t *testing.T) {
	var v map[string]any
	if err := json.Unmarshal(lireOctets(t, ancresTestP), &v); err != nil {
		t.Fatal(err)
	}
	v["recorders"].([]any)[1].(map[string]any)["key_id"] = "rec-test-99"
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "ancres.json")
	ecrireOctets(t, f, b)
	res := Verifier(Options{Repertoire: seq7, Ancres: f, Langue: "fr", Version: "0.0.0", Exiger: []int{6}})
	if res.Erreur != nil {
		t.Fatalf("erreur : %+v", res.Erreur)
	}
	n3 := verifs(res)["N-3"]
	if res.Code != 3 || n3.Statut != commun.NonExecute || n3.Raison != commun.AncreAbsente || !strings.Contains(n3.Detail.Fr, "rec-test-02") {
		t.Fatalf("code %d, N-3 %s/%s : %s", res.Code, n3.Statut, n3.Raison, n3.Detail.Fr)
	}
	if c := res.Controles[6]; c.Statut != commun.NonExecute || c.Raison != commun.AncreAbsente {
		t.Fatalf("contrôle 6 : %s/%s", c.Statut, c.Raison)
	}
	for _, c := range res.Rapport.Controls {
		if c.Number == 6 && len(c.AnchorsUsed) != 0 {
			t.Fatalf("anchors_used du contrôle 6 : %v", c.AnchorsUsed)
		}
	}
	temoin := Verifier(Options{Repertoire: seq7, Ancres: ancresTestP, Langue: "fr", Version: "0.0.0", Exiger: []int{6}})
	// Témoin : N-3 réussie, contrôle 6 réussi. Depuis le complément du
	// 2026-11-19 (EX-6.25), les clés rec-test-01 et rec-test-02 sont des clés
	// d'essai : le contrôle 6 exigé est sans valeur de preuve, code 3.
	if temoin.Code != 3 || verifs(temoin)["N-3"].Statut != commun.Reussi || temoin.Controles[6].Statut != commun.Reussi || fmt.Sprint(temoin.Rapport.Lisible.ExigesSansValeur) != "[6]" {
		t.Fatalf("témoin : code %d, N-3 %s", temoin.Code, verifs(temoin)["N-3"].Statut)
	}
}
