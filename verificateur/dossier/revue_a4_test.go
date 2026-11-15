package dossier

// CT-1 §11.4 (règle générale des relations, « Autres termes mal typés ») :
// request_hash est un terme de la règle d'A-4 ; un approval objet dont
// request_hash est absent ou n'est pas une chaîne (type du schéma) ne laisse
// pas la règle se lire : A-4 échoue, avant toute recherche du voisin, même
// quand voisins.json est inexploitable (vecteur invalide-a3-approval-vide).
// Un request_hash chaîne qui ne désigne aucun voisin reste « hors du
// dossier » : non exécutée, raison admise.

import (
	"strings"
	"testing"

	"github.com/noorfinances-eng/noortrace/verificateur/commun"
)

const dossierSeq6 = "../../spec/vecteurs/ct-1/dossiers/valide-seq-6"

func TestA4RequestHashIllisible(t *testing.T) {
	cas := []struct {
		nom   string
		muter func(t *testing.T, rep string)
	}{
		{"approval {}", func(t *testing.T, rep string) {
			modifierJSON(t, rep, "evenement.json", func(v map[string]any) { v["approval"] = map[string]any{} })
		}},
		{"request_hash retiré", func(t *testing.T, rep string) {
			modifierJSON(t, rep, "evenement.json", func(v map[string]any) { delete(v["approval"].(map[string]any), "request_hash") })
		}},
		{"request_hash nombre", func(t *testing.T, rep string) {
			modifierJSON(t, rep, "evenement.json", func(v map[string]any) { v["approval"].(map[string]any)["request_hash"] = 7 })
		}},
		{"request_hash null", func(t *testing.T, rep string) {
			modifierJSON(t, rep, "evenement.json", func(v map[string]any) { v["approval"].(map[string]any)["request_hash"] = nil })
		}},
		{"approval {} et voisins.json inexploitable", func(t *testing.T, rep string) {
			modifierJSON(t, rep, "evenement.json", func(v map[string]any) { v["approval"] = map[string]any{} })
			remplacerPartie(t, rep, "voisins.json", []byte("{"))
		}},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			rep := copierDossier(t, dossierSeq6)
			c.muter(t, rep)
			a := analyserRep(t, rep, Options{})
			attendreEchec(t, a, "A-4", "request_hash")
		})
	}
	t.Run("request_hash chaîne d'un autre hash : hors du dossier, raison admise", func(t *testing.T) {
		rep := copierDossier(t, dossierSeq6)
		modifierJSON(t, rep, "evenement.json", func(v map[string]any) {
			v["approval"].(map[string]any)["request_hash"] = "0x" + strings.Repeat("ab", 32)
		})
		v := statutDe(t, analyserRep(t, rep, Options{}), "A-4")
		if v.Statut != commun.NonExecute || v.Raison != commun.PieceHorsDossier {
			t.Errorf("A-4 %s/%s (%s), attendu non_execute (piece_hors_dossier)", v.Statut, v.Raison, v.Detail.Fr)
		}
	})
	t.Run("dossier publié : A-4 réussie", func(t *testing.T) {
		v := statutDe(t, analyserRep(t, copierDossier(t, dossierSeq6), Options{}), "A-4")
		if v.Statut != commun.Reussi {
			t.Errorf("A-4 %s (%s), attendu reussi", v.Statut, v.Detail.Fr)
		}
	})
}
