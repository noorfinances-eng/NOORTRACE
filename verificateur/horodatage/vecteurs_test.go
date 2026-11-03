package horodatage

// Rejeu de spec/vecteurs/ct-6/rfc3161/attendu.json (annexe A.3, EX-A.4,
// EX-A.5, EX-A.13) : statuts de T-1 à T-11, statut du contrôle (ou de
// K-7), avertissements et faits d'EX-9.19, jeton par jeton.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/noorfinances-eng/noortrace/verificateur/ancres"
	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/cryptographie"
	"github.com/noorfinances-eng/noortrace/verificateur/entree"
)

const racineCT6 = "../../spec/vecteurs/ct-6"

type casAttendu struct {
	Token             string          `json:"token"`
	DossierPeriodHash string          `json:"dossier_period_hash"`
	Anchors           *string         `json:"anchors"`
	Checks            []etatAttendu   `json:"checks"`
	FailedChecks      []string        `json:"failed_checks"`
	ControlStatus     string          `json:"control_status"`
	ControlReason     *string         `json:"control_reason"`
	Warnings          []string        `json:"warnings"`
	Facts             json.RawMessage `json:"facts"`
	Checkpoint        *struct {
		CheckpointHash string `json:"checkpoint_hash"`
		CheckpointTs   string `json:"checkpoint_ts"`
	} `json:"checkpoint"`
}

type etatAttendu struct {
	ID     string  `json:"id"`
	Status string  `json:"status"`
	Reason *string `json:"reason"`
}

func lire(t testing.TB, chemin string) []byte {
	t.Helper()
	b, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// chargerAncres lit un fichier d'ancres de test avec N-1 complète
// (ControleurAncres compris).
func chargerAncres(t testing.TB, nom string) *ancres.Ancres {
	t.Helper()
	a, d := ancres.AnalyserAncres(lire(t, filepath.Join(racineCT6, nom)), ControleurAncres{})
	if d != nil {
		t.Fatalf("%s : %s", nom, d.Message.Fr)
	}
	return a
}

func hex32(t testing.TB, s string) [32]byte {
	t.Helper()
	b, ok := cryptographie.LireHex(s, 32)
	if !ok {
		t.Fatalf("hexadécimal illisible : %s", s)
	}
	var h [32]byte
	copy(h[:], b)
	return h
}

func raison(r *string) commun.Raison {
	if r == nil {
		return commun.Aucune
	}
	return commun.Raison(*r)
}

func idsAvertissements(av []commun.Avertissement) []string {
	out := []string{}
	for _, a := range av {
		out = append(out, a.ID)
	}
	return out
}

// TestVecteursRFC3161 : chaque cas d'attendu.json.
func TestVecteursRFC3161(t *testing.T) {
	var att struct {
		Cases []casAttendu `json:"cases"`
	}
	if err := json.Unmarshal(lire(t, filepath.Join(racineCT6, "rfc3161/attendu.json")), &att); err != nil {
		t.Fatal(err)
	}
	// Aucun nombre de cas n'est figé : les jetons de la révision 0.4
	// (EX-A.22) s'ajoutent aux 24 premiers.
	if len(att.Cases) == 0 {
		t.Fatal("aucun cas dans rfc3161/attendu.json")
	}
	for _, c := range att.Cases {
		nom := c.Token + " / " + c.DossierPeriodHash[:10]
		if c.Anchors != nil {
			nom += " / " + filepath.Base(*c.Anchors)
		}
		t.Run(nom, func(t *testing.T) {
			e := Entree{Usage: Cloture, Jeton: lire(t, filepath.Join(racineCT6, "rfc3161", c.Token)), Etat: entree.Lu,
				EmpreinteAttendue: hex32(t, c.DossierPeriodHash), EmpreinteDisponible: true}
			if c.Anchors != nil {
				e.Ancres = chargerAncres(t, *c.Anchors)
			}
			if c.Checkpoint != nil {
				e.Usage = Point
				ts, ok := commun.LireHorodatage(c.Checkpoint.CheckpointTs)
				if !ok {
					t.Fatal("checkpoint_ts illisible")
				}
				e.CheckpointTs = ts
			}
			r := Verifier(e)
			if len(r.Verifications) != 11 {
				t.Fatalf("%d vérifications", len(r.Verifications))
			}
			for i, x := range r.Verifications {
				a := c.Checks[i]
				if x.ID != a.ID || string(x.Statut) != a.Status || x.Raison != raison(a.Reason) {
					t.Errorf("%s : obtenu %s/%s (%s), attendu %s/%s", x.ID, x.Statut, x.Raison, x.Detail.Fr, a.Status, raison(a.Reason))
				}
				if len(x.Controles) != 1 || x.Controles[0] != 4 {
					t.Errorf("%s : contrôles %v", x.ID, x.Controles)
				}
			}
			if string(r.Statut) != c.ControlStatus || r.Raison != raison(c.ControlReason) {
				t.Errorf("statut %s/%s, attendu %s/%s", r.Statut, r.Raison, c.ControlStatus, raison(c.ControlReason))
			}
			if got := idsAvertissements(r.Avertissements); strings.Join(got, ",") != strings.Join(c.Warnings, ",") {
				t.Errorf("avertissements %v, attendu %v", got, c.Warnings)
			}
			if string(c.Facts) == "null" || len(c.Facts) == 0 {
				if r.Faits != nil {
					t.Errorf("faits non nuls")
				}
				return
			}
			if r.Faits == nil {
				t.Fatalf("faits nuls")
			}
			var obtenu, attendu any
			b, _ := json.Marshal(r.Faits)
			json.Unmarshal(b, &obtenu)
			json.Unmarshal(c.Facts, &attendu)
			if !reflect.DeepEqual(obtenu, attendu) {
				t.Errorf("faits :\n obtenu  %s\n attendu %s", b, c.Facts)
			}
			if r.Faits.GenTimeInstant.IsZero() || (r.Faits.Accuracy != nil) != (r.Faits.UpperBoundInstant != nil) {
				t.Errorf("instants décodés incohérents")
			}
			if r.Faits.UpperBoundInstant != nil && commun.FormaterInstant(*r.Faits.UpperBoundInstant) != *r.Faits.UpperBound {
				t.Errorf("UpperBoundInstant %v, upper_bound %s", r.Faits.UpperBoundInstant, *r.Faits.UpperBound)
			}
			if e.Usage == Point && !r.Proposition.Vide() {
				t.Errorf("proposition non vide pour un point")
			}
			if e.Usage == Cloture && r.Proposition.Vide() {
				t.Errorf("proposition vide")
			}
		})
	}
}

// TestAncresDeTest : les douze fichiers d'ancres de test passent N-1 avec
// le profil strict, et leurs autorités et CRL se relisent.
func TestAncresDeTest(t *testing.T) {
	ents, err := os.ReadDir(filepath.Join(racineCT6, "ancres"))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		n++
		a := chargerAncres(t, filepath.Join("ancres", e.Name()))
		for _, au := range a.Autorites {
			if _, d := lireCertificat(au.Certificat); d != nil {
				t.Errorf("%s %s : %s", e.Name(), au.Pointeur, d.fr)
			}
		}
		for _, c := range a.CRLs {
			if _, d := lireCRL(c.DER); d != nil {
				t.Errorf("%s %s : %s", e.Name(), c.Pointeur, d.fr)
			}
		}
	}
	if n == 0 {
		t.Error("aucun fichier d'ancres")
	}
}
