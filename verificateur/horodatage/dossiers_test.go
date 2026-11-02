package horodatage_test

// Rejeu des dossiers de spec/vecteurs/ct-6/dossiers pour la seule part du
// contrôle 4 et de K-7 : le jeton et ses entrées sont préparés comme le
// moteur les prépare (dossier, ancres), sans les contrôles 5 et 8, puis
// comparés à attendu.json : T- en échec et non exécutées, statut du
// contrôle 4, K-7, avertissements AV-T- et AV-K-2, AV-K-4, et proposition
// F4 de l'énoncé, octet pour octet (V-5).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/noorfinances-eng/noortrace/verificateur/ancres"
	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/cryptographie"
	"github.com/noorfinances-eng/noortrace/verificateur/dossier"
	"github.com/noorfinances-eng/noortrace/verificateur/entree"
	"github.com/noorfinances-eng/noortrace/verificateur/horodatage"
)

const racineDossiers = "../../spec/vecteurs/ct-6/dossiers"

type etat struct {
	ID     string  `json:"id"`
	Reason *string `json:"reason"`
}

type attendu struct {
	FailedChecks    []string          `json:"failed_checks"`
	ControlStatuses map[string]string `json:"control_statuses"`
	NotExecuted     []etat            `json:"not_executed"`
	Warnings        []string          `json:"warnings"`
	Anchors         *string           `json:"anchors"`
	ExitCode        int               `json:"exit_code"`
	Statement       *struct {
		Fr string `json:"fr"`
		En string `json:"en"`
	} `json:"statement"`
}

func duControle4(id string) bool {
	return strings.HasPrefix(id, "T-") || id == "K-7" || strings.HasPrefix(id, "AV-T-") || id == "AV-K-2" || id == "AV-K-4"
}

func TestDossiersControle4(t *testing.T) {
	ents, err := os.ReadDir(racineDossiers)
	if err != nil {
		t.Fatal(err)
	}
	var noms []string
	for _, e := range ents {
		if e.IsDir() {
			noms = append(noms, e.Name())
		}
	}
	sort.Strings(noms)
	avecJeton, avecPoint := 0, 0
	for _, nom := range noms {
		rep := filepath.Join(racineDossiers, nom)
		t.Run(nom, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join(rep, "attendu.json"))
			if err != nil {
				t.Fatal(err)
			}
			var att attendu
			if err := json.Unmarshal(b, &att); err != nil {
				t.Fatal(err)
			}
			if att.ExitCode == 2 {
				t.Skip("code 2 : aucun contrôle")
			}
			dos, dd := dossier.Ouvrir(rep)
			if dd != nil {
				t.Fatal(dd.Message.Fr)
			}
			an, dd := dossier.Analyser(dos, dossier.Options{})
			if dd != nil {
				t.Fatal(dd.Message.Fr)
			}
			var anc *ancres.Ancres
			if att.Anchors != nil {
				var d *ancres.Defaut
				if anc, d = ancres.Lire(filepath.Join(rep, *att.Anchors), horodatage.ControleurAncres{}); d != nil {
					t.Fatalf("N-1 : %s", d.Message.Fr)
				}
			}
			base := horodatage.Entree{Ancres: anc}
			if an.Evenement != nil {
				base.TsEvenement, base.TsDisponible = an.Evenement.Ts()
			}
			var verifs []commun.Verification
			var avert []string
			statut4 := commun.Statut("")
			var prop commun.Texte
			if p := dos.Partie(dossier.PJeton); p != nil && p.Present {
				avecJeton++
				e := base
				e.Usage = horodatage.Cloture
				e.Jeton, e.Etat = p.Lecture.Octets, p.Lecture.Etat
				e.EmpreinteAttendue, e.EmpreinteDisponible = an.PeriodHash, an.P1
				r := horodatage.Verifier(e)
				verifs = append(verifs, r.Verifications...)
				statut4 = r.Statut
				prop = r.Proposition
				for _, a := range r.Avertissements {
					avert = append(avert, a.ID)
				}
			}
			var k7 *commun.Verification
			if pt := an.Point; pt != nil && pt.K1 && pt.K2 && pt.JetonBase64 != "" {
				avecPoint++
				jb, err := cryptographie.Base64Canonique(pt.JetonBase64)
				if err != nil || len(jb) > entree.LimiteJeton {
					v := commun.Nouvelle("K-7", commun.Echoue, "", commun.T("jeton du point inexploitable", "checkpoint token unusable"), 4)
					k7 = &v
				} else {
					e := base
					e.Usage = horodatage.Point
					e.Jeton, e.Etat = jb, entree.Lu
					e.EmpreinteAttendue, e.EmpreinteDisponible = pt.CheckpointHash, true
					e.CheckpointTs = pt.CheckpointTs
					r := horodatage.Verifier(e)
					v := commun.Nouvelle("K-7", r.Statut, r.Raison, commun.T("", ""), 4)
					k7 = &v
					var pa []string
					for _, a := range r.Avertissements {
						pa = append(pa, a.ID)
					}
					// Le moteur rapporte les avertissements du point sous K-7,
					// qui précède les T- (EX-6.15).
					sort.SliceStable(pa, func(i, j int) bool { return pa[i] < pa[j] })
					avert = append(pa, avert...)
				}
				if k7.Statut == commun.Echoue {
					statut4 = commun.Echoue
				}
			}
			if k7 != nil {
				verifs = append([]commun.Verification{*k7}, verifs...)
			}
			var echecs, ne []string
			for _, v := range verifs {
				switch v.Statut {
				case commun.Echoue:
					echecs = append(echecs, v.ID)
				case commun.NonExecute:
					ne = append(ne, v.ID+":"+string(v.Raison))
				}
			}
			var attEchecs, attNE, attAv []string
			for _, id := range att.FailedChecks {
				if duControle4(id) {
					attEchecs = append(attEchecs, id)
				}
			}
			for _, e := range att.NotExecuted {
				if duControle4(e.ID) && !(e.ID == "K-7" && an.Point != nil && (!an.Point.K1 || !an.Point.K2 || an.Point.JetonBase64 == "")) {
					r := ""
					if e.Reason != nil {
						r = *e.Reason
					}
					attNE = append(attNE, e.ID+":"+r)
				}
			}
			for _, id := range att.Warnings {
				if duControle4(id) {
					attAv = append(attAv, id)
				}
			}
			if strings.Join(echecs, ",") != strings.Join(attEchecs, ",") {
				t.Errorf("en échec %v, attendu %v", echecs, attEchecs)
			}
			if strings.Join(ne, ",") != strings.Join(attNE, ",") {
				t.Errorf("non exécutées %v, attendu %v", ne, attNE)
			}
			if strings.Join(avert, ",") != strings.Join(attAv, ",") {
				t.Errorf("avertissements %v, attendu %v", avert, attAv)
			}
			if statut4 != "" && string(statut4) != att.ControlStatuses["4"] {
				t.Errorf("contrôle 4 : %s, attendu %s", statut4, att.ControlStatuses["4"])
			}
			if statut4 == commun.Reussi && att.ExitCode != 1 && att.Statement != nil {
				if !strings.Contains(att.Statement.Fr, " ; "+prop.Fr+" ; ") || !strings.Contains(att.Statement.En, "; "+prop.En+"; ") {
					t.Errorf("proposition F4 absente de l'énoncé attendu :\n%s\n%s", prop.Fr, prop.En)
				}
			}
		})
	}
	if avecJeton < 60 || avecPoint < 10 {
		t.Errorf("dossiers avec jeton : %d, avec jeton de point : %d", avecJeton, avecPoint)
	}
}
