package moteur

// Rejeu des dossiers de spec/vecteurs/ct-1/dossiers et de
// spec/vecteurs/ct-6/dossiers contre leur attendu.json (CT-6 V-1 à V-10,
// annexe A).
//
// Un dossier dont l'attendu dépend d'un contrôle encore provisoire (4, 5 ou
// 8, Construit() faux dans le paquet horodatage, ots ou registre) est
// « en attente des contrôles 4, 5, 8 » : sa comparaison complète est
// marquée t.Skip avec la raison ; ses vérifications qui ne relèvent pas de
// ces contrôles (D-, E-, C-, M-, P-, A-, K-1 à K-6, AT-, N-3, statuts des
// contrôles 1, 2, 3, 6 et 7, avertissements AV-AT-) sont comparées quand
// même. TestInventaireVecteurs compte les dossiers rejoués et en attente.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/horodatage"
	"github.com/noorfinances-eng/noortrace/verificateur/jsonv"
	"github.com/noorfinances-eng/noortrace/verificateur/ots"
	"github.com/noorfinances-eng/noortrace/verificateur/registre"
	"github.com/noorfinances-eng/noortrace/verificateur/schema"
)

const (
	racineCT1 = "../../spec/vecteurs/ct-1/dossiers"
	racineCT6 = "../../spec/vecteurs/ct-6/dossiers"
)

type attenduCT1 struct {
	Valide            bool     `json:"valide"`
	ControlesEnEchec  []string `json:"controles_en_echec"`
	PerimeterChecks   []etat   `json:"perimeter_checks"`
	PerimeterRetained *bool    `json:"perimeter_retained"`
	Warnings          []string `json:"warnings"`
}

type etat struct {
	ID     string  `json:"id"`
	Status string  `json:"status"`
	Reason *string `json:"reason"`
}

type texte struct {
	Fr string `json:"fr"`
	En string `json:"en"`
}

type attenduCT6 struct {
	Valid             bool              `json:"valid"`
	FailedChecks      []string          `json:"failed_checks"`
	ControlStatuses   map[string]string `json:"control_statuses"`
	NotExecuted       []etat            `json:"not_executed"`
	Warnings          []string          `json:"warnings"`
	Anchors           *string           `json:"anchors"`
	BitcoinHeaders    *string           `json:"bitcoin_headers"`
	ExitCode          int               `json:"exit_code"`
	Statement         *texte            `json:"statement"`
	Bound             *texte            `json:"bound"`
	PerimeterChecks   []etat            `json:"perimeter_checks"`
	PerimeterRetained *bool             `json:"perimeter_retained"`
}

func lireJSON(t *testing.T, chemin string, v any) {
	t.Helper()
	b, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s : %v", chemin, err)
	}
}

func dossiers(t *testing.T, racine string) []string {
	t.Helper()
	ents, err := os.ReadDir(racine)
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
	return noms
}

// controlesRequis : contrôles réservés (4, 5, 8) dont l'attendu du dossier
// dépend : partie réservée déclarée présente, ou ancre non nulle du point
// de contrôle du journal (K-7, K-9, K-8).
func controlesRequis(t *testing.T, rep string) map[int]bool {
	t.Helper()
	req := map[int]bool{}
	b, err := os.ReadFile(filepath.Join(rep, "dossier.json"))
	if err != nil {
		return req
	}
	idx, err := jsonv.Analyser(b)
	if err != nil {
		return req
	}
	for _, p := range idx.Membre("parts").Elements {
		if !p.Membre("present").Bool {
			continue
		}
		switch p.Membre("name").S() {
		case "jeton_rfc3161":
			req[4] = true
		case "preuve_ots":
			req[5] = true
		case "registre", "certificat_commit":
			req[8] = true
		case "points_de_controle":
			pb, err := os.ReadFile(filepath.Join(rep, "points-de-controle.json"))
			if err != nil {
				continue
			}
			pv, err := jsonv.Analyser(pb)
			if err != nil || !pv.EstObjet() {
				continue
			}
			a := pv.Membre("anchors")
			if a.Membre("rfc3161").EstObjet() {
				req[4] = true
			}
			if a.Membre("ots").EstObjet() {
				req[5] = true
			}
			if a.Membre("registry").EstObjet() {
				req[8] = true
			}
		}
	}
	return req
}

// enAttente rend la raison de l'attente, ou "".
func enAttente(req map[int]bool) string {
	var manquants []string
	if req[4] && !horodatage.Construit() {
		manquants = append(manquants, "4")
	}
	if req[5] && !ots.Construit() {
		manquants = append(manquants, "5")
	}
	if req[8] && !registre.Construit() {
		manquants = append(manquants, "8")
	}
	if len(manquants) == 0 {
		return ""
	}
	return "en attente des contrôles 4, 5, 8 : l'attendu dépend du contrôle " + strings.Join(manquants, ", ") + ", encore provisoire"
}

// familleCoeur : vérification construite par ce temps de l'étape 2.
func familleCoeur(id string) bool {
	switch {
	case strings.HasPrefix(id, "T-"), strings.HasPrefix(id, "O-"), strings.HasPrefix(id, "R-"), id == "N-4":
		return false
	case id == "K-7", id == "K-8", id == "K-9":
		return false
	}
	return true
}

func echecsEtBloquantes(vs []commun.Verification, filtre func(string) bool) (echecs []string, nonExec []etat) {
	for _, v := range vs {
		if !filtre(v.ID) {
			continue
		}
		if v.Statut == commun.Echoue && !strings.HasPrefix(v.ID, "AT-") {
			echecs = append(echecs, v.ID)
		}
		if v.Statut == commun.NonExecute {
			r := string(v.Raison)
			nonExec = append(nonExec, etat{ID: v.ID, Reason: &r})
		}
	}
	return
}

func egalListes(a, b []string) bool { return strings.Join(a, ",") == strings.Join(b, ",") }

func formatEtats(e []etat) string {
	var s []string
	for _, x := range e {
		r := "null"
		if x.Reason != nil {
			r = *x.Reason
		}
		s = append(s, x.ID+":"+r)
	}
	return strings.Join(s, ",")
}

func comparerPerimetre(t *testing.T, res *Resultat, checks []etat, retenue *bool) {
	t.Helper()
	par := map[string]commun.Verification{}
	for _, v := range res.Verifs {
		par[v.ID] = v
	}
	for _, pc := range checks {
		v, ok := par[pc.ID]
		r := ""
		if pc.Reason != nil {
			r = *pc.Reason
		}
		if !ok || string(v.Statut) != pc.Status || string(v.Raison) != r {
			t.Errorf("%s : obtenu %s/%s, attendu %s/%s (%s)", pc.ID, v.Statut, v.Raison, pc.Status, r, v.Detail.Fr)
		}
	}
	if retenue != nil && len(checks) > 0 {
		obtenu := res.Rapport != nil && res.Rapport.Facts.Perimeter != nil
		if res.Rapport == nil {
			return
		}
		if obtenu != *retenue {
			t.Errorf("attestation retenue : obtenu %v, attendu %v", obtenu, *retenue)
		}
	}
}

func avertissements(res *Resultat, filtre func(string) bool) []string {
	var ids []string
	for _, a := range res.Avertissements {
		if filtre(a.ID) {
			ids = append(ids, a.ID)
		}
	}
	return ids
}

func filtrer(ids []string, f func(string) bool) []string {
	var out []string
	for _, id := range ids {
		if f(id) {
			out = append(out, id)
		}
	}
	return out
}

func rapportConforme(t *testing.T, res *Resultat, langue string) {
	t.Helper()
	if res.Rapport == nil {
		return
	}
	b, err := json.Marshal(res.Rapport)
	if err != nil {
		t.Fatal(err)
	}
	v, err := jsonv.Analyser(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.Valider(schema.RapportVerification, v); err != nil {
		t.Errorf("rapport non conforme au schéma rapport-verification-v0 : %v", err)
	}
}

// TestVecteursCT1 : les dossiers de CT-1, sans fichier d'ancres puis avec
// ancres-test.json (V-7, EX-6.14, EX-A.11).
func TestVecteursCT1(t *testing.T) {
	ancresTest, _ := filepath.Abs("../../spec/vecteurs/ct-6/ancres/ancres-test.json")
	for _, nom := range dossiers(t, racineCT1) {
		rep := filepath.Join(racineCT1, nom)
		var att attenduCT1
		lireJSON(t, filepath.Join(rep, "attendu.json"), &att)
		for _, avec := range []bool{false, true} {
			sous := nom
			if avec {
				sous += "/ancres-test"
			}
			t.Run(sous, func(t *testing.T) {
				o := Options{Repertoire: rep, Langue: "fr", Version: "0.0.0"}
				if avec {
					o.Ancres = ancresTest
				}
				if raison := enAttente(controlesRequis(t, rep)); raison != "" {
					t.Skip(raison)
				}
				res := Verifier(o)
				if res.Erreur != nil {
					t.Fatalf("erreur inattendue : %s", res.Erreur.Message.Fr)
				}
				code := 1
				if att.Valide {
					code = 0
				}
				if res.Code != code {
					t.Errorf("code %d, attendu %d", res.Code, code)
				}
				echecs, _ := echecsEtBloquantes(res.Verifs, func(string) bool { return true })
				if !egalListes(echecs, att.ControlesEnEchec) {
					t.Errorf("vérifications en échec %v, attendu %v", echecs, att.ControlesEnEchec)
				}
				comparerPerimetre(t, res, att.PerimeterChecks, att.PerimeterRetained)
				if att.PerimeterChecks != nil {
					av := avertissements(res, func(id string) bool { return strings.HasPrefix(id, "AV-AT-") })
					if !egalListes(av, att.Warnings) {
						t.Errorf("avertissements %v, attendu %v", av, att.Warnings)
					}
				}
				if avec {
					// N-3 réussie, ou absente du rapport, ou non exécutée
					// faute de prérequis (EX-A.11).
					for _, v := range res.Verifs {
						if v.ID == "N-3" && v.Statut == commun.Echoue {
							t.Errorf("N-3 en échec avec ancres-test.json")
						}
					}
				}
				rapportConforme(t, res, "fr")
			})
		}
	}
}

// TestVecteursCT6 : les dossiers de CT-6 (V-1 à V-6, V-9, V-10).
func TestVecteursCT6(t *testing.T) {
	for _, nom := range dossiers(t, racineCT6) {
		rep := filepath.Join(racineCT6, nom)
		var att attenduCT6
		lireJSON(t, filepath.Join(rep, "attendu.json"), &att)
		t.Run(nom, func(t *testing.T) {
			o := Options{Repertoire: rep, Langue: "fr", Version: "0.0.0"}
			if att.Anchors != nil {
				o.Ancres = filepath.Join(rep, *att.Anchors)
			}
			if att.BitcoinHeaders != nil {
				o.Entetes = filepath.Join(rep, *att.BitcoinHeaders)
			}
			res := Verifier(o)
			attente := enAttente(controlesRequis(t, rep))
			if attente == "" {
				comparerComplet(t, res, att)
				rapportConforme(t, res, "fr")
				return
			}
			// Comparaison partielle : ce qui ne relève pas des contrôles 4,
			// 5 et 8.
			if res.Erreur != nil && len(res.AConstruire) == 0 {
				t.Fatalf("erreur inattendue : %s", res.Erreur.Message.Fr)
			}
			echecs, nonExec := echecsEtBloquantes(res.Verifs, func(id string) bool {
				return familleCoeur(id)
			})
			if att := filtrer(att.FailedChecks, familleCoeur); !egalListes(echecs, att) {
				t.Errorf("vérifications en échec (hors 4, 5, 8) %v, attendu %v", echecs, att)
			}
			var attNE []etat
			for _, e := range att.NotExecuted {
				if familleCoeur(e.ID) {
					attNE = append(attNE, e)
				}
			}
			if formatEtats(nonExec) != formatEtats(attNE) {
				t.Errorf("vérifications non exécutées (hors 4, 5, 8) %s, attendu %s", formatEtats(nonExec), formatEtats(attNE))
			}
			for _, n := range []string{"1", "2", "3", "6", "7"} {
				k := int(n[0] - '0')
				if string(res.Controles[k].Statut) != att.ControlStatuses[n] {
					t.Errorf("contrôle %s : %s, attendu %s", n, res.Controles[k].Statut, att.ControlStatuses[n])
				}
			}
			comparerPerimetre(t, res, att.PerimeterChecks, nil)
			av := avertissements(res, func(id string) bool { return strings.HasPrefix(id, "AV-AT-") })
			if a := filtrer(att.Warnings, func(id string) bool { return strings.HasPrefix(id, "AV-AT-") }); !egalListes(av, a) {
				t.Errorf("avertissements AV-AT- %v, attendu %v", av, a)
			}
			t.Skip(attente)
		})
	}
}

func comparerComplet(t *testing.T, res *Resultat, att attenduCT6) {
	t.Helper()
	if att.ExitCode == 2 {
		if res.Code != 2 {
			t.Errorf("code %d, attendu 2", res.Code)
		}
		return
	}
	if res.Erreur != nil {
		t.Fatalf("erreur inattendue : %s", res.Erreur.Message.Fr)
	}
	if res.Code != att.ExitCode {
		t.Errorf("code %d, attendu %d", res.Code, att.ExitCode)
	}
	echecs, nonExec := echecsEtBloquantes(res.Verifs, func(string) bool { return true })
	if !egalListes(echecs, att.FailedChecks) {
		t.Errorf("vérifications en échec %v, attendu %v", echecs, att.FailedChecks)
	}
	if formatEtats(nonExec) != formatEtats(att.NotExecuted) {
		t.Errorf("non exécutées %s, attendu %s", formatEtats(nonExec), formatEtats(att.NotExecuted))
	}
	for n := 1; n <= 8; n++ {
		k := string(rune('0' + n))
		if string(res.Controles[n].Statut) != att.ControlStatuses[k] {
			t.Errorf("contrôle %d : %s, attendu %s", n, res.Controles[n].Statut, att.ControlStatuses[k])
		}
	}
	av := avertissements(res, func(string) bool { return true })
	if !egalListes(av, att.Warnings) {
		t.Errorf("avertissements %v, attendu %v", av, att.Warnings)
	}
	r := res.Rapport
	if att.Statement != nil {
		if r.Statement.Fr != att.Statement.Fr {
			t.Errorf("énoncé fr :\n obtenu  %s\n attendu %s", r.Statement.Fr, att.Statement.Fr)
		}
		if r.Statement.En != att.Statement.En {
			t.Errorf("énoncé en :\n obtenu  %s\n attendu %s", r.Statement.En, att.Statement.En)
		}
	}
	switch {
	case att.Bound == nil && r.Lisible.BorneBilingue != nil:
		t.Errorf("borne %q, attendue nulle", r.Lisible.BorneBilingue.Fr)
	case att.Bound != nil && (r.Lisible.BorneBilingue == nil || r.Lisible.BorneBilingue.Fr != att.Bound.Fr || r.Lisible.BorneBilingue.En != att.Bound.En):
		t.Errorf("borne %v, attendue %v", r.Lisible.BorneBilingue, att.Bound)
	}
	comparerPerimetre(t, res, att.PerimeterChecks, att.PerimeterRetained)
}

// TestInventaireVecteurs compte les dossiers rejoués en entier et ceux qui
// restent en attente des contrôles 4, 5 et 8. Les développeurs de ces
// contrôles voient ici l'effet de leur travail : l'attente d'un dossier se
// lève d'elle-même quand Construit() des contrôles dont il dépend vaut vrai.
func TestInventaireVecteurs(t *testing.T) {
	type compte struct{ total, rejoues, attente int }
	var ct1, ct6 compte
	parControle := map[string]int{}
	for _, r := range []struct {
		racine string
		c      *compte
	}{{racineCT1, &ct1}, {racineCT6, &ct6}} {
		for _, nom := range dossiers(t, r.racine) {
			r.c.total++
			req := controlesRequis(t, filepath.Join(r.racine, nom))
			if enAttente(req) != "" {
				r.c.attente++
				var k []string
				for _, n := range []int{4, 5, 8} {
					if req[n] {
						k = append(k, string(rune('0'+n)))
					}
				}
				parControle[strings.Join(k, "+")]++
			} else {
				r.c.rejoues++
			}
		}
	}
	t.Logf("CT-1 : %d dossiers, %d rejoués en entier, %d en attente", ct1.total, ct1.rejoues, ct1.attente)
	t.Logf("CT-6 : %d dossiers, %d rejoués en entier, %d en attente (comparaison partielle hors 4, 5, 8)", ct6.total, ct6.rejoues, ct6.attente)
	t.Logf("total : %d dossiers, %d rejoués en entier, %d en attente", ct1.total+ct6.total, ct1.rejoues+ct6.rejoues, ct1.attente+ct6.attente)
	var cles []string
	for k := range parControle {
		cles = append(cles, k)
	}
	sort.Strings(cles)
	for _, k := range cles {
		t.Logf("  en attente du ou des contrôles %s : %d", k, parControle[k])
	}
	if ct1.total != 70 || ct6.total != 73 {
		t.Errorf("nombre de dossiers inattendu : CT-1 %d (70 attendus), CT-6 %d (73 attendus)", ct1.total, ct6.total)
	}
	if ct1.rejoues+ct1.attente != ct1.total || ct6.rejoues+ct6.attente != ct6.total {
		t.Errorf("inventaire incohérent")
	}
}
