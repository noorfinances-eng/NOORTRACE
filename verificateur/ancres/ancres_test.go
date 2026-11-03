package ancres

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const repAncres = "../../spec/vecteurs/ct-6/ancres"

func TestFichiersDeTest(t *testing.T) {
	ents, err := os.ReadDir(repAncres)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		a, d := Lire(filepath.Join(repAncres, e.Name()), nil)
		if d != nil {
			t.Errorf("%s : %s", e.Name(), d.Message.Fr)
			continue
		}
		if len(a.Autorites) == 0 || a.Bitcoin == nil || a.Registre == nil {
			t.Errorf("%s : ancres incomplètes", e.Name())
		}
	}
}

func ecrire(t *testing.T, contenu string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "ancres.json")
	if err := os.WriteFile(f, []byte(contenu), 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

// TestRefusN1 : un fichier d'ancres défectueux rend l'entrée inutilisable
// (EX-4.10, EX-12.2, EX-14.11).
func TestRefusN1(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repAncres, "ancres-test.json"))
	if err != nil {
		t.Fatal(err)
	}
	base := string(b)
	cas := map[string]string{
		"pas du JSON":          "{",
		"tableau":              "[]",
		"version 1":            strings.Replace(base, `"version": 0`, `"version": 1`, 1),
		"membre en trop":       strings.Replace(base, `"version": 0`, `"version": 0, "extra": 1`, 1),
		"date inexistante":     strings.Replace(base, `"prepared_at": "2026-11-10T08:00:00.000Z"`, `"prepared_at": "2026-02-30T08:00:00.000Z"`, 1),
		"triplet en double":    strings.Replace(base, `"key_id": "rec-test-02"`, `"key_id": "rec-test-01"`, 1),
		"clé de validateur":    strings.Replace(base, `"pubKeyHex": "0x0405de9b`, `"pubKeyHex": "0x0505de9b`, 1),
		"validateur en double": strings.Replace(base, `"id": "v2"`, `"id": "v1"`, 1),
		"PEM tronqué":          strings.Replace(base, `MII`, `MIJ`, 1),
		// Sans forme canonique (CT-6 EX-4.12, point 3, révision
		// 0.4) : refusé au lieu d'être lu par arrondi ou en dernière
		// occurrence.
		"nombre non entier":     strings.Replace(base, `"height": 1000,`, `"height": 1000.0,`, 1),
		"exposant":              strings.Replace(base, `"height": 1000,`, `"height": 1e3,`, 1),
		"nom en double":         strings.Replace(base, `"version": 0`, `"version": 0, "version": 0`, 1),
		"identifiant vide":      strings.Replace(base, `"id": "v2"`, `"id": " \t"`, 1),
		"doublon après espaces": strings.Replace(base, `"id": "v2"`, `"id": " v1 "`, 1),
	}
	for nom, c := range cas {
		_, d := Lire(ecrire(t, c), nil)
		if d == nil {
			t.Errorf("%s : accepté", nom)
			continue
		}
		if d.Genre != "ancres_inutilisables" || d.Verification != "N-1" {
			t.Errorf("%s : %s %s", nom, d.Genre, d.Verification)
		}
	}
	if _, d := Lire(filepath.Join(t.TempDir(), "absent.json"), nil); d == nil || d.Genre != "ancres_inutilisables" {
		t.Error("fichier absent")
	}
}

// TestRefusN2 : fichier d'en-têtes (EX-12.3, EX-4.12).
func TestRefusN2(t *testing.T) {
	ok := `{"version":0,"network":"regtest","start_height":10,"source":"essai","headers":["0x` + strings.Repeat("00", 80) + `"]}`
	if _, d := LireEntetes(ecrire(t, ok)); d != nil {
		t.Fatalf("fichier conforme refusé : %s", d.Message.Fr)
	}
	cas := map[string]string{
		"pas du JSON":          "{",
		"version 1":            strings.Replace(ok, `"version":0`, `"version":1`, 1),
		"réseau":               strings.Replace(ok, `regtest`, `testnet`, 1),
		"en-tête de 79 octets": strings.Replace(ok, `"0x`+strings.Repeat("00", 80), `"0x`+strings.Repeat("00", 79), 1),
		"hauteur ≥ 2^32":       strings.Replace(ok, `"start_height":10`, `"start_height":4294967295`, 1) + "",
	}
	cas["nombre non entier"] = strings.Replace(ok, `"start_height":10`, `"start_height":10.0`, 1)
	cas["nom en double"] = strings.Replace(ok, `"version":0`, `"version":0,"version":0`, 1)
	cas["hauteur ≥ 2^32"] = strings.Replace(strings.Replace(ok, `"start_height":10`, `"start_height":4294967295`, 1), `"]}`, `","0x`+strings.Repeat("00", 80)+`"]}`, 1)
	for nom, c := range cas {
		_, d := LireEntetes(ecrire(t, c))
		if d == nil {
			t.Errorf("%s : accepté", nom)
			continue
		}
		if d.Genre != "entree_illisible" || d.Verification != "N-2" {
			t.Errorf("%s : %s %s", nom, d.Genre, d.Verification)
		}
	}
	// Plus de 200 000 en-têtes : taille dépassée.
	var sb strings.Builder
	sb.WriteString(`{"version":0,"network":"regtest","start_height":0,"source":"essai","headers":[`)
	h := `"0x` + strings.Repeat("00", 80) + `"`
	for i := 0; i < 200001; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(h)
	}
	sb.WriteString("]}")
	if _, d := LireEntetes(ecrire(t, sb.String())); d == nil || d.Genre != "taille_depassee" {
		t.Errorf("200 001 en-têtes : %v", d)
	}
}

// TestIdentifiantsEspaces : un jeu de validateurs se charge comme le nœud
// le charge (EX-12.2) : identifiants lus après strings.TrimSpace.
func TestIdentifiantsEspaces(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repAncres, "ancres-test.json"))
	if err != nil {
		t.Fatal(err)
	}
	c := strings.Replace(string(b), `"id": "v4"`, `"id": " v4\n"`, 1)
	if c == string(b) {
		t.Fatal("modification sans effet")
	}
	a, d := Lire(ecrire(t, c), nil)
	if d != nil {
		t.Fatalf("identifiant entouré d'espaces refusé : %s", d.Message.Fr)
	}
	trouve := false
	for _, j := range a.Registre.Jeux {
		for _, v := range j.Validateurs {
			if v.ID == "v4" {
				trouve = true
			}
			if strings.TrimSpace(v.ID) != v.ID {
				t.Errorf("identifiant non normalisé : %q", v.ID)
			}
		}
	}
	if !trouve {
		t.Error("v4 absent du jeu chargé")
	}
}

func TestN3(t *testing.T) {
	a, d := Lire(filepath.Join(repAncres, "ancres-test.json"), nil)
	if d != nil {
		t.Fatal(d.Message.Fr)
	}
	org := "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab"
	jr := "0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164"
	cles := []CleDossier{{"rec-test-01", "0xe2116fdce7f27ff208971b6c821f9691a4a9a29bc407224eaf0c4b60c1174045"}, {"rec-test-02", "0xfd08757fa4798c3c8757bbf5a0db49580cbcb80075ddb30f13f881b0f47aacb3"}}
	r := a.VerifierN3(EntreeN3{OrgID: org, JournalID: jr, ClesExploitables: true, Cles: cles, Signataires: []string{"rec-test-01", "rec-test-02"}})
	if !r.Figure || r.Verification.Statut != "reussi" || !r.Confirmees["rec-test-01"] || !r.Confirmees["rec-test-02"] {
		t.Errorf("N-3 : %+v", r.Verification)
	}
	cles[0].ClePublique = cles[1].ClePublique
	if r := a.VerifierN3(EntreeN3{OrgID: org, JournalID: jr, ClesExploitables: true, Cles: cles, Signataires: []string{"rec-test-01"}}); r.Verification.Statut != "echoue" {
		t.Error("clé différente non vue")
	}
	if r := a.VerifierN3(EntreeN3{OrgID: org, JournalID: "0x" + strings.Repeat("11", 32), ClesExploitables: true, Cles: cles}); r.Figure {
		t.Error("N-3 figure pour un autre journal (EX-5.6)")
	}
	if r := a.VerifierN3(EntreeN3{OrgID: org, JournalID: jr, Cles: cles}); r.Verification.Raison != "prerequis_en_echec" {
		t.Error("cles.json inexploitable : prerequis_en_echec attendu")
	}
	if r := a.VerifierN3(EntreeN3{OrgID: org, JournalID: jr, ClesExploitables: true, Cles: cles, Signataires: []string{"rec-autre"}}); r.Verification.Raison != "ancre_absente" {
		t.Error("aucune clé comparée : ancre_absente attendu")
	}
}
