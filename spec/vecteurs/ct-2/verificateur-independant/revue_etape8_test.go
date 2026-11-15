package main

// Essais de la revue de sécurité de l'étape 8 : réponse d'evaluer à neuf
// membres et épinglage (CT-2 EX-7.16 révision 0.11, annexe B.4), ancres d'un
// motif nommé après une correspondance remplacée (EX-10.9) et passages sans
// borne arbitraire (EX-10.14), entrée absente sans panique (garde nil),
// plancher de l'oracle et cas comptés contre INDEX.md (CT-9 TA-66).

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestMain permet aux essais du plancher de lancer main() dans un processus
// fils (code de retour observé tel que le module le rend).
func TestMain(m *testing.M) {
	if os.Getenv("NOORTRACE_REVUE_MAIN") == "1" {
		os.Args = append([]string{"verificateur-independant"}, strings.Split(os.Getenv("NOORTRACE_REVUE_ARGS"), "\x1f")...)
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func lancerCT2(t *testing.T, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "NOORTRACE_REVUE_MAIN=1", "NOORTRACE_REVUE_ARGS="+strings.Join(args, "\x1f"))
	var sortie bytes.Buffer
	cmd.Stdout, cmd.Stderr = &sortie, &sortie
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, sortie.String()
	case errors.As(err, &ee):
		return ee.ExitCode(), sortie.String()
	}
	t.Fatal(err)
	return -1, ""
}

const epinglageTexte = `"policy_version":"2026-11-01","policy_sha256":"0xc5dac49797e5d273c2209e9ef6b44f77b80a2b927d2ddc8e93fc759d979b030c","approval_sha256":"0xa866fa5ab951735156052400d148b06654c1534b848251db81ab38b4af180589"`

// EX-7.16 (révision 0.11) : neuf membres exactement, les trois de
// l'épinglage dans la forme de CT-3 §12.3.
func TestRevueReponseEvaluerNeufMembres(t *testing.T) {
	six := `{"rule":"paiement hors CHF","decision":"refuse","ticket":null,"ticket_state":null,"approval":null,"approver_set":null`
	if issue, raison := IssueReponseEvaluer(doit(t, six+","+epinglageTexte+"}")); issue != IssueRefus || raison != "" {
		t.Errorf("réponse à neuf membres : %q (%s), attendu refus", issue, raison)
	}
	if issue, raison := IssueReponseEvaluer(valeurSpec(t, "annexe-a-reponse-evaluer.json")); issue != IssueNouveau || raison != "" {
		t.Errorf("réponse de l'annexe A (révision 0.11) : %q (%s)", issue, raison)
	}
	for nom, txt := range map[string]string{
		"six membres (révision 0.10)":      six + "}",
		"dix membres":                      six + "," + epinglageTexte + `,"x":1}`,
		"policy_version vide":              six + `,"policy_version":"","policy_sha256":"0xc5dac49797e5d273c2209e9ef6b44f77b80a2b927d2ddc8e93fc759d979b030c","approval_sha256":"0xa866fa5ab951735156052400d148b06654c1534b848251db81ab38b4af180589"}`,
		"policy_version de 129 car.":       six + `,"policy_version":"` + strings.Repeat("v", 129) + `","policy_sha256":"0xc5dac49797e5d273c2209e9ef6b44f77b80a2b927d2ddc8e93fc759d979b030c","approval_sha256":"0xa866fa5ab951735156052400d148b06654c1534b848251db81ab38b4af180589"}`,
		"policy_sha256 en majuscules":      six + `,"policy_version":"2026-11-01","policy_sha256":"0xC5DAC49797E5D273C2209E9EF6B44F77B80A2B927D2DDC8E93FC759D979B030C","approval_sha256":"0xa866fa5ab951735156052400d148b06654c1534b848251db81ab38b4af180589"}`,
		"approval_sha256 de 31 octets":     six + `,"policy_version":"2026-11-01","policy_sha256":"0xc5dac49797e5d273c2209e9ef6b44f77b80a2b927d2ddc8e93fc759d979b030c","approval_sha256":"0xa866fa5ab951735156052400d148b06654c1534b848251db81ab38b4af1805"}`,
		"policy_version qui est un nombre": six + `,"policy_version":20261101,"policy_sha256":"0xc5dac49797e5d273c2209e9ef6b44f77b80a2b927d2ddc8e93fc759d979b030c","approval_sha256":"0xa866fa5ab951735156052400d148b06654c1534b848251db81ab38b4af180589"}`,
	} {
		if issue, raison := IssueReponseEvaluer(doit(t, txt)); issue != "" || raison == "" {
			t.Errorf("%s : acceptée (%s)", nom, issue)
		}
	}
	if issue, _ := IssueReponseEvaluer(doit(t, six+`,"policy_version":"`+strings.Repeat("é", 128)+`","policy_sha256":"0xc5dac49797e5d273c2209e9ef6b44f77b80a2b927d2ddc8e93fc759d979b030c","approval_sha256":"0xa866fa5ab951735156052400d148b06654c1534b848251db81ab38b4af180589"}`)); issue != IssueRefus {
		t.Errorf("policy_version de 128 caractères (256 octets) : refusée")
	}
}

// Annexe B.4 et EX-7.16 (révision 0.11) : approval = { response, pinned } ;
// les trois membres de la réponse égaux à ceux de pinned, sinon la réponse
// est invalide (politique_non_epinglee).
func TestRevueEpinglagePiecesMCP(t *testing.T) {
	src := filepath.Join("..", "pieces-mcp", "appels", "approbation-refus")
	if !fichierExiste(filepath.Join(src, "attendu.json")) {
		t.Skip("vecteurs publiés absents")
	}
	monter := func(pinned string) string {
		racine := t.TempDir()
		dst := filepath.Join(racine, "pieces-mcp", "appels", "approbation-refus")
		if err := os.MkdirAll(dst, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, f := range []string{"hote.jsonl", "amont.jsonl"} {
			b, err := os.ReadFile(filepath.Join(src, f))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dst, f), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		b, _ := os.ReadFile(filepath.Join(src, "attendu.json"))
		att := doit(t, string(b))
		rep := Copier(att.Get("approval").Get("response"))
		if rep.Get("policy_version") == nil {
			for _, m := range doit(t, "{"+epinglageTexte+"}").Obj {
				Definir(rep, m.Key, m.Val)
			}
		}
		approval := Objet("response", rep)
		if pinned != "" {
			Definir(approval, "pinned", doit(t, pinned))
		}
		Definir(att, "approval", approval)
		c, err := CanoniqueIntegral(att)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, "attendu.json"), c, 0o644); err != nil {
			t.Fatal(err)
		}
		return racine
	}
	juger := func(racine string) (string, []string) {
		rap := &Rapport{Titre: TitreRapportCT2, Racine: racine, Comparaisons: []Comparaison{}, Erreurs: []string{}, Notes: []string{}, Details: []string{}}
		ctx := &contexteCT2{racine: racine, appels: map[string]*Value{}, issuesApprobation: map[string]string{}}
		famillePiecesMCP(rap, ctx)
		obtenu := "absent"
		for _, c := range rap.Comparaisons {
			if c.Vecteur == "appels/approbation-refus" && strings.HasPrefix(c.Grandeur, "approval.response") {
				obtenu = c.Obtenu
				if c.Concorde {
					obtenu = "concorde"
				}
			}
		}
		var erreurs []string
		for _, e := range rap.Erreurs {
			if strings.Contains(e, "approbation-refus") {
				erreurs = append(erreurs, e)
			}
		}
		return obtenu, erreurs
	}
	if got, errs := juger(monter("{" + epinglageTexte + "}")); got != "concorde" || len(errs) > 0 {
		t.Errorf("réponse épinglée : %s %v", got, errs)
	}
	if got, _ := juger(monter(strings.Replace("{"+epinglageTexte+"}", "0xc5dac4", "0xd5dac4", 1))); !strings.Contains(got, "politique_non_epinglee") {
		t.Errorf("policy_sha256 différent de l'épinglage : %s", got)
	}
	if got, _ := juger(monter(strings.Replace("{"+epinglageTexte+"}", "2026-11-01", "2026-11-02", 1))); !strings.Contains(got, "politique_non_epinglee") {
		t.Errorf("policy_version différente de l'épinglage : %s", got)
	}
	if got, _ := juger(monter(strings.Replace("{"+epinglageTexte+"}", "0xa866fa", "0xb866fa", 1))); !strings.Contains(got, "politique_non_epinglee") {
		t.Errorf("approval_sha256 différent de l'épinglage : %s", got)
	}
	if got, _ := juger(monter("")); !strings.Contains(got, "approval.pinned absent") {
		t.Errorf("sans pinned : %s", got)
	}
}

// politiqueAncres : les motifs des vecteurs redaction/motif-ancre-* et
// passages-en-cascade, dans une règle de portée resultat.
func politiqueAncres(t *testing.T) *Politique {
	t.Helper()
	p, mq := ChargerPolitique(doit(t, `{"version":0,"name":"ancres-test","description":"essai","pseudonym_key":null,
	  "named_patterns":{"ancre-non-frontiere":{"pattern":"\\Bz","description":"d"},"ancre-alternative":{"pattern":"x|\\b#","description":"d"},
	    "ancre-debut":{"pattern":"^[0-9]{3}","description":"d"},"cascade-a":{"pattern":"A\\b","description":"d"},"cascade-b":{"pattern":"B$","description":"d"}},
	  "rules":[{"id":"motifs-ancres","description":"d","scopes":["resultat"],"tools":["ancres__test"],
	    "detectors":[{"type":"regex","name":"ancre-non-frontiere"},{"type":"regex","name":"ancre-alternative"},{"type":"regex","name":"ancre-debut"},{"type":"regex","name":"cascade-a"},{"type":"regex","name":"cascade-b"}],
	    "action":{"kind":"remplacer"}}]}`))
	if len(mq) > 0 {
		t.Fatalf("politique : %v", mq)
	}
	return p
}

// EX-10.9 (révision 0.11) : la position qui suit une correspondance
// remplacée est un début de chaîne pour les ancres et frontières du motif.
// EX-10.14 (révision 0.11) : aucune borne arbitraire du nombre de passages.
func TestRevueRedactionAncresEtPassages(t *testing.T) {
	p := politiqueAncres(t)
	j := func(n string) string { return "[REDIGE:" + n + "]" }
	cas := []struct {
		nom, entree, sortie, decomptes string
	}{
		{"\\Bz sur zzz", "zzz", "z" + j("ancre-non-frontiere") + "z", "regex:ancre-non-frontiere=1"},
		{"x|\\b# sur x#", "x#", j("ancre-alternative") + "#", "regex:ancre-alternative=1"},
		{"^[0-9]{3} sur trois candidats adjacents", "123123123", strings.Repeat(j("ancre-debut"), 3), "regex:ancre-debut=3"},
		{"cascade de 66 passages modificateurs", strings.Repeat("A", 65) + "B", strings.Repeat(j("cascade-a"), 65) + j("cascade-b"), "regex:cascade-b=1 ; regex:cascade-a=65"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			res := p.Appliquer("resultat", "ancres__test", Objet("note", Chaine(c.entree)))
			if got := chaineDe(res.Valeur, "note"); got != c.sortie {
				t.Errorf("pièce : %q, attendu %q (notes %v)", got, c.sortie, res.Notes)
			}
			var ds []string
			for _, d := range res.Decomptes {
				ds = append(ds, d.Detecteur+"="+itoa(d.Nombre))
			}
			if got := strings.Join(ds, " ; "); got != c.decomptes {
				t.Errorf("décomptes : %s, attendu %s", got, c.decomptes)
			}
			// EX-10.15 : idempotence.
			res2 := p.Appliquer("resultat", "ancres__test", res.Valeur)
			if chaineDe(res2.Valeur, "note") != chaineDe(res.Valeur, "note") {
				t.Errorf("non idempotente : %q", chaineDe(res2.Valeur, "note"))
			}
		})
	}
}

func itoa(n int) string {
	var b [20]byte
	i := len(b)
	if n == 0 {
		return "0"
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// monterRacineCT2 rend une racine faite de liens vers les entrées publiées ;
// les chemins de reels sont des répertoires réels faits de liens vers leurs
// entrées, sauf celles de sans (chemins relatifs à la racine).
func monterRacineCT2(t *testing.T, reels []string, sans map[string]bool) string {
	t.Helper()
	abs, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	var copier func(rel string)
	copier = func(rel string) {
		es, err := os.ReadDir(filepath.Join(abs, rel))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range es {
			r := filepath.Join(rel, e.Name())
			if sans[r] || r == "verificateur-independant" {
				continue
			}
			reel := false
			for _, x := range reels {
				if x == r {
					reel = true
				}
			}
			if reel {
				if err := os.MkdirAll(filepath.Join(dst, r), 0o755); err != nil {
					t.Fatal(err)
				}
				copier(r)
				continue
			}
			if err := os.Symlink(filepath.Join(abs, r), filepath.Join(dst, r)); err != nil {
				t.Fatal(err)
			}
		}
	}
	copier("")
	return dst
}

// Entrée absente sans panique : evenements/journal-demo/attendu.json absent : erreur
// consignée, rapport imprimé, code 1, jamais une panique.
func TestRevueEntreeAbsenteSansPanique(t *testing.T) {
	if !fichierExiste(filepath.Join("..", "evenements", "journal-demo", "attendu.json")) {
		t.Skip("vecteurs publiés absents")
	}
	racine := monterRacineCT2(t, []string{"evenements", filepath.Join("evenements", "journal-demo")}, map[string]bool{filepath.Join("evenements", "journal-demo", "attendu.json"): true})
	code, sortie := lancerCT2(t, racine)
	if code != 1 || strings.Contains(sortie, "panic") || strings.Contains(sortie, "panne interne") || !strings.Contains(sortie, "attendu.json : absent ou illisible ; famille evenements non confrontée") || !strings.Contains(sortie, "Total :") {
		t.Errorf("code %d (attendu 1, rapport imprimé, sans panique) :\n%s", code, sortie)
	}
}

// CT-9 TA-66 : racine vide, famille sans valeur, cas retiré, cas en trop :
// code 1 et l'erreur nommée.
func TestRevuePlancherCT2(t *testing.T) {
	if !fichierExiste(filepath.Join("..", "INDEX.md")) || !fichierExiste(filepath.Join("..", "pieces-modele")) {
		t.Skip("vecteurs publiés absents")
	}
	abs, _ := filepath.Abs("..")
	jcsVide := monterRacineCT2(t, []string{"jcs-integral"}, map[string]bool{filepath.Join("jcs-integral", "cas.json"): true})
	if err := os.WriteFile(filepath.Join(jcsVide, "jcs-integral", "cas.json"), []byte(`{"cas":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	es, _ := os.ReadDir(filepath.Join(abs, "pieces-modele"))
	retire := es[0].Name()
	sansModele := monterRacineCT2(t, []string{"pieces-modele"}, map[string]bool{filepath.Join("pieces-modele", retire): true})
	enTrop := monterRacineCT2(t, []string{"pieces-modele"}, nil)
	if err := os.Symlink(filepath.Join(abs, "pieces-modele", retire), filepath.Join(enTrop, "pieces-modele", "copie-non-indexee")); err != nil {
		t.Fatal(err)
	}
	cas := []struct{ nom, racine, message string }{
		{"racine vide", t.TempDir(), "plancher (CT-9 TA-66) : famille redaction : aucune valeur recalculée"},
		{"jcs-integral sans cas", jcsVide, "famille jcs-integral : aucune valeur recalculée"},
		{"un cas de pieces-modele retiré", sansModele, "le cas " + retire + " est nommé mais absent de la racine"},
		{"un cas de pieces-modele en trop", enTrop, "le cas copie-non-indexee est présent mais l'index ne le nomme pas"},
		{"sans INDEX.md", monterRacineCT2(t, nil, map[string]bool{"INDEX.md": true}), "plancher (CT-9 TA-66) : INDEX.md illisible"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			code, sortie := lancerCT2(t, c.racine)
			if code != 1 || !strings.Contains(sortie, c.message) {
				t.Errorf("code %d (attendu 1), message « %s » attendu :\n%s", code, c.message, sortie)
			}
		})
	}
}
