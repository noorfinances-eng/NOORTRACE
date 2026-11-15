package main

// Essais de la revue de sécurité de l'étape 8 (CT-1 révision 0.6) : A-2 sur
// events vide et borne des 1 024 décisions (§11.4), règle root d'une série
// jugée sur les événements fournis (§10.5, tree_size géant), plancher de
// l'oracle et cas comptés contre INDEX.md (§13).

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// lancer rend le code de retour et la sortie de main() sur les arguments.
func lancer(t *testing.T, args ...string) (int, string) {
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

// approbationsModifiees rend une altération de approbations.json qui
// remplace events par la liste rendue par f (forme canonique).
func approbationsModifiees(t *testing.T, f func(premier string) []string) func(string) string {
	return func(s string) string {
		ap, err := ParseJSON([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		premier, err := Canonique(ap.Get("events").Arr[0])
		if err != nil {
			t.Fatal(err)
		}
		nouveau, err := ParseJSON([]byte("[" + strings.Join(f(string(premier)), ",") + "]"))
		if err != nil {
			t.Fatal(err)
		}
		for i := range ap.Obj {
			if ap.Obj[i].Key == "events" {
				ap.Obj[i].Val = nouveau
			}
		}
		c, err := Canonique(ap)
		if err != nil {
			t.Fatal(err)
		}
		return string(c)
	}
}

// §11.4, A-2 (révision 0.6) : events compte au moins une décision ; absent
// ou vide, A-2 échoue (« aucun événement de décision »).
func TestRevueA2EvenementsVides(t *testing.T) {
	src := publie("valide-seq-7")
	verifierCas(t, []casDossier{
		{nom: "approbations.json réduit à {} : A-1, A-2, A-3", src: src, reindexer: true,
			alteration: map[string]func(string) string{"approbations.json": remplacerContenu("{}")},
			echecs:     []string{"A-1", "A-2", "A-3"}},
		{nom: "events vide : A-1 (schéma), A-2", src: src, reindexer: true,
			alteration: map[string]func(string) string{"approbations.json": approbationsModifiees(t, func(string) []string { return nil })},
			echecs:     []string{"A-1", "A-2"}},
	})
}

// §11.4, A-2 (révision 0.6) : au-delà de 1 024 décisions, A-1 échoue par le
// schéma, A-2 compte et nomme les éléments en trop, qui ne sont ni contrôlés
// ni rapportés un à un (ici, les éléments en trop sont des événements au
// hash faux : aucun contrôle E- ne doit le voir).
func TestRevueA2Borne(t *testing.T) {
	src := publie("valide-seq-7")
	faux := func(premier string) string {
		i := strings.Index(premier, `"hash":"0x`) + len(`"hash":"0x`)
		c := byte('0')
		if premier[i] == '0' {
			c = '1'
		}
		return premier[:i] + string(c) + premier[i+1:]
	}
	alt := approbationsModifiees(t, func(premier string) []string {
		var l []string
		for i := 0; i < 1024; i++ {
			l = append(l, premier)
		}
		for i := 0; i < 6; i++ {
			l = append(l, faux(premier))
		}
		return l
	})
	d := VerifierDossier(copierDossier(t, src, map[string]func(string) string{"approbations.json": alt}, true))
	if got := strings.Join(d.Resultats.Echecs(), ","); got != "A-1,A-2" {
		t.Fatalf("échecs [%s], attendu [A-1,A-2]\n%s", got, d.Resultats.Resume("  "))
	}
	a2 := strings.Join(d.Resultats.parID["A-2"].Details, "\n")
	if !strings.Contains(a2, "6 élément(s) de events au-delà des 1024") || !strings.Contains(a2, "approbations.events[1024] à approbations.events[1029]") {
		t.Errorf("A-2 ne compte pas ni ne nomme les éléments en trop :\n%s", a2)
	}
	for _, c := range d.Resultats.parID {
		for _, x := range c.Details {
			if strings.Contains(x, "approbations.events[1024]") && c.ID != "A-2" {
				t.Errorf("%s rapporte un élément au-delà de la borne : %s", c.ID, x)
			}
		}
	}
	// 1 024 décisions exactement : dans la borne, aucun échec.
	alt1024 := approbationsModifiees(t, func(premier string) []string {
		l := make([]string, 1024)
		for i := range l {
			l[i] = premier
		}
		return l
	})
	d = VerifierDossier(copierDossier(t, src, map[string]func(string) string{"approbations.json": alt1024}, true))
	if got := d.Resultats.Echecs(); len(got) != 0 {
		t.Errorf("1 024 décisions : échecs %v, attendu aucun", got)
	}
}

// §10.5 (règle root, revue de sécurité) : un point de tree_size 2^53 − 1 se
// juge sur les événements fournis ; la série est jugée en moins de 5 s.
func TestRevueSerieTreeSizeGeant(t *testing.T) {
	racine := racineVecteursCT1
	f := filepath.Join(racine, "points-de-controle", "periode-1.json")
	if !fichierExiste(f) {
		t.Skip("vecteurs publiés absents")
	}
	points := lireTest(t, f).Arr
	m1 := LireManifeste(lireTest(t, filepath.Join(racine, "manifestes", "periode-1.json")))
	evs := lireTest(t, filepath.Join(racine, "journal-valide", "evenements.json")).Arr
	jeu, _ := ChargerCles(lireTest(t, filepath.Join(racine, "cles", "cles.json")))
	der := len(points) - 1
	c, _ := Canonique(points[der])
	texte := strings.Replace(strings.Replace(string(c), `"tree_size":9`, `"tree_size":9007199254740991`, 1), `"last_seq":9`, `"last_seq":9007199254740991`, 1)
	serie := append([]*Value{}, points...)
	serie[der] = objetDe(t, texte)
	type sortie struct {
		regles []string
		ne     []RegleNonEvaluee
	}
	fin := make(chan sortie, 1)
	go func() {
		r, _, ne := ControlerSerie(serie, m1, evs, jeu, false)
		fin <- sortie{r, ne}
	}()
	select {
	case s := <-fin:
		if got := strings.Join(s.regles, ",") + " | " + texteNonEvaluees(s.ne); got != "last_seq,dernier_point,signature | root:piece_hors_dossier,last_hash:piece_hors_dossier" {
			t.Errorf("série géante : %s", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("série de tree_size 2^53 − 1 non jugée en 5 s : la règle root parcourt tree_size numéros de séquence")
	}
}

// §13 (révision 0.6) : racine vide, famille absente, cas retiré : code 1 ;
// vecteurs complets : code 0.
func TestRevuePlancher(t *testing.T) {
	racine := racineVecteursCT1
	if !fichierExiste(filepath.Join(racine, "dossiers")) || !fichierExiste(filepath.Join(racine, "INDEX.md")) {
		t.Skip("vecteurs publiés absents")
	}
	abs, err := filepath.Abs(racine)
	if err != nil {
		t.Fatal(err)
	}
	monter := func(sansEntree string, sansDossier string) string {
		return monterAvec(t, abs, sansEntree, sansDossier)
	}
	cas := []struct {
		nom, racine, message string
	}{
		{"racine vide", t.TempDir(), "révision 0.6) : aucune valeur recalculée"},
		{"sans dossiers/", monter("dossiers", ""), "famille dossiers absente : dossiers introuvable"},
		{"sans merkle/", monter("merkle", ""), "famille coherence absente : merkle/coherence.json introuvable"},
		{"jcs sans cas", jcsSansCas(t, monter("jcs", "")), "famille jcs : aucune valeur recalculée"},
		{"sans INDEX.md", monter("INDEX.md", ""), "INDEX.md illisible"},
		{"un dossier retiré", monter("", "invalide-hash-faux"), "le cas invalide-hash-faux/ est nommé mais absent de la racine"},
		{"un dossier de trop", dossierEnTrop(t, abs, monter("", "-")), "le cas copie-non-indexee/ est présent mais l'index ne le nomme pas"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			code, sortie := lancer(t, c.racine)
			if code != 1 || !strings.Contains(sortie, c.message) {
				t.Errorf("code %d (attendu 1), message « %s » attendu :\n%s", code, c.message, sortie)
			}
		})
	}
	t.Run("vecteurs complets", func(t *testing.T) {
		if code, sortie := lancer(t, abs); code != 0 {
			t.Errorf("code %d, attendu 0 :\n%s", code, sortie)
		}
	})
}

// jcsSansCas place dans la racine une famille jcs présente mais sans cas.
func jcsSansCas(t *testing.T, racine string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(racine, "jcs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(racine, "jcs", "cas-limites.json"), []byte(`{"cas":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return racine
}

// dossierEnTrop ajoute à dossiers/ un lien vers un dossier publié sous un
// nom que l'INDEX.md ne nomme pas.
func dossierEnTrop(t *testing.T, abs, racine string) string {
	t.Helper()
	if err := os.Symlink(filepath.Join(abs, "dossiers", "valide-seq-7"), filepath.Join(racine, "dossiers", "copie-non-indexee")); err != nil {
		t.Fatal(err)
	}
	return racine
}

// monterAvec rend une racine faite de liens vers les entrées publiées, sauf
// sansEntree ; avec sansDossier non vide, dossiers/ est un répertoire réel
// fait de liens vers chaque dossier publié sauf sansDossier.
func monterAvec(t *testing.T, abs, sansEntree, sansDossier string) string {
	t.Helper()
	dst := t.TempDir()
	es, err := os.ReadDir(abs)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range es {
		n := e.Name()
		if n == sansEntree || n == "verificateur-independant" {
			continue
		}
		if n == "dossiers" && sansDossier != "" {
			if err := os.Mkdir(filepath.Join(dst, n), 0o755); err != nil {
				t.Fatal(err)
			}
			ds, _ := os.ReadDir(filepath.Join(abs, n))
			for _, d := range ds {
				if d.Name() != sansDossier {
					if err := os.Symlink(filepath.Join(abs, n, d.Name()), filepath.Join(dst, n, d.Name())); err != nil {
						t.Fatal(err)
					}
				}
			}
			continue
		}
		if err := os.Symlink(filepath.Join(abs, n), filepath.Join(dst, n)); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}
