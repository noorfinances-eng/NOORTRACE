package main

// Essais de la revue de sécurité de l'étape 8 (CT-8 révision 0.8) : forme
// « première occurrence » des règles régénérées (EX-10.6), PV-7, PV-8 et
// PV-10 sous PV-2 (EX-11.18), familles absentes, plancher de l'oracle et
// cas comptés contre INDEX.md (CT-9 TA-66).

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

func lancerCT8(t *testing.T, args ...string) (int, string) {
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

// monterRacineCT8 rend une racine spec/vecteurs/ct-8 faite de liens vers les
// entrées publiées (le reste du dépôt en liens, pour ../../schemas, le texte
// et deploiement/), sauf celles de sans ; reels sont des répertoires réels.
func monterRacineCT8(t *testing.T, reels []string, sans map[string]bool) string {
	t.Helper()
	abs, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	spec := filepath.Join(dst, "spec")
	vec := filepath.Join(spec, "vecteurs")
	if err := os.MkdirAll(vec, 0o755); err != nil {
		t.Fatal(err)
	}
	specAbs := filepath.Dir(filepath.Dir(abs))
	depot := filepath.Dir(specAbs)
	for _, d := range []struct{ src, dst, sauf string }{{depot, dst, "spec"}, {specAbs, spec, "vecteurs"}, {filepath.Dir(abs), vec, "ct-8"}} {
		es, _ := os.ReadDir(d.src)
		for _, e := range es {
			if e.Name() != d.sauf {
				if err := os.Symlink(filepath.Join(d.src, e.Name()), filepath.Join(d.dst, e.Name())); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	racine := filepath.Join(vec, "ct-8")
	var copier func(rel string)
	copier = func(rel string) {
		if err := os.MkdirAll(filepath.Join(racine, rel), 0o755); err != nil {
			t.Fatal(err)
		}
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
				reel = reel || x == r
			}
			if reel {
				copier(r)
				continue
			}
			if err := os.Symlink(filepath.Join(abs, r), filepath.Join(racine, r)); err != nil {
				t.Fatal(err)
			}
		}
	}
	copier("")
	return racine
}

// EX-10.6 (révision 0.8) : une règle `increase(x[w]) OP n` sur un compteur
// de l'extracteur, du démon ou du composant d'ancrage est régénérée en
// `(increase(x[w]) OP n) or ((x unless x offset w) OP n)` ; dans une
// expression composée, `increase(S[w])` devient `((S unless S offset w) or
// increase(S[w]))` ; la forme vaut aussi pour `rate(x[w]) OP n` (arbitrage
// du 14 novembre). Un compteur du nœud du registre (noor_*), exposé à 0 dès
// le démarrage du nœud, n'est pas visé (TestRevuePremiereOccurrenceUnitaire).
func TestRevueEX106PremiereOccurrence(t *testing.T) {
	src := filepath.Join("..", "supervision", "regles-attendues.yml")
	b, err := os.ReadFile(src)
	if err != nil {
		t.Skip("vecteurs publiés absents")
	}
	longues := map[string][2]string{
		"noortrace_bail_renouvellement": {"'increase(noortrace_lease_renew_failures_total[5m]) > 0'",
			"'(increase(noortrace_lease_renew_failures_total[5m]) > 0) or ((noortrace_lease_renew_failures_total unless noortrace_lease_renew_failures_total offset 5m) > 0)'"},
		"noortrace_ancrage_volume": {"'sum(increase(noortrace_anchoring_attempts_total[1h])) > 2 * 76'",
			"'sum(((noortrace_anchoring_attempts_total unless noortrace_anchoring_attempts_total offset 1h) or increase(noortrace_anchoring_attempts_total[1h]))) > 2 * 76'"},
	}
	texte := string(b)
	for _, l := range longues {
		switch {
		case strings.Contains(texte, l[1]):
			// vecteur déjà régénéré dans la forme d'EX-10.6
		case strings.Contains(texte, l[0]):
			texte = strings.Replace(texte, l[0], l[1], 1)
		default:
			t.Fatalf("règle introuvable dans le vecteur : %s", l[0])
		}
	}
	racine := monterRacineCT8(t, []string{"supervision"}, map[string]bool{filepath.Join("supervision", "regles-attendues.yml"): true})
	if err := os.WriteFile(filepath.Join(racine, "supervision", "regles-attendues.yml"), []byte(texte), 0o644); err != nil {
		t.Fatal(err)
	}
	rap := VerifierVecteurs(racine)
	juge := map[string]bool{}
	for _, c := range rap.Comparaisons {
		if c.Grandeur != "SV-6 : règle régénérée (EX-10.6)" {
			continue
		}
		nom := strings.TrimPrefix(c.Vecteur, "supervision/")
		if _, ok := longues[nom]; ok {
			juge[nom] = true
			if !c.Concorde {
				t.Errorf("%s : attendu\n%s\nobtenu\n%s", nom, c.Attendu, c.Obtenu)
			}
		}
	}
	if len(juge) != 2 {
		t.Errorf("règles jugées : %v, deux attendues", juge)
	}
}

// EX-11.18, PV-2 (révision 0.8) : PV-7, PV-8 et PV-10 ne sont exécutées que
// si PV-2 a réussi.
func TestRevuePV2Prealable(t *testing.T) {
	rep := filepath.Join("..", "proces-verbaux")
	o, err := os.ReadFile(filepath.Join(rep, "invalides", "pv-2-non-trie.json"))
	if err != nil {
		t.Skip("vecteurs publiés absents")
	}
	abs, _ := filepath.Abs("..")
	rap := NouveauRapport(abs)
	c := &Contexte{Racine: abs, Spec: filepath.Join(abs, "..", ".."), Rap: rap, Schemas: map[string]*Schema{}}
	sb, err := os.ReadFile(filepath.Join(c.Spec, "schemas", "proces-verbal-exploitation-v0.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := ChargerSchema("proces-verbal-exploitation-v0", sb)
	if err != nil {
		t.Fatal(err)
	}
	c.Schemas["proces-verbal-exploitation-v0"] = s
	cb, _ := os.ReadFile(filepath.Join(rep, "cles.json"))
	cles, err := AnalyserJSON(cb)
	if err != nil {
		t.Fatal(err)
	}
	st := VerifierPV(c, o, filepath.Join(rep, "racine"), cles)
	if st["PV-2"] != "echoue" {
		t.Fatalf("PV-2 %s, echoue attendu", st["PV-2"])
	}
	for _, id := range []string{"PV-7", "PV-8", "PV-10"} {
		if st[id] != "non_execute" {
			t.Errorf("%s : %s, non_execute attendu (PV-2 en échec)", id, st[id])
		}
	}
}

// et CT-9 TA-66 : famille absente, famille sans valeur, cas retiré,
// cas non indexé, INDEX.md absent : code 1 et l'erreur nommée.
func TestRevuePlancherCT8(t *testing.T) {
	if _, err := os.Stat(filepath.Join("..", "INDEX.md")); err != nil {
		t.Skip("vecteurs publiés absents")
	}
	enTrop := monterRacineCT8(t, []string{"conteneurs"}, nil)
	if err := os.Symlink(filepath.Join(enTrop, "conteneurs", "valide-production.attendu.json"), filepath.Join(enTrop, "conteneurs", "copie-non-indexee.attendu.json")); err != nil {
		t.Fatal(err)
	}
	cas := []struct{ nom, racine, message string }{
		{"sans supervision/", monterRacineCT8(t, nil, map[string]bool{"supervision": true}), "famille supervision absente"},
		{"sans journaux/", monterRacineCT8(t, nil, map[string]bool{"journaux": true}), "famille journaux absente"},
		{"sans consultations/", monterRacineCT8(t, nil, map[string]bool{"consultations": true}), "plancher (CT-9 TA-66) : famille consultations : aucune valeur recalculée"},
		{"conteneur valide retiré", monterRacineCT8(t, []string{"conteneurs"}, map[string]bool{filepath.Join("conteneurs", "valide-production.attendu.json"): true}), "le cas valide-production est nommé mais absent de la racine"},
		{"conteneur non indexé", enTrop, "le cas copie-non-indexee est présent mais l'index ne le nomme pas"},
		{"procès-verbal retiré", monterRacineCT8(t, []string{"proces-verbaux", filepath.Join("proces-verbaux", "invalides")}, map[string]bool{filepath.Join("proces-verbaux", "invalides", "pv-2-non-trie.json"): true}), "le cas invalides/pv-2-non-trie.json est nommé mais absent de la racine"},
		{"sans INDEX.md", monterRacineCT8(t, nil, map[string]bool{"INDEX.md": true}), "plancher (CT-9 TA-66) : INDEX.md illisible"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			code, sortie := lancerCT8(t, c.racine)
			if code != 1 || !strings.Contains(sortie, c.message) {
				t.Errorf("code %d (attendu 1), message « %s » attendu :\n%s", code, c.message, sortie)
			}
		})
	}
}
