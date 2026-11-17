package main

// Règle 4. CT-3 EX-A.10 (complément du 2026-11-16, point 13 de la section 0) :
// les cas comptés dans les deux sens sont les fichiers .json de vingt
// répertoires, sans leurs sous-répertoires, attendu.json compris, lus
// seulement dans la section « Cas nommés » de l'INDEX.md ; « les noms que
// citent les autres sections ne servent pas à ce compte ».

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// vingtRepertoires est la liste d'EX-A.10, recopiée ici depuis le texte, dans
// son ordre.
var vingtRepertoires = []string{
	"politiques/", "politiques-invalides/", "evaluation/", "candidats/", "acceptation/cas/",
	"tickets/", "reponses-evaluer/", "decisions/valides/", "decisions/invalides/", "signatures/",
	"annuaire/", "annuaire/annuaires/", "annuaire/traces/", "annuaire/exports/", "console/modeles/",
	"console/requetes/", "console/reponses/", "console/decouverte/", "console/fichiers-cle/", "notifications/",
}

// indexModifie rend une racine dont l'INDEX.md est celui des vecteurs publiés
// passé par f ; reels sont des répertoires réels de la racine.
func indexModifie(t *testing.T, reels []string, f func(string) string) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "INDEX.md"))
	if err != nil {
		t.Fatal(err)
	}
	racine := monterRacineCT3(t, reels, map[string]bool{"INDEX.md": true})
	out := f(string(src))
	if out == string(src) {
		t.Fatal("INDEX.md inchangé")
	}
	if err := os.WriteFile(filepath.Join(racine, "INDEX.md"), []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
	return racine
}

// sansLigne retire les lignes qui commencent par prefixe.
func sansLigne(prefixe string) func(string) string {
	return func(s string) string {
		var g []string
		for _, l := range strings.Split(s, "\n") {
			if !strings.HasPrefix(l, prefixe) {
				g = append(g, l)
			}
		}
		return strings.Join(g, "\n")
	}
}

func TestCasNommesSection(t *testing.T) {
	if _, err := os.Stat(filepath.Join("..", "INDEX.md")); err != nil {
		t.Skip("vecteurs publiés absents")
	}

	// Vecteurs publiés : aucune erreur, et une note par répertoire, dans
	// l'ordre d'EX-A.10, aux comptes du disque.
	rap := &Rapport{}
	AppliquerPlancherCT3(rap, "..")
	for _, e := range rap.Erreurs {
		t.Errorf("erreur : %s", e)
	}
	var notes []string
	for _, n := range rap.Notes {
		for _, d := range vingtRepertoires {
			if strings.HasPrefix(n, d+" : ") {
				notes = append(notes, n)
			}
		}
	}
	var attendues []string
	for _, d := range vingtRepertoires {
		es, err := os.ReadDir(filepath.Join("..", filepath.FromSlash(d)))
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, e := range es {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
				n++
			}
		}
		attendues = append(attendues, d+" : "+itoa(n)+" cas nommés par INDEX.md, "+itoa(n)+" présents")
	}
	if strings.Join(notes, "\n") != strings.Join(attendues, "\n") {
		t.Errorf("notes :\n%s\nattendues :\n%s", strings.Join(notes, "\n"), strings.Join(attendues, "\n"))
	}

	// Un fichier en trop dans notifications/ : code 1.
	enTrop := monterRacineCT3(t, []string{"notifications"}, nil)
	if err := os.Symlink(filepath.Join(enTrop, "notifications", "notifications.json"), filepath.Join(enTrop, "notifications", "en-trop.json")); err != nil {
		t.Fatal(err)
	}
	// Une ligne des vingt retirée.
	sansSignatures := indexModifie(t, nil, sansLigne("- `signatures/` : "))
	// Les tables des autres sections ne comptent plus : la ligne du cas dans
	// la table d'exports/ retirée ne change rien.
	sansTable := indexModifie(t, nil, sansLigne("| `expiration-entree-portee.json` |"))
	// Un cas nommé seulement dans les autres sections : code 1.
	horsSection := indexModifie(t, nil, func(s string) string {
		return strings.Replace(s, "`annuaire/exports/expiration-entree-portee.json`, ", "", 1)
	})
	// attendu.json est compté.
	sansAttendu := indexModifie(t, nil, func(s string) string {
		return strings.Replace(s, "`annuaire/exports/attendu.json`, ", "", 1)
	})
	// La section absente : code 1.
	sansSection := indexModifie(t, nil, func(s string) string {
		return strings.Replace(s, "## Cas nommés (EX-A.10)", "## Cas cités", 1)
	})

	cas := []struct {
		nom, racine string
		code        int
		message     string
	}{
		{"cas présent non nommé (notifications/)", enTrop, 1, "INDEX.md (Cas nommés) : le cas notifications/en-trop.json est présent mais l'index ne le nomme pas"},
		{"cas nommé absent (console/decouverte/)", monterRacineCT3(t, []string{"console", filepath.Join("console", "decouverte")}, map[string]bool{filepath.Join("console", "decouverte", "nom-vide.json"): true}), 1, "INDEX.md (Cas nommés) : le cas console/decouverte/nom-vide.json est nommé mais absent de la racine"},
		{"ligne de signatures/ absente", sansSignatures, 1, "INDEX.md (Cas nommés) : aucune ligne pour le répertoire signatures/"},
		{"table d'exports/ sans le cas", sansTable, 0, "Résultat : tout concorde."},
		{"cas nommé hors de la section", horsSection, 1, "INDEX.md (Cas nommés) : le cas annuaire/exports/expiration-entree-portee.json est présent mais l'index ne le nomme pas"},
		{"attendu.json non nommé", sansAttendu, 1, "INDEX.md (Cas nommés) : le cas annuaire/exports/attendu.json est présent mais l'index ne le nomme pas"},
		{"section absente", sansSection, 1, "INDEX.md (Cas nommés) : section « ## Cas nommés (EX-A.10) » absente"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			code, sortie := lancerCT3(t, c.racine)
			if code != c.code || !strings.Contains(sortie, c.message) {
				t.Errorf("code %d (attendu %d), message « %s » attendu :\n%s", code, c.code, c.message, tronquer(sortie, 3000))
			}
		})
	}
}
