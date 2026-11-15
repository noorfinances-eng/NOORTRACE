// Plancher de l'oracle (revue de sécurité de l'étape 8 ; même
// règle que CT-1 §13 révision 0.6 et CT-9 TA-66) : une famille de l'annexe A
// sans aucune valeur recalculée est une erreur (code 1), et les fichiers des
// familles que l'INDEX.md nomme un à un (evaluation/, tickets/, politiques/
// et politiques-invalides/, candidats/) sont comptés contre lui, dans les
// deux sens. Une famille absente est déjà une erreur.

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	reTitreFichierCT3 = regexp.MustCompile("^### `([^`]+\\.json)`")
	reLigneFichierCT3 = regexp.MustCompile("^\\| `([^`]+\\.json)` \\|")
)

// AppliquerPlancherCT3 ajoute au rapport les erreurs du plancher et des
// comptes de cas.
func AppliquerPlancherCT3(r *Rapport, racine string) {
	for _, f := range r.Familles {
		if rec, _, _, _ := r.Comptes(f); rec == 0 {
			r.Erreur("plancher (CT-9 TA-66) : famille %s : aucune valeur recalculée", f)
		}
	}
	octets, err := os.ReadFile(filepath.Join(racine, "INDEX.md"))
	if err != nil {
		r.Erreur("plancher (CT-9 TA-66) : INDEX.md illisible : %v", err)
		return
	}
	sections := map[string]string{}
	for _, s := range strings.Split(string(octets), "\n## ")[1:] {
		titre, corps, _ := strings.Cut(s, "\n")
		sections[strings.SplitN(titre, " ", 2)[0]] = corps
	}
	for _, x := range []struct {
		section string
		re      *regexp.Regexp
		dirs    []string
	}{
		{"evaluation/", reTitreFichierCT3, []string{"evaluation"}},
		{"tickets/", reTitreFichierCT3, []string{"tickets"}},
		{"politiques/", reLigneFichierCT3, []string{"politiques", "politiques-invalides"}},
		{"candidats/", reLigneFichierCT3, []string{"candidats"}},
	} {
		nommes := map[string]bool{}
		for _, l := range strings.Split(sections[x.section], "\n") {
			if m := x.re.FindStringSubmatch(l); m != nil {
				nommes[m[1]] = true
			}
		}
		presents := map[string]bool{}
		for _, d := range x.dirs {
			es, _ := os.ReadDir(filepath.Join(racine, d))
			for _, e := range es {
				if strings.HasSuffix(e.Name(), ".json") && e.Name() != "attendu.json" {
					presents[e.Name()] = true
				}
			}
		}
		var ecarts []string
		for c := range nommes {
			if !presents[c] {
				ecarts = append(ecarts, "INDEX.md ("+x.section+") : le cas "+c+" est nommé mais absent de la racine")
			}
		}
		for c := range presents {
			if !nommes[c] {
				ecarts = append(ecarts, "INDEX.md ("+x.section+") : le cas "+c+" est présent mais l'index ne le nomme pas")
			}
		}
		if len(nommes) == 0 {
			ecarts = append(ecarts, "INDEX.md ("+x.section+") : aucun cas nommé")
		}
		sort.Strings(ecarts)
		for _, e := range ecarts {
			r.Erreur("%s", e)
		}
		r.Note("%s : %d cas nommés par INDEX.md, %d présents", x.section, len(nommes), len(presents))
	}
}
