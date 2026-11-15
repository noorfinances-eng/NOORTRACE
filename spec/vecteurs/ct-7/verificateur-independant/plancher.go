// Plancher de l'oracle (revue de sécurité de l'étape 8 ; même
// règle que CT-1 §13 révision 0.6 et CT-9 TA-66) : une famille de l'annexe A
// recalculée sans aucune valeur est une erreur (code 1), et les cas que
// l'INDEX.md nomme (ceremonies/, cas d'attestations.json et de croises.json,
// matrice/invalides/) sont comptés contre lui, dans les deux sens. La
// famille epreuves (section 9) n'a, par construction, aucune valeur à
// recalculer et n'entre pas dans le plancher.

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// FamillesAnnexeA sont les familles recalculées par ce module, sous leur nom
// de rapport.
var FamillesAnnexeA = []string{"constantes", "ceremonies", "exemple 5.10", "attestations", "exemple 7.1-7.5", "croises", "matrice", "menaces", "cles-de-test"}

var reLigneCasCT7 = regexp.MustCompile("^\\| `([^`]+)` \\|")

// AppliquerPlancherCT7 ajoute au rapport les erreurs du plancher et des
// comptes de cas.
func AppliquerPlancherCT7(rap *Rapport, racine string) {
	par := map[string]int{}
	for _, c := range rap.Comparaisons {
		if !c.HorsPerimetre {
			par[c.Famille]++
		}
	}
	for _, f := range FamillesAnnexeA {
		if par[f] == 0 {
			rap.Erreur("plancher (CT-9 TA-66) : famille %s : aucune valeur recalculée", f)
		}
	}
	octets, err := os.ReadFile(filepath.Join(racine, "INDEX.md"))
	if err != nil {
		rap.Erreur("plancher (CT-9 TA-66) : INDEX.md illisible : %v", err)
		return
	}
	sections := map[string]string{}
	for _, s := range strings.Split(string(octets), "\n## ")[1:] {
		titre, corps, _ := strings.Cut(s, "\n")
		sections[strings.SplitN(titre, " ", 2)[0]] = corps
	}
	nommes := func(section string) []string {
		var out []string
		for _, l := range strings.Split(sections[section], "\n") {
			if m := reLigneCasCT7.FindStringSubmatch(l); m != nil {
				out = append(out, m[1])
			}
		}
		return out
	}
	// ceremonies/ : un répertoire par cas.
	var ceremonies []string
	es, _ := os.ReadDir(filepath.Join(racine, "ceremonies"))
	for _, e := range es {
		ceremonies = append(ceremonies, e.Name())
	}
	confronterCasCT7(rap, "ceremonies/", nommes("ceremonies/"), ceremonies)
	// attestations/ : les cas de attestations.json et de croises.json.
	var attestations []string
	for _, f := range []string{"attestations.json", "croises.json"} {
		b, err := os.ReadFile(filepath.Join(racine, "attestations", f))
		if err != nil {
			rap.Erreur("plancher (CT-9 TA-66) : attestations/%s : %v", f, err)
			continue
		}
		v, err := AnalyserJSON(b)
		if err != nil {
			rap.Erreur("plancher (CT-9 TA-66) : attestations/%s : %v", f, err)
			continue
		}
		for _, c := range v.Get("cases").Arr {
			attestations = append(attestations, c.Get("name").Chaine())
		}
	}
	confronterCasCT7(rap, "attestations/", nommes("attestations/"), attestations)
	// matrice/invalides/ : un fichier par cas, attendu.json à part.
	var matrices []string
	es, _ = os.ReadDir(filepath.Join(racine, "matrice", "invalides"))
	for _, e := range es {
		if e.Name() != "attendu.json" {
			matrices = append(matrices, e.Name())
		}
	}
	confronterCasCT7(rap, "matrice/invalides/", nommes("matrice-conformite.json"), matrices)
}

// confronterCasCT7 compare les cas nommés par l'INDEX.md aux cas présents.
func confronterCasCT7(rap *Rapport, famille string, nommes, presents []string) {
	n, p := map[string]bool{}, map[string]bool{}
	for _, c := range nommes {
		n[c] = true
	}
	for _, c := range presents {
		p[c] = true
	}
	var ecarts []string
	for c := range n {
		if !p[c] {
			ecarts = append(ecarts, "INDEX.md ("+famille+") : le cas "+c+" est nommé mais absent de la racine")
		}
	}
	for c := range p {
		if !n[c] {
			ecarts = append(ecarts, "INDEX.md ("+famille+") : le cas "+c+" est présent mais l'index ne le nomme pas")
		}
	}
	if len(n) == 0 {
		ecarts = append(ecarts, "INDEX.md ("+famille+") : aucun cas nommé")
	}
	sort.Strings(ecarts)
	for _, e := range ecarts {
		rap.Erreur("%s", e)
	}
	rap.Note("%s : %d cas nommés par INDEX.md, %d présents", famille, len(n), len(p))
}
