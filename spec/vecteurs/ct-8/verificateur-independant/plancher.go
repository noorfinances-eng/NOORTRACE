// Plancher de l'oracle (revue de sécurité de l'étape 8 ; même
// règle que CT-1 §13 révision 0.6 et CT-9 TA-66) : une famille de l'annexe A
// sans aucune valeur recalculée est une erreur (code 1), et les cas que
// l'INDEX.md nomme dans ses tables (conteneurs/, journaux/,
// proces-verbaux/) sont comptés contre lui, dans les deux sens.

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// FamillesAnnexeA sont les familles de l'annexe A de CT-8 que ce module
// confronte, sous leur nom de rapport.
var FamillesAnnexeA = []string{"disposition", "coefficients", "dimensionnement", "controle-prealable", "paquets", "conteneurs", "observation", "journaux", "consultations", "proces-verbaux", "supervision"}

var reLigneCasCT8 = regexp.MustCompile("^\\| `([^`]+)` \\|")

// AppliquerPlancherCT8 ajoute au rapport les erreurs du plancher et des
// comptes de cas.
func AppliquerPlancherCT8(rap *Rapport, racine string) {
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
		sections[strings.TrimSpace(titre)] = corps
	}
	nommes := func(section string) []string {
		var out []string
		for _, l := range strings.Split(sections[section], "\n") {
			if m := reLigneCasCT8.FindStringSubmatch(l); m != nil {
				out = append(out, m[1])
			}
		}
		return out
	}
	lister := func(dir string, garder func(os.DirEntry) (string, bool)) []string {
		var out []string
		es, _ := os.ReadDir(filepath.Join(racine, filepath.FromSlash(dir)))
		for _, e := range es {
			if n, ok := garder(e); ok {
				out = append(out, n)
			}
		}
		return out
	}
	confronterCasCT8(rap, "conteneurs/", nommes("conteneurs"), lister("conteneurs", func(e os.DirEntry) (string, bool) {
		return strings.TrimSuffix(e.Name(), ".attendu.json"), strings.HasSuffix(e.Name(), ".attendu.json")
	}))
	confronterCasCT8(rap, "journaux/", nommes("journaux"), lister("journaux", func(e os.DirEntry) (string, bool) {
		return e.Name(), fichierPresent(filepath.Join(racine, "journaux", e.Name(), "attendu.json"))
	}))
	var pv []string
	for _, d := range []string{"valides", "invalides"} {
		pv = append(pv, lister("proces-verbaux/"+d, func(e os.DirEntry) (string, bool) {
			return d + "/" + e.Name(), strings.HasSuffix(e.Name(), ".json")
		})...)
	}
	confronterCasCT8(rap, "proces-verbaux/", nommes("proces-verbaux"), pv)
}

func fichierPresent(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// confronterCasCT8 compare les cas nommés par l'INDEX.md aux cas présents.
func confronterCasCT8(rap *Rapport, famille string, nommes, presents []string) {
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
