// Plancher de l'oracle (revue de sécurité de l'étape 8 ; même
// règle que CT-1 §13 révision 0.6 et CT-9 TA-66) : un fichier de famille de
// l'annexe A sans aucun cas est une erreur (code 1), et les cas de chaque
// fichier de famille sont comptés contre la table de l'INDEX.md qui les
// nomme, dans les deux sens. Une famille absente est déjà une erreur (sa
// lecture échoue et compte comme discordance) ; texte, constantes, format et
// couverture recalculent leurs valeurs sur toute racine où elles sont
// lisibles, et lireFamille confronte la forme de tout fichier lu : aucune
// famille ne peut donc rendre zéro valeur sans erreur.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	reTitreFamilleCT4 = regexp.MustCompile("^(\\S+\\.json) — famille `([^`]+)`")
	reLigneCasCT4     = regexp.MustCompile("^\\| `([^`]+)` \\|")
)

// AppliquerPlancherCT4 ajoute au rapport les erreurs du plancher et des
// comptes de cas.
func AppliquerPlancherCT4(rap *Rapport, racine string) {
	octets, err := os.ReadFile(filepath.Join(racine, "INDEX.md"))
	if err != nil {
		rap.F("format").Erreur("INDEX.md", "comptes de cas", fmt.Errorf("INDEX.md illisible : %v (CT-9 TA-66)", err), "EX-A.3")
		return
	}
	for _, s := range strings.Split(string(octets), "\n## ")[1:] {
		titre, corps, _ := strings.Cut(s, "\n")
		m := reTitreFamilleCT4.FindStringSubmatch(titre)
		if m == nil {
			continue
		}
		fichier, famille := m[1], m[2]
		f := rap.F(famille)
		var nommes []string
		for _, l := range strings.Split(corps, "\n") {
			if x := reLigneCasCT4.FindStringSubmatch(l); x != nil {
				nommes = append(nommes, x[1])
			}
		}
		v, _, err := LireJSON(filepath.Join(racine, filepath.FromSlash(fichier)))
		if err != nil {
			f.Erreur("INDEX.md", "comptes de cas de "+fichier, err, "EX-A.3")
			continue
		}
		var presents []string
		for _, c := range v.Get("cases").Arr {
			presents = append(presents, c.Get("id").S())
		}
		if len(presents) == 0 {
			f.Erreur(fichier, "cas", fmt.Errorf("famille %s : aucun cas (plancher, CT-9 TA-66)", famille), "EX-A.3")
		}
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
				ecarts = append(ecarts, "le cas "+c+" est nommé par INDEX.md mais absent de "+fichier)
			}
		}
		for c := range p {
			if !n[c] {
				ecarts = append(ecarts, "le cas "+c+" de "+fichier+" n'est pas nommé par INDEX.md")
			}
		}
		if len(n) == 0 {
			ecarts = append(ecarts, "aucun cas nommé par INDEX.md pour "+fichier)
		}
		sort.Strings(ecarts)
		for _, e := range ecarts {
			f.Erreur("INDEX.md", "cas comptés contre l'index", fmt.Errorf("%s (CT-9 TA-66)", e), "EX-A.3")
		}
	}
}
