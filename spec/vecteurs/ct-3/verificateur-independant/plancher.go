// Plancher de l'oracle (révision 0.8 ; même règle que CT-1 §13 révision 0.6
// et CT-9 TA-66) : une famille de l'annexe A sans aucune valeur recalculée
// est une erreur (code 1), et les cas que la section « Cas nommés » de
// l'INDEX.md nomme sont comptés contre la racine, dans les deux sens
// (CT-3 EX-A.10). Une famille absente est déjà une erreur.

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// RepertoiresCasNommes sont les vingt répertoires d'EX-A.10 (complément du
// 2026-11-16, point 13 de la section 0), dans l'ordre du texte : « les cas
// ainsi comptés, dans les deux sens, sont les fichiers .json de vingt
// répertoires, sans leurs sous-répertoires, attendu.json compris ».
var RepertoiresCasNommes = []string{
	"politiques/", "politiques-invalides/", "evaluation/", "candidats/", "acceptation/cas/",
	"tickets/", "reponses-evaluer/", "decisions/valides/", "decisions/invalides/", "signatures/",
	"annuaire/", "annuaire/annuaires/", "annuaire/traces/", "annuaire/exports/", "console/modeles/",
	"console/requetes/", "console/reponses/", "console/decouverte/", "console/fichiers-cle/", "notifications/",
}

// TitreCasNommes est le titre de la section qui nomme les cas.
const TitreCasNommes = "## Cas nommés (EX-A.10)"

var (
	// « une ligne par répertoire, qui nomme le répertoire puis chacun de ses
	// cas, par son chemin relatif à spec/vecteurs/ct-3/ entre accents
	// graves » : - `<rep>/` : `<rep>/<cas>.json`, …
	reLigneCasNommes = regexp.MustCompile("^- `([^`]+/)` :(.*)$")
	reCheminCasNomme = regexp.MustCompile("^`([^`]+)`$")
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
	CompterCasNommes(r, racine, string(octets))
}

// CompterCasNommes applique EX-A.10 (complément du 2026-11-16, point 13 de
// la section 0) : « L'INDEX.md les nomme dans sa section « Cas nommés », que
// le générateur écrit […] ; les noms que citent les autres sections ne
// servent pas à ce compte ». Code 1 quand un chemin nommé est absent, quand
// un .json présent dans l'un des vingt répertoires n'est pas nommé, et quand
// la ligne d'un des vingt répertoires manque.
func CompterCasNommes(r *Rapport, racine, index string) {
	const ctx = "INDEX.md (Cas nommés) : "
	// La section seule : de son titre au titre de niveau 2 suivant.
	var corps []string
	dedans, vue := false, false
	for _, l := range strings.Split(index, "\n") {
		l = strings.TrimRight(l, " \r")
		if strings.HasPrefix(l, "## ") {
			dedans = l == TitreCasNommes
			vue = vue || dedans
			continue
		}
		if dedans {
			corps = append(corps, l)
		}
	}
	if !vue {
		r.Erreur("%s", ctx+"section « "+TitreCasNommes+" » absente")
		return
	}
	connu := map[string]bool{}
	for _, d := range RepertoiresCasNommes {
		connu[d] = true
	}
	nommes := map[string]map[string]bool{}
	var ecarts []string
	for _, l := range corps {
		if !strings.HasPrefix(l, "- ") {
			continue
		}
		m := reLigneCasNommes.FindStringSubmatch(l)
		if m == nil {
			ecarts = append(ecarts, ctx+"ligne illisible : "+tronquer(l, 120))
			continue
		}
		rep := m[1]
		if !connu[rep] {
			// Hors des vingt répertoires : le texte ne fixe pas son sort ;
			// la ligne n'entre pas dans le compte.
			r.Note("%s", ctx+"ligne du répertoire "+rep+", hors des vingt d'EX-A.10, non comptée")
			continue
		}
		if nommes[rep] == nil {
			nommes[rep] = map[string]bool{}
		}
		if reste := strings.TrimSpace(m[2]); reste != "" {
			for _, c := range strings.Split(reste, ", ") {
				cm := reCheminCasNomme.FindStringSubmatch(strings.TrimSpace(c))
				nom := ""
				if cm != nil {
					nom = strings.TrimPrefix(cm[1], rep)
				}
				// Un chemin d'un autre répertoire, d'un sous-répertoire, ou
				// qui n'est pas un .json, n'est pas un cas de ce répertoire.
				if cm == nil || !strings.HasPrefix(cm[1], rep) || nom == "" || strings.Contains(nom, "/") || !strings.HasSuffix(nom, ".json") {
					ecarts = append(ecarts, ctx+"ligne "+rep+" : "+c+" n'est pas un cas .json de ce répertoire")
					continue
				}
				nommes[rep][cm[1]] = true
			}
		}
	}
	for _, rep := range RepertoiresCasNommes {
		presents := map[string]bool{}
		es, _ := os.ReadDir(filepath.Join(racine, filepath.FromSlash(rep)))
		for _, e := range es {
			if !strings.HasSuffix(e.Name(), ".json") {
				continue
			}
			// Sans les sous-répertoires ; un lien est suivi.
			if st, err := os.Stat(filepath.Join(racine, filepath.FromSlash(rep), e.Name())); err == nil && st.IsDir() {
				continue
			}
			presents[rep+e.Name()] = true
		}
		n, ligne := nommes[rep]
		if !ligne {
			ecarts = append(ecarts, ctx+"aucune ligne pour le répertoire "+rep)
		}
		var ec []string
		for c := range n {
			if !presents[c] {
				ec = append(ec, ctx+"le cas "+c+" est nommé mais absent de la racine")
			}
		}
		for c := range presents {
			if ligne && !n[c] {
				ec = append(ec, ctx+"le cas "+c+" est présent mais l'index ne le nomme pas")
			}
		}
		sort.Strings(ec)
		ecarts = append(ecarts, ec...)
		if ligne {
			r.Note("%s : %d cas nommés par INDEX.md, %d présents", rep, len(n), len(presents))
		}
	}
	for _, e := range ecarts {
		r.Erreur("%s", e)
	}
}
