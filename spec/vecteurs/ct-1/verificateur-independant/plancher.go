// Plancher de l'oracle (CT-1 §13, révision 0.6) : le module rend le code 1
// quand une famille de la table des vecteurs publiés de §13 est absente de
// la racine qu'il lit, ou quand il n'a recalculé aucune valeur ; ses cas
// sont comptés contre l'INDEX.md de la racine. Un « tout concorde » rendu
// sans rien comparer n'est pas une concordance.

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// familleAnnexe est une ligne de la table de §13 : le nom de famille du
// rapport et les entrées de la racine qui la portent.
type familleAnnexe struct {
	famille string
	entrees []string
}

// famillesSection13 suit la table « Répertoire ou fichier » de CT-1 §13.
var famillesSection13 = []familleAnnexe{
	{"clés", []string{"cles/cles-test.json", "cles/cles.json"}},
	{"jcs", []string{"jcs/cas-limites.json"}},
	{"journaux", []string{"journal-valide", "journal-supprime", "journal-modifie", "journal-insere", "journal-insere-sans-cle", "journal-reordonne"}},
	{"arbres", []string{"merkle/arbres.json"}},
	{"manifestes", []string{"manifestes"}},
	{"points", []string{"points-de-controle"}},
	{"coherence", []string{"merkle/coherence.json"}},
	{"dossiers", []string{"dossiers"}},
}

// AppliquerPlancher ajoute au rapport une erreur par famille absente ou sans
// valeur recalculée, une erreur si aucune valeur n'a été recalculée, et une
// erreur par cas que l'INDEX.md nomme sans qu'il soit présent, ou présent
// sans que l'INDEX.md le nomme.
func AppliquerPlancher(rap *Rapport, racine string) {
	parFamille := map[string]int{}
	total := 0
	for _, c := range rap.Comparaisons {
		if c.HorsPerimetre {
			continue
		}
		parFamille[c.Famille]++
		total++
	}
	for _, f := range famillesSection13 {
		for _, e := range f.entrees {
			if _, err := os.Stat(filepath.Join(racine, filepath.FromSlash(e))); err != nil {
				rap.Erreur("plancher (CT-1 §13, révision 0.6) : famille %s absente : %s introuvable", f.famille, e)
			}
		}
		if parFamille[f.famille] == 0 {
			rap.Erreur("plancher (CT-1 §13, révision 0.6) : famille %s : aucune valeur recalculée", f.famille)
		}
	}
	if total == 0 {
		rap.Erreur("plancher (CT-1 §13, révision 0.6) : aucune valeur recalculée")
	}
	compterContreIndex(rap, racine)
}

var (
	reTitreSection = regexp.MustCompile("^## ")
	reLigneCas     = regexp.MustCompile("^\\| `([a-z0-9][a-z0-9-]*)/` \\|")
)

// casDeSection rend les cas nommés en première colonne des tables de la
// section de l'INDEX.md dont le titre commence par titre.
func casDeSection(index, titre string) []string {
	var cas []string
	dedans := false
	for _, ligne := range strings.Split(index, "\n") {
		if reTitreSection.MatchString(ligne) {
			dedans = strings.HasPrefix(ligne, titre)
			continue
		}
		if !dedans {
			continue
		}
		if m := reLigneCas.FindStringSubmatch(ligne); m != nil {
			cas = append(cas, m[1])
		}
	}
	return cas
}

// confronterCas compare les cas nommés par l'INDEX.md aux cas présents.
func confronterCas(rap *Rapport, famille string, nommes, presents []string) {
	n := map[string]bool{}
	for _, c := range nommes {
		n[c] = true
	}
	p := map[string]bool{}
	for _, c := range presents {
		p[c] = true
	}
	var manquants, inconnus []string
	for c := range n {
		if !p[c] {
			manquants = append(manquants, c)
		}
	}
	for c := range p {
		if !n[c] {
			inconnus = append(inconnus, c)
		}
	}
	sort.Strings(manquants)
	sort.Strings(inconnus)
	for _, c := range manquants {
		rap.Erreur("INDEX.md (%s) : le cas %s/ est nommé mais absent de la racine", famille, c)
	}
	for _, c := range inconnus {
		rap.Erreur("INDEX.md (%s) : le cas %s/ est présent mais l'index ne le nomme pas", famille, c)
	}
	if len(n) == 0 {
		rap.Erreur("INDEX.md (%s) : aucun cas nommé", famille)
	}
	rap.Note("%s : %d cas nommés par INDEX.md, %d présents", famille, len(n), len(p))
}

// compterContreIndex confronte les dossiers et les journaux altérés aux
// tables de l'INDEX.md.
func compterContreIndex(rap *Rapport, racine string) {
	octets, err := os.ReadFile(filepath.Join(racine, "INDEX.md"))
	if err != nil {
		rap.Erreur("plancher (CT-1 §13, révision 0.6) : INDEX.md illisible : %v", err)
		return
	}
	index := string(octets)
	// Dossiers : chaque répertoire de dossiers/ qui porte un dossier.json.
	var dossiers []string
	if es, err := os.ReadDir(filepath.Join(racine, "dossiers")); err == nil {
		for _, e := range es {
			if fichierExiste(filepath.Join(racine, "dossiers", e.Name(), "dossier.json")) {
				dossiers = append(dossiers, e.Name())
			}
		}
	}
	confronterCas(rap, "dossiers", casDeSection(index, "## `dossiers/`"), dossiers)
	// Journaux altérés : chaque répertoire journal-* autre que journal-valide.
	var journaux []string
	if es, err := os.ReadDir(racine); err == nil {
		for _, e := range es {
			if strings.HasPrefix(e.Name(), "journal-") && e.Name() != "journal-valide" && fichierExiste(filepath.Join(racine, e.Name(), "evenements.json")) {
				journaux = append(journaux, e.Name())
			}
		}
	}
	confronterCas(rap, "journaux altérés", casDeSection(index, "## `journal-supprime/`"), journaux)
}
