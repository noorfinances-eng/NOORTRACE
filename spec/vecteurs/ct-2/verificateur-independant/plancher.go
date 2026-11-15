// Plancher de l'oracle (revue de sécurité de l'étape 8 ; même
// règle que CT-1 §13 révision 0.6 et CT-9 TA-66) : une famille de l'annexe
// B sans aucune valeur recalculée est une erreur (code 1) ; les cas des familles que l'INDEX.md décrit par une
// table (annexe B.7 : « l'index liste chaque cas ») sont comptés contre lui,
// dans les deux sens. Une famille absente est déjà une erreur (ct2.go).

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// FamillesAnnexeB sont les familles de l'annexe B que ce module confronte,
// sous leur nom de rapport.
var FamillesAnnexeB = []string{FamilleConstantes, FamilleJCSIntegral, FamilleRedaction, FamillePiecesMCP, FamillePiecesModele, FamilleEvenements, "otel", "worm", "cout-agent", FamilleIndex}

// AppliquerPlancherCT2 ajoute au rapport les erreurs du plancher et des
// comptes de cas.
func AppliquerPlancherCT2(rap *Rapport, racine string) {
	// Le plancher par famille couvre aussi « aucune valeur recalculée » : la
	// famille constantes recalcule ses trois valeurs sur toute racine, et
	// chaque autre famille à zéro est une erreur.
	parFamille := map[string]int{}
	for _, c := range rap.Comparaisons {
		if !c.HorsPerimetre {
			parFamille[c.Famille]++
		}
	}
	for _, f := range FamillesAnnexeB {
		if parFamille[f] == 0 {
			rap.Erreur("plancher (CT-9 TA-66) : famille %s : aucune valeur recalculée", f)
		}
	}
	compterCasCT2(rap, racine)
}

var reLigneCasCT2 = regexp.MustCompile("^\\| `([^`/]+)/?` \\|")

// casDeSectionCT2 rend les cas nommés en première colonne des tables de la
// section de l'INDEX.md dont le titre commence par titre.
func casDeSectionCT2(index, titre string) []string {
	var cas []string
	dedans := false
	for _, ligne := range strings.Split(index, "\n") {
		if strings.HasPrefix(ligne, "## ") {
			dedans = strings.HasPrefix(ligne, titre)
			continue
		}
		if m := reLigneCasCT2.FindStringSubmatch(ligne); dedans && m != nil {
			cas = append(cas, m[1])
		}
	}
	return cas
}

// confronterCasCT2 compare les cas nommés par l'INDEX.md aux cas présents.
func confronterCasCT2(rap *Rapport, famille string, nommes, presents []string) {
	n, p := map[string]bool{}, map[string]bool{}
	for _, c := range nommes {
		n[c] = true
	}
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
		rap.Erreur("INDEX.md (%s) : le cas %s est nommé mais absent de la racine", famille, c)
	}
	for _, c := range inconnus {
		rap.Erreur("INDEX.md (%s) : le cas %s est présent mais l'index ne le nomme pas", famille, c)
	}
	if len(n) == 0 {
		rap.Erreur("INDEX.md (%s) : aucun cas nommé", famille)
	}
	rap.Note("%s : %d cas nommés par INDEX.md, %d présents", famille, len(n), len(p))
}

// nomsDeCas rend les membres name des cas d'un fichier cas.json.
func nomsDeCas(chemin string) ([]string, error) {
	octets, err := os.ReadFile(chemin)
	if err != nil {
		return nil, err
	}
	v, err := ParseJSON(octets)
	if err != nil {
		return nil, err
	}
	cas := v
	if c := v.Get("cas"); c != nil {
		cas = c
	}
	if cas == nil || cas.Kind != KindArray {
		return nil, fmt.Errorf("tableau de cas attendu")
	}
	var noms []string
	for _, x := range cas.Arr {
		noms = append(noms, chaineDe(x, "name"))
	}
	return noms, nil
}

// compterCasCT2 confronte à l'INDEX.md les cas de redaction/cas.json,
// jcs-integral/cas.json, pieces-mcp/appels/, pieces-modele/ et otel/.
func compterCasCT2(rap *Rapport, racine string) {
	octets, err := os.ReadFile(filepath.Join(racine, "INDEX.md"))
	if err != nil {
		rap.Erreur("plancher (CT-9 TA-66) : INDEX.md illisible : %v", err)
		return
	}
	index := string(octets)
	for _, x := range []struct{ titre, fichier string }{
		{"## `redaction/`", "redaction/cas.json"},
		{"## `jcs-integral/cas.json`", "jcs-integral/cas.json"},
	} {
		noms, err := nomsDeCas(filepath.Join(racine, filepath.FromSlash(x.fichier)))
		if err != nil {
			rap.Erreur("plancher (CT-9 TA-66) : %s : %v", x.fichier, err)
			continue
		}
		confronterCasCT2(rap, x.fichier, casDeSectionCT2(index, x.titre), noms)
	}
	for _, x := range []struct{ titre, dir string }{
		{"## `pieces-mcp/`", "pieces-mcp/appels"},
		{"## `pieces-modele/`", "pieces-modele"},
		{"## `otel/`", "otel"},
	} {
		var presents []string
		es, _ := os.ReadDir(filepath.Join(racine, filepath.FromSlash(x.dir)))
		for _, e := range es {
			if fichierExiste(filepath.Join(racine, filepath.FromSlash(x.dir), e.Name(), "attendu.json")) {
				presents = append(presents, e.Name())
			}
		}
		confronterCasCT2(rap, x.dir, casDeSectionCT2(index, x.titre), presents)
	}
}
