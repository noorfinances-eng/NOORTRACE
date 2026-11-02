package main

// Lecture des spécifications (CT-9 §5.2, EX-5.6), des occurrences de
// « CT-9 » (CT-9 §0.2, EX-0.1), des sections d'un texte et des extraits
// (EX-12.2, EX-A.16), et des chiffres que la prose de CT-9 imprime.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Specification est une spécification CT-1 à CT-8 (ou CT-9) lue dans spec/.
type Specification struct {
	ID       string // « CT-1 »
	Fichier  string // chemin relatif à la racine, séparateur « / »
	Version  string // « 0.4 », lue dans l'en-tête (« Version 0.4, … »)
	Texte    string
	IDs      map[string]bool // identifiants définis (5.2)
	Sections map[string]bool // numéros des titres de niveau 2 à 4 (« 16.1 », « A.3 »)
}

var (
	reEXGras     = regexp.MustCompile(`\*\*(EX-[0-9A-Z]+\.[0-9]+)(\*\*| \()`)
	reFamille    = regexp.MustCompile(`^\| (\*\*)?([A-Z]{1,3}(-[A-Z]{1,3})?-[0-9]+)(\*\*)? \|`)
	reDM         = regexp.MustCompile(`^(DM-[0-9]+)\s`)
	reIRIC       = regexp.MustCompile(`^\*\*((?:IR|IC)-[0-9]+)\b`)
	reRB         = regexp.MustCompile(`^### 10\.1[2-9] (RB-[1-8])\b`)
	reTitre      = regexp.MustCompile(`^#{2,4}\s+(.*)$`)
	reNumTitre   = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)*|[A-Z](?:\.[0-9]+)*)\.?\s`)
	reAnnexe     = regexp.MustCompile(`^Annexe ([A-Z])\b`)
	reSpecFile   = regexp.MustCompile(`^CT-([1-9])-.*\.md$`)
	reIDCatalog  = regexp.MustCompile(`^(CT-[1-9]) (.+)$`)
	reSectionCat = regexp.MustCompile(`^(CT-[1-9]) §(.+)$`)
	reFinNum     = regexp.MustCompile(`[-.][0-9]+$`)
	reVersion    = regexp.MustCompile(`(?m)^Version ([0-9]+\.[0-9]+)`)
	reBlancs     = regexp.MustCompile(`\s+`)
)

// LireSpecification lit une spécification par son fichier.
func LireSpecification(racine, nom string) (*Specification, error) {
	m := reSpecFile.FindStringSubmatch(nom)
	if m == nil {
		return nil, fmt.Errorf("%s : nom de spécification inattendu", nom)
	}
	octets, err := os.ReadFile(filepath.Join(racine, "spec", nom))
	if err != nil {
		return nil, err
	}
	s := &Specification{ID: "CT-" + m[1], Fichier: "spec/" + nom, Texte: string(octets)}
	s.IDs, s.Sections = IdentifiantsDefinis(s.ID, s.Texte)
	if v := reVersion.FindStringSubmatch(s.Texte); v != nil {
		s.Version = v[1]
	}
	return s, nil
}

// LireSpecifications lit spec/CT-1-*.md à CT-8-*.md (une par numéro).
func LireSpecifications(racine string) ([]*Specification, error) {
	entrees, err := os.ReadDir(filepath.Join(racine, "spec"))
	if err != nil {
		return nil, err
	}
	par := map[string]*Specification{}
	for _, e := range entrees {
		m := reSpecFile.FindStringSubmatch(e.Name())
		if m == nil || m[1] == "9" {
			continue
		}
		s, err := LireSpecification(racine, e.Name())
		if err != nil {
			return nil, err
		}
		if par[s.ID] != nil {
			return nil, fmt.Errorf("deux fichiers pour %s", s.ID)
		}
		par[s.ID] = s
	}
	var out []*Specification
	for n := 1; n <= 8; n++ {
		s := par[fmt.Sprintf("CT-%d", n)]
		if s == nil {
			return nil, fmt.Errorf("spécification CT-%d absente de spec/", n)
		}
		out = append(out, s)
	}
	return out, nil
}

// IdentifiantsDefinis applique les règles de CT-9 §5.2 : les EX- en gras
// (« **EX-s.k** » ou « **EX-s.k (») et les familles en première cellule d'une
// ligne de table (gras retiré), hors blocs de code ; exclusion des préfixes
// CT- (tables de relations) et EIP- (faux positif) ; pour CT-8, les lignes
// « DM-n » en début de ligne (blocs de code compris : les lignes DM- sont dans
// un bloc), les « **IR-n** », « **IC-n** » en gras et RB-1 à RB-8 des titres
// 10.12 à 10.19. Rend aussi les numéros des titres de niveau 2 à 4.
func IdentifiantsDefinis(ct, texte string) (map[string]bool, map[string]bool) {
	ids := map[string]bool{}
	sections := map[string]bool{}
	code := false
	for _, l := range strings.Split(texte, "\n") {
		if strings.HasPrefix(l, "```") {
			code = !code
			continue
		}
		if ct == "CT-8" {
			if m := reDM.FindStringSubmatch(l); m != nil {
				ids[m[1]] = true
			}
		}
		if code {
			continue
		}
		for _, m := range reEXGras.FindAllStringSubmatch(l, -1) {
			ids[m[1]] = true
		}
		if m := reFamille.FindStringSubmatch(l); m != nil && !strings.HasPrefix(m[2], "CT-") && !strings.HasPrefix(m[2], "EIP-") {
			ids[m[2]] = true
		}
		if ct == "CT-8" {
			if m := reIRIC.FindStringSubmatch(l); m != nil {
				ids[m[1]] = true
			}
			if m := reRB.FindStringSubmatch(l); m != nil {
				ids[m[1]] = true
			}
		}
		if t := reTitre.FindStringSubmatch(l); t != nil {
			if n := reNumTitre.FindStringSubmatch(t[1]); n != nil {
				sections[n[1]] = true
			} else if a := reAnnexe.FindStringSubmatch(t[1]); a != nil {
				sections[a[1]] = true
			}
		}
	}
	return ids, sections
}

// Famille rend le préfixe de famille d'un identifiant nu : EX-3.4 → EX-3,
// TR-101 → TR, AV-T-1 → AV-T (comptes par famille du rapport).
func Famille(id string) string { return reFinNum.ReplaceAllString(id, "") }

// Occurrence est une occurrence de « CT-9 » dans un fichier de spec/.
type Occurrence struct {
	Fichier string // préfixe de la clé (« CT-7 », « `spec/README.md` »)
	Cle     string
	Ligne   int
}

// OccurrencesCT9 applique le procédé de CT-9 §0.2 à spec/CT-1-*.md …
// CT-8-*.md puis spec/README.md : la clé est « <préfixe> <section> », la
// section étant le dernier titre de niveau 2 à 4 qui précède l'occurrence,
// hors bloc de code (« §s » quand le titre commence par un numéro, son texte
// entre guillemets sinon, « en-tête » avant le premier titre) ; une entrée par
// occurrence, dans l'ordre des fichiers puis des lignes. Les occurrences sont
// comptées sur toutes les lignes, blocs de code compris.
func OccurrencesCT9(racine string, specs []*Specification) ([]Occurrence, error) {
	var out []Occurrence
	type fichier struct{ prefixe, chemin string }
	var fichiers []fichier
	for _, s := range specs {
		fichiers = append(fichiers, fichier{s.ID, s.Fichier})
	}
	fichiers = append(fichiers, fichier{"`spec/README.md`", "spec/README.md"})
	for _, f := range fichiers {
		octets, err := os.ReadFile(filepath.Join(racine, filepath.FromSlash(f.chemin)))
		if err != nil {
			return nil, err
		}
		section := "« en-tête »"
		code := false
		for i, l := range strings.Split(string(octets), "\n") {
			if strings.HasPrefix(l, "```") {
				code = !code
			}
			if !code {
				if t := reTitre.FindStringSubmatch(l); t != nil {
					if n := reNumTitre.FindStringSubmatch(t[1]); n != nil {
						section = "§" + n[1]
					} else {
						section = "« " + t[1] + " »"
					}
				}
			}
			for j := 0; j < strings.Count(l, "CT-9"); j++ {
				out = append(out, Occurrence{Fichier: f.prefixe, Cle: f.prefixe + " " + section, Ligne: i + 1})
			}
		}
	}
	return out, nil
}

// MultiEnsemble compte les clés d'une liste.
func MultiEnsemble(cles []string) map[string]int {
	m := map[string]int{}
	for _, k := range cles {
		m[k]++
	}
	return m
}

// ClesTriees rend les clés d'un multi-ensemble, triées.
func ClesTriees(m map[string]int) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Normaliser réduit les suites de blancs à une espace.
func Normaliser(s string) string { return strings.TrimSpace(reBlancs.ReplaceAllString(s, " ")) }

// SectionTexte rend le texte d'une section de niveau 2 (« 14 », « Annexe A »)
// ou 3 (« 5.5 », « A.6 »), du titre exclu au titre suivant de même niveau ou
// supérieur, hors blocs de code pour la détection des titres.
func SectionTexte(texte, numero string) string {
	lignes := strings.Split(texte, "\n")
	niveau := 2
	if strings.Contains(numero, ".") {
		niveau = 3
	}
	var out []string
	dedans, code := false, false
	for _, l := range lignes {
		if strings.HasPrefix(l, "```") {
			code = !code
		}
		if !code && strings.HasPrefix(l, "#") {
			n := numeroTitre(l)
			prof := len(l) - len(strings.TrimLeft(l, "#"))
			if dedans && prof <= niveau && prof >= 2 {
				break
			}
			if !dedans && prof == niveau && n == numero {
				dedans = true
				continue
			}
		}
		if dedans {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// numeroTitre rend le numéro d'un titre (« 14 », « 5.5 », « Annexe A »,
// « A.15 »), ou le texte du titre sans numéro.
func numeroTitre(l string) string {
	t := strings.TrimSpace(strings.TrimLeft(l, "#"))
	if a := reAnnexe.FindStringSubmatch(t); a != nil {
		return "Annexe " + a[1]
	}
	if n := reNumTitre.FindStringSubmatch(t); n != nil {
		return n[1]
	}
	return t
}

// Couper rend un extrait d'une spécification (EX-12.2, EX-A.16) : le texte
// découpé par sections de niveau 2 et 3, hors blocs de code, sans autre
// modification. Soit on retire des sections de niveau 2 (« 14 », « Annexe
// A ») et de niveau 3 (« A.15 »), soit on ne garde que des sections de
// niveau 2 (« 13 »), auquel cas tout ce qui précède la première section
// gardée est retiré aussi.
func Couper(src string, retirerL2, retirerL3, garderL2 []string) string {
	dans := func(l []string, x string) bool {
		for _, y := range l {
			if x == y {
				return true
			}
		}
		return false
	}
	var out []string
	code := false
	sauter := garderL2 != nil
	l2Retiree := false
	for _, l := range strings.Split(src, "\n") {
		if strings.HasPrefix(l, "```") {
			code = !code
		}
		if !code {
			if strings.HasPrefix(l, "## ") {
				n := numeroTitre(l)
				if garderL2 != nil {
					sauter = !dans(garderL2, n)
				} else {
					l2Retiree = dans(retirerL2, n)
					sauter = l2Retiree
				}
			} else if strings.HasPrefix(l, "### ") && garderL2 == nil {
				sauter = l2Retiree || dans(retirerL3, numeroTitre(l))
			}
		}
		if !sauter {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// EntierFrancais lit un nombre écrit en chiffres (« 14 293 », « 1 588,11 »)
// ou en lettres (« dix », « soixante-seize ») ; rend faux s'il ne le lit pas.
func EntierFrancais(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	chiffres := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(s, " ", ""), " ", ""), " ", "")
	chiffres = strings.ReplaceAll(chiffres, ",", ".")
	if f, err := strconv.ParseFloat(chiffres, 64); err == nil {
		return f, true
	}
	mots := map[string]int{"un": 1, "une": 1, "deux": 2, "trois": 3, "quatre": 4, "cinq": 5, "six": 6, "sept": 7, "huit": 8, "neuf": 9, "dix": 10, "onze": 11, "douze": 12, "treize": 13, "quatorze": 14, "quinze": 15, "seize": 16, "vingt": 20, "trente": 30, "quarante": 40, "cinquante": 50, "soixante": 60, "cent": 100}
	total, courant := 0, 0
	for _, m := range strings.Split(strings.ToLower(s), "-") {
		m = strings.TrimSpace(m)
		if m == "et" {
			continue
		}
		v, ok := mots[m]
		if !ok {
			return 0, false
		}
		if v == 100 {
			if courant == 0 {
				courant = 1
			}
			courant *= 100
			total += courant
			courant = 0
		} else {
			courant += v
		}
	}
	return float64(total + courant), true
}
