package main

// Titres des tests (CT-9 EX-4.2) : le titre cité est le texte source du
// premier argument de describe( ou it(, entre ses délimiteurs, tel qu'il
// figure dans le fichier, avant toute interpolation ; describe seul désigne
// tous les it de ce describe ; un it appartient aux describe qui l'englobent.
// L'analyse est lexicale : commentaires, chaînes, gabarits et littéraux
// d'expression rationnelle sont reconnus pour ne pas confondre un « it( »
// dans une chaîne ou un commentaire avec un appel ; l'appartenance suit les
// accolades. Révision 0.10 (EX-5.4 (d)) : un appel it.skip, it.only ou
// describe.skip est lu avec son modificateur, et un it sans second argument
// est lu sans corps. Le fichier test/adversarial.test.js obéit en plus à
// EX-10.7 : le titre d'un it commence par le ou les TA- (séparés par
// « et »), puis la ou les menaces entre parenthèses (suivies au besoin d'une
// précision après une virgule), et finit par « (tué) » ou « (tués) » selon
// le nombre de mutants ; un scénario du plan (forme (4)) nomme les menaces
// composées qu'il éprouve, son it de bout en bout ne finit pas par
// « (tué) », son it qui retire une réponse porte « réponse retirée ».

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// CasTest est un it avec ses describe englobants, du plus externe au plus
// interne.
type CasTest struct {
	Describes    []string
	It           string
	Modificateur string // "skip", "only" ou vide (it.skip, it.only)
	Corps        bool   // l'appel a un second argument (la fonction du test)
	SousSkip     bool   // un describe englobant est un describe.skip
}

// TitresFichier est le résultat de l'analyse d'un fichier de test.
type TitresFichier struct {
	Cas         []CasTest
	Describes   []string
	Profondeurs []int // nombre de describe englobant chaque describe
}

var (
	reNomStep = regexp.MustCompile(`(?m)^\s*- name: (.+?)\s*$`)
	reTitreTA = regexp.MustCompile(`^(TA-[1-9][0-9]*(?: et TA-[1-9][0-9]*)*) \((MN-[1-9][0-9]*(?:, MN-[1-9][0-9]*)*)[,)]`)
	reTue     = regexp.MustCompile(` \((tué|tués)\)$`)
)

func estDelimiteur(c byte) bool { return c == '"' || c == '\'' || c == '`' }
func estIdentDebut(c byte) bool {
	return c == '_' || c == '$' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}
func estIdent(c byte) bool { return estIdentDebut(c) || (c >= '0' && c <= '9') }
func estBlanc(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// AnalyserTitres lit les describe et it d'un source JavaScript.
func AnalyserTitres(source string) TitresFichier {
	var out TitresFichier
	type cadre struct {
		titre string
		prof  int
		skip  bool
	}
	var pile []cadre
	prof := 0
	n := len(source)
	i := 0
	dernier := "" // dernier lexème significatif, pour distinguer « / » d'une regex
	avantRegex := map[string]bool{"(": true, ",": true, "=": true, ":": true, "[": true, "!": true, "&": true, "|": true, "?": true, "{": true, "}": true, ";": true, "+": true, "-": true, "*": true, "%": true, "<": true, ">": true, "~": true, "^": true, "": true, "return": true}
	// finChaine rend l'indice du délimiteur fermant d'une chaîne ouverte en j
	// (ou du saut de ligne qui termine une chaîne simple). Dans un gabarit,
	// une interpolation ${…} est une expression : ses accolades sont
	// équilibrées et les chaînes et gabarits qu'elle contient sont sautés
	// (un gabarit imbriqué dont le texte porte « \} » ne ferme rien).
	var finChaine func(j int, q byte) int
	finInterpolation := func(k int) int {
		// k suit « ${ » ; rend l'indice qui suit l'accolade fermante.
		p := 1
		for k < n {
			c := source[k]
			if estDelimiteur(c) {
				k = finChaine(k, c) + 1
				continue
			}
			if c == '{' {
				p++
			} else if c == '}' {
				p--
				if p == 0 {
					return k + 1
				}
			}
			k++
		}
		return n
	}
	finChaine = func(j int, q byte) int {
		k := j + 1
		for k < n {
			c := source[k]
			if c == '\\' {
				k += 2
				continue
			}
			if q == '`' && c == '$' && k+1 < n && source[k+1] == '{' {
				k = finInterpolation(k + 2)
				continue
			}
			if c == q {
				return k
			}
			if q != '`' && c == '\n' {
				return k
			}
			k++
		}
		return n
	}
	lireChaine := func(q byte) string {
		// i est sur le délimiteur ouvrant ; rend le texte source entre délimiteurs.
		j := finChaine(i, q)
		fin := j
		if fin > n {
			fin = n
		}
		s := source[i+1 : fin]
		i = j + 1
		return s
	}
	for i < n {
		c := source[i]
		if c == '/' && i+1 < n && source[i+1] == '/' {
			for i < n && source[i] != '\n' {
				i++
			}
			continue
		}
		if c == '/' && i+1 < n && source[i+1] == '*' {
			f := strings.Index(source[i+2:], "*/")
			if f == -1 {
				i = n
			} else {
				i = i + 2 + f + 2
			}
			continue
		}
		if estDelimiteur(c) {
			lireChaine(c)
			dernier = "\""
			continue
		}
		if c == '/' && avantRegex[dernier] {
			j := i + 1
			classe := false
			for j < n && source[j] != '\n' {
				d := source[j]
				if d == '\\' {
					j += 2
					continue
				}
				if d == '[' {
					classe = true
				} else if d == ']' {
					classe = false
				} else if d == '/' && !classe {
					break
				}
				j++
			}
			i = j + 1
			dernier = "/"
			continue
		}
		if estIdentDebut(c) {
			j := i
			for j < n && estIdent(source[j]) {
				j++
			}
			mot := source[i:j]
			precedentPoint := i > 0 && source[i-1] == '.'
			if (mot == "describe" || mot == "it") && !precedentPoint {
				k := j
				modificateur := ""
				for _, m := range []string{"skip", "only"} {
					if strings.HasPrefix(source[k:], "."+m) && (k+1+len(m) >= n || !estIdent(source[k+1+len(m)])) {
						modificateur = m
						k += 1 + len(m)
					}
				}
				for k < n && estBlanc(source[k]) {
					k++
				}
				if k < n && source[k] == '(' {
					k++
					for k < n && estBlanc(source[k]) {
						k++
					}
					if k < n && estDelimiteur(source[k]) {
						i = k
						titre := lireChaine(source[k])
						if mot == "describe" {
							out.Describes = append(out.Describes, titre)
							out.Profondeurs = append(out.Profondeurs, len(pile))
							pile = append(pile, cadre{titre, prof, modificateur == "skip"})
						} else {
							var d []string
							sousSkip := false
							for _, p := range pile {
								d = append(d, p.titre)
								sousSkip = sousSkip || p.skip
							}
							out.Cas = append(out.Cas, CasTest{Describes: d, It: titre, Modificateur: modificateur, Corps: aUnCorps(source, i), SousSkip: sousSkip})
						}
						dernier = "\""
						continue
					}
				}
			}
			i = j
			if mot == "return" {
				dernier = "return"
			} else {
				dernier = "a"
			}
			continue
		}
		if c == '{' {
			prof++
		} else if c == '}' {
			prof--
			for len(pile) > 0 && pile[len(pile)-1].prof >= prof {
				pile = pile[:len(pile)-1]
			}
		}
		if !estBlanc(c) {
			dernier = string(c)
		}
		i++
	}
	return out
}

// aUnCorps dit si l'appel dont le titre se termine juste avant k a un
// second argument : après le titre, une virgule suivie d'autre chose qu'une
// parenthèse fermante. Un titre suivi d'un autre opérateur (concaténation)
// est lu comme ayant un corps, faute de pouvoir dire mieux sans évaluer.
func aUnCorps(source string, k int) bool {
	n := len(source)
	sauter := func() {
		for k < n {
			if estBlanc(source[k]) {
				k++
			} else if strings.HasPrefix(source[k:], "//") {
				for k < n && source[k] != '\n' {
					k++
				}
			} else if strings.HasPrefix(source[k:], "/*") {
				f := strings.Index(source[k+2:], "*/")
				if f == -1 {
					k = n
				} else {
					k += 2 + f + 2
				}
			} else {
				return
			}
		}
	}
	sauter()
	if k >= n || source[k] == ')' {
		return false
	}
	if source[k] != ',' {
		return true
	}
	k++
	sauter()
	return k < n && source[k] != ')'
}

// FichiersTests rend test/*.test.js, chemins relatifs triés.
func FichiersTests(racine string) ([]string, error) {
	entrees, err := os.ReadDir(filepath.Join(racine, "test"))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entrees {
		if strings.HasSuffix(e.Name(), ".test.js") {
			out = append(out, "test/"+e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

// IndexTitres analyse chaque fichier de test.
func IndexTitres(racine string) (map[string]TitresFichier, []string, error) {
	fichiers, err := FichiersTests(racine)
	if err != nil {
		return nil, nil, err
	}
	index := map[string]TitresFichier{}
	for _, f := range fichiers {
		octets, err := os.ReadFile(filepath.Join(racine, filepath.FromSlash(f)))
		if err != nil {
			return nil, nil, err
		}
		index[f] = AnalyserTitres(string(octets))
	}
	return index, fichiers, nil
}

// TitreExiste dit si le test cité existe : fichier indexé, describe présent
// (englobant compris) et, si it est donné, un it de ce titre sous ce describe.
func TitreExiste(index map[string]TitresFichier, t TestExistant) bool {
	r, ok := index[t.File]
	if !ok {
		return false
	}
	if t.It == nil {
		for _, d := range r.Describes {
			if d == t.Describe {
				return true
			}
		}
		return false
	}
	for _, c := range r.Cas {
		if c.It != *t.It {
			continue
		}
		for _, d := range c.Describes {
			if d == t.Describe {
				return true
			}
		}
	}
	return false
}

// EtatCite applique EX-5.4 (d) à un test cité : "" si le titre existe et,
// pour un it, si l'un des it de ce titre sous ce describe a un corps, n'est
// ni skip ni only et n'est pas sous un describe.skip ; sinon le premier
// défaut, dans l'ordre « absent », « sans corps », « skip », « only »,
// « sous describe.skip ».
func EtatCite(index map[string]TitresFichier, t TestExistant) string {
	if !TitreExiste(index, t) {
		return "absent"
	}
	if t.It == nil {
		return ""
	}
	pire := ""
	rang := map[string]int{"sans corps": 1, "skip": 2, "only": 3, "sous describe.skip": 4}
	for _, c := range index[t.File].Cas {
		if c.It != *t.It || !contient(c.Describes, t.Describe) {
			continue
		}
		pb := ""
		switch {
		case !c.Corps:
			pb = "sans corps"
		case c.Modificateur != "":
			pb = c.Modificateur
		case c.SousSkip:
			pb = "sous describe.skip"
		default:
			return ""
		}
		if pire == "" || rang[pb] < rang[pire] {
			pire = pb
		}
	}
	return pire
}

// Structure est la disposition des describe d'un fichier (EX-A.11) :
// describe de premier niveau dans l'ordre du fichier, nombre d'it sous
// chacun, nombre de describe qui contiennent directement un it sous chacun,
// et leur total.
type Structure struct {
	Premiers           []string
	ItsParPremier      []int
	FeuillesParPremier []int
	Feuilles           int
}

// StructureDescribes calcule la Structure d'un fichier analysé ; un it
// hors de tout describe n'est compté nulle part.
func StructureDescribes(r TitresFichier) Structure {
	var s Structure
	rang := map[string]int{}
	for i, d := range r.Describes {
		if r.Profondeurs[i] == 0 {
			if _, vu := rang[d]; !vu {
				rang[d] = len(s.Premiers)
				s.Premiers = append(s.Premiers, d)
			}
		}
	}
	s.ItsParPremier = make([]int, len(s.Premiers))
	s.FeuillesParPremier = make([]int, len(s.Premiers))
	vues := map[string]bool{}
	for _, c := range r.Cas {
		if len(c.Describes) == 0 {
			continue
		}
		p := rang[c.Describes[0]]
		s.ItsParPremier[p]++
		chemin := strings.Join(c.Describes, "\x00")
		if !vues[chemin] {
			vues[chemin] = true
			s.FeuillesParPremier[p]++
			s.Feuilles++
		}
	}
	return s
}

// EtapesCI rend les valeurs exactes des membres « - name: » de ci.yml.
func EtapesCI(texte string) map[string]bool {
	out := map[string]bool{}
	for _, m := range reNomStep.FindAllStringSubmatch(texte, -1) {
		out[m[1]] = true
	}
	return out
}

// TitreTA est la lecture d'un titre d'it de test/adversarial.test.js selon
// EX-10.7 : les TA- cités, les menaces citées, le pluriel de « tué » (qui
// compte les mutants, non les TA-).
type TitreTA struct {
	TAs     []string
	Menaces []string
	Tue     bool // le titre finit par « (tué) » ou « (tués) »
	Pluriel bool
	Retiree bool // le titre porte « réponse retirée » (forme (4) d'EX-10.7)
}

// LireTitreTA lit un titre d'it selon EX-10.7 ; rend faux s'il n'en a pas
// la forme.
func LireTitreTA(titre string) (TitreTA, bool) {
	m := reTitreTA.FindStringSubmatch(titre)
	if m == nil {
		return TitreTA{}, false
	}
	t := reTue.FindStringSubmatch(titre)
	return TitreTA{TAs: strings.Split(m[1], " et "), Menaces: strings.Split(m[2], ", "), Tue: t != nil, Pluriel: t != nil && t[1] == "tués", Retiree: strings.Contains(titre, "réponse retirée")}, true
}

// ProblemesItScenario applique la forme (4) d'EX-10.7 au titre d'un it qui
// nomme un scénario du plan (10.5) : les menaces du titre sont des menaces
// composées par le scénario ; l'it qui retire une réponse porte « réponse
// retirée » et finit par « (tué) » ; l'it de bout en bout ne finit pas par
// « (tué) ».
func ProblemesItScenario(lu TitreTA, menacesScenario []string) []string {
	var pb []string
	for _, m := range lu.Menaces {
		if !contient(menacesScenario, m) {
			pb = append(pb, m+" n'est pas une menace composée par le scénario")
		}
	}
	if lu.Retiree && !lu.Tue {
		pb = append(pb, "it « réponse retirée » sans « (tué) »")
	}
	if !lu.Retiree && lu.Tue {
		pb = append(pb, "it de bout en bout terminé par « (tué) »")
	}
	return pb
}

// ProblemesScenario applique 10.5 (révision 0.10) aux titres des it de
// test/adversarial.test.js qu'un scénario cite : exactement un it de bout en
// bout qui le nomme ; sauf pour l'exception nommée par le texte, exactement
// un it « réponse retirée » qui le nomme ; pour l'exception, un it tué de
// chaque TA- nommé en plus ; aucun autre it qui ne le nomme pas (EX-10.7).
func ProblemesScenario(id string, cites []string, exception bool, enPlus []string) []string {
	var pb []string
	bout, retrait := 0, 0
	tues := map[string]bool{}
	for _, titre := range cites {
		lu, ok := LireTitreTA(titre)
		if !ok {
			pb = append(pb, "cite un it sans la forme d'EX-10.7")
			continue
		}
		if contient(lu.TAs, id) {
			if lu.Retiree {
				retrait++
			} else {
				bout++
			}
			continue
		}
		nomme := false
		for _, x := range enPlus {
			if contient(lu.TAs, x) && lu.Tue {
				tues[x] = true
				nomme = true
			}
		}
		if !nomme {
			pb = append(pb, fmt.Sprintf("cite un it dont le titre nomme %v et non %s (EX-10.7)", lu.TAs, id))
		}
	}
	if bout != 1 {
		pb = append(pb, fmt.Sprintf("%d it de bout en bout cité(s) (un attendu)", bout))
	}
	if exception {
		if retrait != 0 {
			pb = append(pb, fmt.Sprintf("%d it « réponse retirée » cité(s) (aucun attendu)", retrait))
		}
		for _, x := range enPlus {
			if !tues[x] {
				pb = append(pb, "ne cite pas le mutant tué de "+x)
			}
		}
	} else if retrait != 1 {
		pb = append(pb, fmt.Sprintf("%d it « réponse retirée » cité(s) (un attendu)", retrait))
	}
	return pb
}
