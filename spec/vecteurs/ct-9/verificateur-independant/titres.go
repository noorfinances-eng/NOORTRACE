package main

// Titres des tests (CT-9 EX-4.2) : le titre cité est le texte source du
// premier argument de describe( ou it(, entre ses délimiteurs, tel qu'il
// figure dans le fichier, avant toute interpolation ; describe seul désigne
// tous les it de ce describe ; un it appartient aux describe qui l'englobent.
// L'analyse est lexicale : commentaires, chaînes, gabarits et littéraux
// d'expression rationnelle sont reconnus pour ne pas confondre un « it( »
// dans une chaîne ou un commentaire avec un appel ; l'appartenance suit les
// accolades. Le fichier test/adversarial.test.js obéit en plus à EX-10.7 :
// le titre d'un it commence par le ou les TA- (séparés par « et »), puis la
// ou les menaces entre parenthèses (suivies au besoin d'une précision après
// une virgule), et finit par « (tué) » ou « (tués) » selon le nombre de
// mutants.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// CasTest est un it avec ses describe englobants, du plus externe au plus
// interne.
type CasTest struct {
	Describes []string
	It        string
}

// TitresFichier est le résultat de l'analyse d'un fichier de test.
type TitresFichier struct {
	Cas       []CasTest
	Describes []string
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
	}
	var pile []cadre
	prof := 0
	n := len(source)
	i := 0
	dernier := "" // dernier lexème significatif, pour distinguer « / » d'une regex
	avantRegex := map[string]bool{"(": true, ",": true, "=": true, ":": true, "[": true, "!": true, "&": true, "|": true, "?": true, "{": true, "}": true, ";": true, "+": true, "-": true, "*": true, "%": true, "<": true, ">": true, "~": true, "^": true, "": true, "return": true}
	lireChaine := func(q byte) string {
		// i est sur le délimiteur ouvrant ; rend le texte source entre délimiteurs.
		j := i + 1
		var b strings.Builder
		gabarit := 0
		for j < n {
			c := source[j]
			if c == '\\' {
				b.WriteByte(c)
				if j+1 < n {
					b.WriteByte(source[j+1])
				}
				j += 2
				continue
			}
			if q == '`' && c == '$' && j+1 < n && source[j+1] == '{' {
				gabarit++
				b.WriteString("${")
				j += 2
				continue
			}
			if q == '`' && gabarit > 0 && c == '}' {
				gabarit--
				b.WriteByte(c)
				j++
				continue
			}
			if c == q && gabarit == 0 {
				break
			}
			if q != '`' && c == '\n' {
				break
			}
			b.WriteByte(c)
			j++
		}
		i = j + 1
		return b.String()
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
							pile = append(pile, cadre{titre, prof})
						} else {
							var d []string
							for _, p := range pile {
								d = append(d, p.titre)
							}
							out.Cas = append(out.Cas, CasTest{Describes: d, It: titre})
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
}

// LireTitreTA lit un titre d'it selon EX-10.7 ; rend faux s'il n'en a pas
// la forme.
func LireTitreTA(titre string) (TitreTA, bool) {
	m := reTitreTA.FindStringSubmatch(titre)
	if m == nil {
		return TitreTA{}, false
	}
	t := reTue.FindStringSubmatch(titre)
	return TitreTA{TAs: strings.Split(m[1], " et "), Menaces: strings.Split(m[2], ", "), Tue: t != nil, Pluriel: t != nil && t[1] == "tués"}, true
}
