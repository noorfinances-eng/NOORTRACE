// Sous-ensemble commun ECMAScript/RE2 des motifs nommés et des expressions
// d'extraction (CT-2 EX-10.6, EX-7.6) : liste autorisée, vérifiée par une
// analyse descendante du motif, point de code par point de code.

package main

import (
	"fmt"
	"regexp"
	"strconv"
)

var reNomGroupe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,31}$`)

type analyseMotif struct {
	r      []rune
	i      int
	noms   map[string]bool
	erreur string
}

func (a *analyseMotif) refuser(format string, args ...any) {
	if a.erreur == "" {
		a.erreur = fmt.Sprintf(format, args...) + fmt.Sprintf(" (position %d)", a.i)
	}
	panic(a)
}

func (a *analyseMotif) car(k int) rune {
	if a.i+k < len(a.r) {
		return a.r[a.i+k]
	}
	return -1
}

// echappement lit un échappement admis (point 2 de la liste) ; rend vrai si
// c'est un caractère (borne d'intervalle possible), et la valeur du caractère.
func (a *analyseMotif) echappement(dansClasse bool) (bool, rune) {
	e := a.car(1)
	switch {
	case e == -1:
		a.refuser("échappement final")
	case containsRune(`\^$.|?*+()[]{}/`, e):
		a.i += 2
		return true, e
	case dansClasse && e == '-':
		a.i += 2
		return true, '-'
	case containsRune("tnrfv", e):
		a.i += 2
		return true, map[rune]rune{'t': 9, 'n': 10, 'r': 13, 'f': 12, 'v': 11}[e]
	case e == 'x':
		h := string(a.r[min(a.i+2, len(a.r)):min(a.i+4, len(a.r))])
		v, err := strconv.ParseUint(h, 16, 8)
		if len(h) != 2 || err != nil {
			a.refuser(`\x exige deux chiffres hexadécimaux`)
		}
		a.i += 4
		return true, rune(v)
	case containsRune("dDwW", e):
		a.i += 2
		return false, 0
	case !dansClasse && (e == 'b' || e == 'B'):
		a.i += 2
		return false, -1 // assertion
	}
	a.refuser(`échappement \%c hors du sous-ensemble commun`, e)
	return false, 0
}

func containsRune(s string, r rune) bool {
	for _, c := range s {
		if c == r {
			return true
		}
	}
	return false
}

func (a *analyseMotif) classe() {
	a.i++ // [
	if a.car(0) == '^' {
		a.i++
	}
	debut, n := a.i, 0
	for a.car(0) != ']' {
		c := a.car(0)
		if c == -1 {
			a.refuser("classe non fermée")
		}
		if c == '[' {
			a.refuser("« [ » non échappé dans une classe")
		}
		var estCar bool
		var v rune
		switch {
		case c == '\\':
			estCar, v = a.echappement(true)
		case c == '-':
			if a.i != debut && a.car(1) != ']' {
				a.refuser("« - » littéral seulement en première ou dernière position")
			}
			estCar, v = true, '-'
			a.i++
		default:
			estCar, v = true, c
			a.i++
		}
		n++
		if a.car(0) == '-' && a.car(1) != ']' && a.car(1) != -1 {
			a.i++
			var estCar2 bool
			var w rune
			switch a.car(0) {
			case '\\':
				estCar2, w = a.echappement(true)
			case '[':
				a.refuser("« [ » non échappé dans une classe")
			default:
				estCar2, w = true, a.car(0)
				a.i++
			}
			if !estCar || !estCar2 {
				a.refuser("intervalle dont une borne est une classe")
			}
			if v > w {
				a.refuser("intervalle décroissant")
			}
		}
	}
	if n == 0 {
		a.refuser("classe vide")
	}
	a.i++ // ]
}

var reQuantificateur = regexp.MustCompile(`^\{([0-9]{1,4})(,([0-9]{0,4}))?\}`)

func (a *analyseMotif) quantificateur() bool {
	switch c := a.car(0); {
	case c == '*' || c == '+' || c == '?':
		a.i++
	case c == '{':
		m := reQuantificateur.FindStringSubmatch(string(a.r[a.i:]))
		if m == nil {
			a.refuser("« { » qui n'ouvre pas un quantificateur")
		}
		n, _ := strconv.Atoi(m[1])
		mx := n
		if m[2] != "" {
			if m[3] == "" {
				mx = -1
			} else {
				mx, _ = strconv.Atoi(m[3])
			}
		}
		if n > 1000 || (mx != -1 && (mx > 1000 || mx < n)) {
			a.refuser("quantificateur hors de 0 ≤ n ≤ m ≤ 1000")
		}
		a.i += len([]rune(m[0]))
	default:
		return false
	}
	if a.car(0) == '?' {
		a.i++
	}
	if c := a.car(0); c == '*' || c == '+' || c == '?' || c == '{' {
		a.refuser("quantificateur répété ou possessif")
	}
	return true
}

func (a *analyseMotif) alternative(profondeur int) {
	for {
		a.sequence(profondeur)
		if a.car(0) != '|' {
			return
		}
		a.i++
	}
}

func (a *analyseMotif) sequence(profondeur int) {
	for {
		c := a.car(0)
		if c == -1 || c == '|' || c == ')' {
			if c == ')' && profondeur == 0 {
				a.refuser("« ) » sans « ( »")
			}
			return
		}
		quantifiable := true
		switch {
		case c == '^' || c == '$':
			a.i++
			quantifiable = false
		case c == '\\':
			if estCar, v := a.echappement(false); !estCar && v == -1 {
				quantifiable = false
			}
		case c == '[':
			a.classe()
		case c == '(':
			a.i++
			if a.car(0) == '?' {
				reste := string(a.r[a.i:])
				m := regexp.MustCompile(`^\?(?::|P?<([^>]*)>)`).FindStringSubmatch(reste)
				if m == nil {
					a.refuser("construction (?…) hors du sous-ensemble commun")
				}
				if m[1] != "" || len(m[0]) > 2 {
					if !reNomGroupe.MatchString(m[1]) {
						a.refuser("nom de groupe invalide")
					}
					if a.noms[m[1]] {
						a.refuser("nom de groupe en double")
					}
					a.noms[m[1]] = true
				}
				a.i += len([]rune(m[0]))
			}
			a.alternative(profondeur + 1)
			if a.car(0) != ')' {
				a.refuser("groupe non fermé")
			}
			a.i++
		case c == '.':
			a.refuser("« . » refusé")
		case containsRune(`^$|?*+()[]{}`, c):
			a.refuser("« %c » non échappé", c)
		default:
			a.i++
		}
		if a.quantificateur() && !quantifiable {
			a.refuser("quantificateur sur une ancre ou une frontière")
		}
	}
}

// ErreurMotifCommun rend "" si le motif est dans le sous-ensemble commun
// d'EX-10.6 et se compile en RE2, sinon la raison du refus.
func ErreurMotifCommun(motif string) (raison string) {
	a := &analyseMotif{r: []rune(motif), noms: map[string]bool{}}
	defer func() {
		if x := recover(); x != nil {
			if x != a {
				panic(x)
			}
			raison = a.erreur
		}
	}()
	a.alternative(0)
	if a.i < len(a.r) {
		a.refuser("« ) » sans « ( »")
	}
	if _, err := regexp.Compile(motif); err != nil {
		return "motif invalide en RE2 : " + err.Error()
	}
	return ""
}
