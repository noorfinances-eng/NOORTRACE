// Sous-ensemble commun ECMAScript/RE2 des motifs nommés et des expressions
// d'extraction (CT-2 EX-10.6, EX-7.6) : liste autorisée, vérifiée par une
// analyse descendante du motif, point de code par point de code, puis les
// règles de structure et de taille de la version 0.3 : a) aucun
// quantificateur sur un groupe dont le corps contient un quantificateur ou
// une alternative ; b) aucun groupe quantifié dont le corps ne consomme
// rien ; c) taille développée d'au plus 1 000.

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
	// sansRegles désactive les règles a) et b) (calcul de la seule taille).
	sansRegles bool
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

var reQuantificateur = regexp.MustCompile(`^\{(0|[1-9][0-9]{0,3})(,((?:0|[1-9][0-9]{0,3})?))?\}`)

// reQuantificateurZero reconnaît un quantificateur dont n ou m a un zéro non
// significatif : EX-10.6, point 5, exige n et m de la forme 0|[1-9][0-9]{0,3}
// (RE2 et Go lisent sinon « { » comme un littéral).
var reQuantificateurZero = regexp.MustCompile(`^\{[0-9]{1,4}(,[0-9]{0,4})?\}`)

// TailleMaxMotif est la borne de la règle c) d'EX-10.6.
const TailleMaxMotif = 1000

// infoMotif résume une suite, une alternative ou un groupe pour les règles
// a) à c) : taille développée, présence d'un quantificateur ou d'une
// alternative à quelque profondeur que ce soit, présence d'un élément qui
// consomme un caractère (littéral, échappement de caractère, classe).
type infoMotif struct {
	taille     int64
	quantOuAlt bool
	consomme   bool
}

// plafond borne une taille développée pour éviter tout débordement : au-delà
// de la borne de la règle c), la valeur exacte n'importe plus.
func plafond(n int64) int64 {
	if n > 1<<40 {
		return 1 << 40
	}
	return n
}

// quantificateur lit un quantificateur éventuel ; rend s'il y en a un et son
// facteur de taille (règle c) : 1 pour *, + et ? ; max(n, 1) pour {n} ;
// n + 1 pour {n,} ; max(m, 1) pour {n,m}.
func (a *analyseMotif) quantificateur() (bool, int64) {
	facteur := int64(1)
	switch c := a.car(0); {
	case c == '*' || c == '+' || c == '?':
		a.i++
	case c == '{':
		m := reQuantificateur.FindStringSubmatch(string(a.r[a.i:]))
		if m == nil && reQuantificateurZero.MatchString(string(a.r[a.i:])) {
			a.refuser("zéro non significatif dans un quantificateur")
		}
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
		switch {
		case m[2] == "":
			facteur = int64(max(n, 1))
		case mx == -1:
			facteur = int64(n) + 1
		default:
			facteur = int64(max(mx, 1))
		}
		a.i += len([]rune(m[0]))
	default:
		return false, 1
	}
	if a.car(0) == '?' {
		a.i++
	}
	if c := a.car(0); c == '*' || c == '+' || c == '?' || c == '{' {
		a.refuser("quantificateur répété ou possessif")
	}
	return true, facteur
}

// alternative lit des suites séparées par « | » ; la taille est la somme de
// celles des suites (règle c).
func (a *analyseMotif) alternative(profondeur int) infoMotif {
	var out infoMotif
	for {
		s := a.sequence(profondeur)
		out.taille = plafond(out.taille + s.taille)
		out.quantOuAlt = out.quantOuAlt || s.quantOuAlt
		out.consomme = out.consomme || s.consomme
		if a.car(0) != '|' {
			return out
		}
		out.quantOuAlt = true
		a.i++
	}
}

// sequence lit une suite d'éléments éventuellement quantifiés et applique
// les règles a) et b) à chaque groupe quantifié.
func (a *analyseMotif) sequence(profondeur int) infoMotif {
	var out infoMotif
	for {
		c := a.car(0)
		if c == -1 || c == '|' || c == ')' {
			if c == ')' && profondeur == 0 {
				a.refuser("« ) » sans « ( »")
			}
			return out
		}
		quantifiable := true
		groupe := false
		elt := infoMotif{taille: 1}
		switch {
		case c == '^' || c == '$':
			a.i++
			quantifiable = false
		case c == '\\':
			if estCar, v := a.echappement(false); !estCar && v == -1 {
				quantifiable = false // frontière \b, \B : ne consomme rien
			} else {
				elt.consomme = true // échappement de caractère, ou \d \D \w \W
			}
		case c == '[':
			a.classe()
			elt.consomme = true
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
			elt = a.alternative(profondeur + 1)
			groupe = true
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
			elt.consomme = true
		}
		if q, facteur := a.quantificateur(); q {
			if !quantifiable {
				a.refuser("quantificateur sur une ancre ou une frontière")
			}
			if groupe && elt.quantOuAlt && !a.sansRegles {
				a.refuser("règle a) : quantificateur sur un groupe dont le corps contient un quantificateur ou une alternative")
			}
			if groupe && !elt.consomme && !a.sansRegles {
				a.refuser("règle b) : groupe quantifié dont le corps ne consomme aucun caractère")
			}
			elt.taille = plafond(elt.taille * facteur)
			elt.quantOuAlt = true
		}
		out.taille = plafond(out.taille + elt.taille)
		out.quantOuAlt = out.quantOuAlt || elt.quantOuAlt
		out.consomme = out.consomme || elt.consomme
	}
}

// TailleDeveloppee rend la taille développée d'un motif fait des
// constructions du sous-ensemble (règle c d'EX-10.6), qu'il respecte ou non
// les règles a) et b), ou -1 s'il n'est pas dans le sous-ensemble.
func TailleDeveloppee(motif string) (taille int64) {
	a := &analyseMotif{r: []rune(motif), noms: map[string]bool{}, sansRegles: true}
	defer func() {
		if x := recover(); x != nil {
			if x != a {
				panic(x)
			}
			taille = -1
		}
	}()
	info := a.alternative(0)
	if a.i < len(a.r) {
		return -1
	}
	return info.taille
}

// ErreurMotifCommun rend "" si le motif est dans le sous-ensemble commun
// d'EX-10.6, respecte les règles de structure et de taille a) à c) et se
// compile en RE2 (en Go, tel quel), sinon la raison du refus.
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
	info := a.alternative(0)
	if a.i < len(a.r) {
		a.refuser("« ) » sans « ( »")
	}
	if info.taille > TailleMaxMotif {
		return fmt.Sprintf("règle c) : taille développée %d, au-delà de %d", info.taille, TailleMaxMotif)
	}
	if _, err := regexp.Compile(motif); err != nil {
		return "motif invalide en RE2 : " + err.Error()
	}
	return ""
}
