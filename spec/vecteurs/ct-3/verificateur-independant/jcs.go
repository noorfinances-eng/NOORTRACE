// Formes canoniques.
//
// JCS v0 (CT-1 §4) : RFC 8785 restreinte aux entiers sûrs, employée pour
// l'objet signé A des approbateurs (CT-1 §6.3, CT-3 §9.1). Copié du
// vérificateur indépendant CT-1 (spec/vecteurs/ct-1/verificateur-independant/jcs.go),
// que CT-3 EX-A.10 permet de reprendre, avec une adaptation : l'analyseur de
// ce module tolère les substituts isolés (json.go), la forme canonique les
// refuse donc ici explicitement (CT-1 §4 règle 3).
//
// JCS intégral (CT-2 §8.1, EX-8.1) : RFC 8785 telle quelle, nombres compris,
// employé pour la clé de rapprochement d'un ticket (CT-3 EX-7.3 : « octets
// JCS intégral (CT-2 §8.1) des arguments en clair »). Fonctions NombreDouble,
// NombreES6 et ecrireIntegral copiées du vérificateur indépendant CT-2
// (spec/vecteurs/ct-2/verificateur-independant/jcs_integral.go), lui-même
// écrit sans le JavaScript.
//
// encoding/json n'est pas utilisé pour la sortie : json.Marshal échappe <, >,
// & et U+2028/U+2029, ce que JCS interdit.

package main

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// EntierSurMax est 2^53 - 1, la plus grande valeur entière admise.
const EntierSurMax = 9007199254740991

var reEntier = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// ErreurCanonique signale une valeur que la forme canonique refuse.
type ErreurCanonique struct {
	Chemin string
	Msg    string
}

func (e *ErreurCanonique) Error() string {
	return fmt.Sprintf("forme canonique impossible en %s : %s", e.Chemin, e.Msg)
}

// Canonique rend la forme canonique JCS v0 d'une valeur, en UTF-8.
func Canonique(v *Value) ([]byte, error) {
	var sb strings.Builder
	if err := ecrireCanonique(&sb, v, "$", false); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}

// CanoniqueIntegral rend le JCS intégral d'une valeur, en UTF-8.
func CanoniqueIntegral(v *Value) ([]byte, error) {
	var sb strings.Builder
	if err := ecrireCanonique(&sb, v, "$", true); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}

// EntierCanonique valide un littéral de nombre JSON sous la restriction v0 et
// rend sa sérialisation canonique.
func EntierCanonique(lit string) (string, error) {
	if !reEntier.MatchString(lit) {
		return "", fmt.Errorf("nombre non entier %q (fraction ou exposant)", lit)
	}
	n, err := strconv.ParseInt(lit, 10, 64)
	if err != nil || n > EntierSurMax || n < -EntierSurMax {
		return "", fmt.Errorf("entier %q hors de [-(2^53-1), 2^53-1]", lit)
	}
	return strconv.FormatInt(n, 10), nil
}

// NombreDouble rend la valeur double précision la plus proche d'un littéral
// de nombre JSON ; un littéral hors de la double précision finie est refusé
// (RFC 8785 §3.2.2.3).
func NombreDouble(lit string) (float64, error) {
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil {
		var ne *strconv.NumError
		if errors.As(err, &ne) && errors.Is(ne.Err, strconv.ErrRange) && !math.IsInf(f, 0) {
			return f, nil // dénormalisé arrondi
		}
		return 0, fmt.Errorf("nombre %q hors de la double précision finie", lit)
	}
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return 0, fmt.Errorf("nombre %q non fini", lit)
	}
	return f, nil
}

// NombreES6 sérialise une double finie selon ECMAScript Number::toString.
func NombreES6(f float64) string {
	if f == 0 {
		return "0"
	}
	if f < 0 {
		return "-" + NombreES6(-f)
	}
	e := strconv.FormatFloat(f, 'e', -1, 64)
	i := strings.IndexByte(e, 'e')
	mantisse, exposant := e[:i], e[i+1:]
	chiffres := strings.Replace(mantisse, ".", "", 1)
	x, _ := strconv.Atoi(exposant)
	k := len(chiffres)
	n := x + 1
	switch {
	case k <= n && n <= 21:
		return chiffres + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		return chiffres[:n] + "." + chiffres[n:]
	case -6 < n && n <= 0:
		return "0." + strings.Repeat("0", -n) + chiffres
	}
	signe := "+"
	if n-1 < 0 {
		signe = "-"
	}
	abs := n - 1
	if abs < 0 {
		abs = -abs
	}
	if k == 1 {
		return chiffres + "e" + signe + strconv.Itoa(abs)
	}
	return chiffres[:1] + "." + chiffres[1:] + "e" + signe + strconv.Itoa(abs)
}

func ecrireCanonique(sb *strings.Builder, v *Value, chemin string, integral bool) error {
	if v == nil {
		return &ErreurCanonique{Chemin: chemin, Msg: "valeur absente"}
	}
	switch v.Kind {
	case KindNull:
		sb.WriteString("null")
	case KindBool:
		if v.Bool {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
	case KindNumber:
		if integral {
			f, err := NombreDouble(v.Num)
			if err != nil {
				return &ErreurCanonique{Chemin: chemin, Msg: err.Error()}
			}
			sb.WriteString(NombreES6(f))
		} else {
			s, err := EntierCanonique(v.Num)
			if err != nil {
				return &ErreurCanonique{Chemin: chemin, Msg: err.Error()}
			}
			sb.WriteString(s)
		}
	case KindString:
		if !ChaineBienFormee(v.Str) {
			return &ErreurCanonique{Chemin: chemin, Msg: "substitut isolé"}
		}
		EchapperChaine(sb, v.Str)
	case KindArray:
		sb.WriteByte('[')
		for i, e := range v.Arr {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := ecrireCanonique(sb, e, fmt.Sprintf("%s[%d]", chemin, i), integral); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	case KindObject:
		membres := make([]Member, len(v.Obj))
		copy(membres, v.Obj)
		sort.SliceStable(membres, func(i, j int) bool {
			return ComparerUTF16(membres[i].Key, membres[j].Key) < 0
		})
		sb.WriteByte('{')
		for i, m := range membres {
			if i > 0 {
				sb.WriteByte(',')
			}
			if !ChaineBienFormee(m.Key) {
				return &ErreurCanonique{Chemin: chemin, Msg: "substitut isolé dans une clé"}
			}
			EchapperChaine(sb, m.Key)
			sb.WriteByte(':')
			if err := ecrireCanonique(sb, m.Val, chemin+"."+m.Key, integral); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	}
	return nil
}

// ComparerUTF16 compare deux chaînes comme suites d'unités de code UTF-16
// (ordre de Array.prototype.sort en ECMAScript).
func ComparerUTF16(a, b string) int {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			if ua[i] < ub[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(ua) < len(ub):
		return -1
	case len(ua) > len(ub):
		return 1
	}
	return 0
}

// EchapperChaine écrit une chaîne entre guillemets avec l'échappement de
// JSON.stringify : guillemet, barre oblique inverse, \b \t \n \f \r, les
// autres contrôles en \u00xx minuscules ; tout le reste en clair.
func EchapperChaine(sb *strings.Builder, s string) {
	const hexa = "0123456789abcdef"
	sb.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\b':
			sb.WriteString(`\b`)
		case '\t':
			sb.WriteString(`\t`)
		case '\n':
			sb.WriteString(`\n`)
		case '\f':
			sb.WriteString(`\f`)
		case '\r':
			sb.WriteString(`\r`)
		default:
			if r < 0x20 {
				sb.WriteString(`\u00`)
				sb.WriteByte(hexa[r>>4])
				sb.WriteByte(hexa[r&0xF])
			} else {
				sb.WriteRune(r)
			}
		}
	}
	sb.WriteByte('"')
}

// RationnelDe rend la valeur mathématique exacte d'un littéral de nombre
// JSON (fraction et exposant compris), sans passer par un flottant.
// Un exposant de plus de quatre chiffres est refusé (il demanderait un
// entier démesuré ; aucun nombre des vecteurs n'en a).
func RationnelDe(lit string) (*big.Rat, bool) {
	if i := strings.IndexAny(lit, "eE"); i >= 0 {
		exp := strings.TrimLeft(lit[i+1:], "+-")
		if len(strings.TrimLeft(exp, "0")) > 4 {
			return nil, false
		}
	}
	r, ok := new(big.Rat).SetString(lit)
	return r, ok
}
