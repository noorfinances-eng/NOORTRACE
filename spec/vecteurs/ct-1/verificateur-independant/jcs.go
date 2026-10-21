// Forme canonique JCS v0 (CT-1 §4) : RFC 8785 restreinte aux entiers sûrs.
// Tri des membres par unités de code UTF-16, échappement minimal de
// JSON.stringify (ECMAScript 2019+), aucun nombre non entier.
//
// encoding/json n'est pas utilisé pour la sortie : json.Marshal échappe <, >,
// & et U+2028/U+2029, ce que JCS interdit.

package main

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// EntierSurMax est 2^53 - 1, la plus grande valeur entière admise.
const EntierSurMax = 9007199254740991

var reEntier = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// ErreurCanonique signale une valeur que la forme canonique v0 refuse (E-2).
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
	if err := ecrireCanonique(&sb, v, "$"); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}

// CanoniqueTexte analyse un texte JSON et rend sa forme canonique.
func CanoniqueTexte(src []byte) ([]byte, error) {
	v, err := ParseJSON(src)
	if err != nil {
		return nil, err
	}
	return Canonique(v)
}

// EntierCanonique valide un littéral de nombre JSON sous la restriction v0 et
// rend sa sérialisation canonique et sa valeur.
func EntierCanonique(lit string) (string, int64, error) {
	if !reEntier.MatchString(lit) {
		return "", 0, fmt.Errorf("nombre non entier %q (fraction ou exposant)", lit)
	}
	n, err := strconv.ParseInt(lit, 10, 64)
	if err != nil || n > EntierSurMax || n < -EntierSurMax {
		return "", 0, fmt.Errorf("entier %q hors de [-(2^53-1), 2^53-1]", lit)
	}
	if n == 0 {
		return "0", 0, nil // -0 se sérialise 0
	}
	return strconv.FormatInt(n, 10), n, nil
}

func ecrireCanonique(sb *strings.Builder, v *Value, chemin string) error {
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
		s, _, err := EntierCanonique(v.Num)
		if err != nil {
			return &ErreurCanonique{Chemin: chemin, Msg: err.Error()}
		}
		sb.WriteString(s)
	case KindString:
		EchapperChaine(sb, v.Str)
	case KindArray:
		sb.WriteByte('[')
		for i, e := range v.Arr {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := ecrireCanonique(sb, e, fmt.Sprintf("%s[%d]", chemin, i)); err != nil {
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
			EchapperChaine(sb, m.Key)
			sb.WriteByte(':')
			if err := ecrireCanonique(sb, m.Val, chemin+"."+m.Key); err != nil {
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
// autres contrôles en \u00xx minuscules ; tout le reste (barre oblique,
// non-ASCII, U+007F, U+2028, U+2029) en clair.
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
