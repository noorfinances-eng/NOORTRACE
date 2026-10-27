// Forme canonique JCS v0 (CT-1 §4), à laquelle CT-7 renvoie pour le
// procès-verbal (EX-5.6, EX-5.7 : JCS(V)) et pour l'attestation (EX-7.6 :
// JCS(P)) : membres triés par unités de code UTF-16, aucun espace,
// échappement minimal de JSON.stringify d'ECMAScript, entiers seuls.
//
// encoding/json n'est pas employé pour la sortie : json.Marshal échappe <,
// >, & et U+2028, U+2029, que la forme canonique écrit en clair.

package main

import (
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"unicode/utf16"
)

// EntierSurMax est 2^53 − 1, borne de l'intervalle sûr (CT-1 §3).
const EntierSurMax = int64(1)<<53 - 1

// EntierLitteral rend la valeur d'un nombre JSON s'il est entier (ni
// fraction ni exposant) et dans [-(2^53-1), 2^53-1] (CT-1 §4, règle 4).
func EntierLitteral(lit string) (int64, error) {
	if strings.ContainsAny(lit, ".eE") {
		return 0, fmt.Errorf("nombre non entier %s", lit)
	}
	n, ok := new(big.Int).SetString(lit, 10)
	if !ok {
		return 0, fmt.Errorf("nombre illisible %s", lit)
	}
	if n.CmpAbs(big.NewInt(EntierSurMax)) > 0 {
		return 0, fmt.Errorf("entier %s hors de l'intervalle sûr", lit)
	}
	return n.Int64(), nil
}

// Canonique rend JCS(v), encodée en UTF-8.
func Canonique(v *Value) ([]byte, error) {
	var sb strings.Builder
	if err := ecrireCanonique(&sb, v); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}

func ecrireCanonique(sb *strings.Builder, v *Value) error {
	if v == nil {
		return errors.New("valeur absente")
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
		n, err := EntierLitteral(v.Num)
		if err != nil {
			return err
		}
		fmt.Fprintf(sb, "%d", n) // -0 s'écrit 0
	case KindString:
		EchapperChaine(sb, v.Str)
	case KindArray:
		sb.WriteByte('[')
		for i, x := range v.Arr {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := ecrireCanonique(sb, x); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	case KindObject:
		membres := append([]Membre(nil), v.Obj...)
		sort.SliceStable(membres, func(i, j int) bool { return ComparerUTF16(membres[i].Cle, membres[j].Cle) < 0 })
		for i := 1; i < len(membres); i++ {
			if membres[i].Cle == membres[i-1].Cle {
				return fmt.Errorf("nom de membre %q en double", membres[i].Cle)
			}
		}
		sb.WriteByte('{')
		for i, m := range membres {
			if i > 0 {
				sb.WriteByte(',')
			}
			EchapperChaine(sb, m.Cle)
			sb.WriteByte(':')
			if err := ecrireCanonique(sb, m.Val); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	}
	return nil
}

// ComparerUTF16 compare deux chaînes par unités de code UTF-16.
func ComparerUTF16(a, b string) int {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			if ua[i] < ub[i] {
				return -1
			}
			return 1
		}
	}
	return len(ua) - len(ub)
}

// EchapperChaine écrit une chaîne comme JSON.stringify (CT-1 §4, règle 3).
func EchapperChaine(sb *strings.Builder, s string) {
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
				fmt.Fprintf(sb, `\u%04x`, r)
			} else {
				sb.WriteRune(r)
			}
		}
	}
	sb.WriteByte('"')
}

// Egales dit si deux valeurs JSON sont égales : mêmes sortes, mêmes
// membres quel que soit leur ordre, nombres comparés par valeur.
func Egales(a, b *Value) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case KindNull:
		return true
	case KindBool:
		return a.Bool == b.Bool
	case KindNumber:
		x, okx := new(big.Rat).SetString(a.Num)
		y, oky := new(big.Rat).SetString(b.Num)
		return okx && oky && x.Cmp(y) == 0
	case KindString:
		return a.Str == b.Str
	case KindArray:
		if len(a.Arr) != len(b.Arr) {
			return false
		}
		for i := range a.Arr {
			if !Egales(a.Arr[i], b.Arr[i]) {
				return false
			}
		}
		return true
	case KindObject:
		if len(a.Obj) != len(b.Obj) {
			return false
		}
		for _, m := range a.Obj {
			if !Egales(m.Val, b.Get(m.Cle)) {
				return false
			}
		}
		return true
	}
	return false
}
