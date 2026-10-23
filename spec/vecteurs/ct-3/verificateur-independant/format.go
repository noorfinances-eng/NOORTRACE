// Forme des fichiers JSON des vecteurs (CT-3 EX-A.1) : « écrits par
// JSON.stringify(objet, null, 2) suivi d'un saut de ligne ». Le texte est
// réécrit ici à partir de la valeur analysée (membres dans l'ordre du
// fichier), selon les règles de JSON.stringify d'ECMAScript 2019 :
// indentation de deux espaces, « "clé": valeur », conteneurs vides « {} » et
// « [] », nombres par Number::toString (CT-2 §8.1), chaînes avec
// l'échappement minimal, substitut isolé écrit \udxxx en minuscules (JSON
// bien formé, ECMAScript 2019).

package main

import (
	"strings"
	"unicode/utf8"
)

// Stringify2 rend JSON.stringify(v, null, 2).
func Stringify2(v *Value) (string, error) {
	var sb strings.Builder
	if err := stringify(&sb, v, ""); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func stringify(sb *strings.Builder, v *Value, ind string) error {
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
		f, err := NombreDouble(v.Num)
		if err != nil {
			return err
		}
		sb.WriteString(NombreES6(f))
	case KindString:
		echapperES(sb, v.Str)
	case KindArray:
		if len(v.Arr) == 0 {
			sb.WriteString("[]")
			return nil
		}
		sb.WriteString("[\n")
		for i, e := range v.Arr {
			if i > 0 {
				sb.WriteString(",\n")
			}
			sb.WriteString(ind + "  ")
			if err := stringify(sb, e, ind+"  "); err != nil {
				return err
			}
		}
		sb.WriteString("\n" + ind + "]")
	case KindObject:
		if len(v.Obj) == 0 {
			sb.WriteString("{}")
			return nil
		}
		sb.WriteString("{\n")
		for i, m := range v.Obj {
			if i > 0 {
				sb.WriteString(",\n")
			}
			sb.WriteString(ind + "  ")
			echapperES(sb, m.Key)
			sb.WriteString(": ")
			if err := stringify(sb, m.Val, ind+"  "); err != nil {
				return err
			}
		}
		sb.WriteString("\n" + ind + "}")
	}
	return nil
}

// echapperES écrit une chaîne comme JSON.stringify (ECMAScript 2019) ; un
// substitut isolé (forme WTF-8 de json.go) est écrit \udxxx.
func echapperES(sb *strings.Builder, s string) {
	const hexa = "0123456789abcdef"
	sb.WriteByte('"')
	for i := 0; i < len(s); {
		r, t := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && t == 1 && i+2 < len(s) && s[i] == 0xED && s[i+1] >= 0xA0 && s[i+1] <= 0xBF {
			u := (int(s[i])&0x0F)<<12 | (int(s[i+1])&0x3F)<<6 | int(s[i+2])&0x3F
			sb.WriteString(`\u`)
			sb.WriteByte(hexa[u>>12&0xF])
			sb.WriteByte(hexa[u>>8&0xF])
			sb.WriteByte(hexa[u>>4&0xF])
			sb.WriteByte(hexa[u&0xF])
			i += 3
			continue
		}
		i += t
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
