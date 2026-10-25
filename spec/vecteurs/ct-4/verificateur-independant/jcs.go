// Forme canonique JCS v0 (CT-1 §4) et périodes (CT-1 §9 et §10), pour ce que
// CT-4 en emploie : periodHash d'un manifeste (CT-1 §10.2, entrée de RG-4 et
// de RG-5) et racine RFC 6962 du manifeste d'exemple de A.2.

package main

import (
	"errors"
	"sort"
	"strings"
	"unicode/utf16"
)

// JCS rend la forme canonique d'une valeur (CT-1 §4 : membres triés par
// unités de code UTF-16, aucun espace, entiers seuls).
func JCS(v *Value) (string, error) {
	var sb strings.Builder
	if err := jcs(&sb, v); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func cleUTF16(s string) []uint16 { return utf16.Encode([]rune(s)) }

func jcs(sb *strings.Builder, v *Value) error {
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
		n, ok := EntierLitteral(v.Num)
		if !ok {
			return errors.New("nombre non entier : interdit par JCS v0")
		}
		if n.BitLen() > 53 {
			return errors.New("entier hors de l'intervalle sûr")
		}
		sb.WriteString(n.String())
	case KindString:
		if !ChaineBienFormee(v.Str) {
			return errors.New("substitut isolé")
		}
		EchapperChaine(sb, v.Str)
	case KindArray:
		sb.WriteByte('[')
		for i, e := range v.Arr {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := jcs(sb, e); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	case KindObject:
		ms := append([]Member{}, v.Obj...)
		sort.SliceStable(ms, func(i, j int) bool {
			a, b := cleUTF16(ms[i].Key), cleUTF16(ms[j].Key)
			for k := 0; k < len(a) && k < len(b); k++ {
				if a[k] != b[k] {
					return a[k] < b[k]
				}
			}
			return len(a) < len(b)
		})
		sb.WriteByte('{')
		for i, m := range ms {
			if i > 0 {
				sb.WriteByte(',')
			}
			EchapperChaine(sb, m.Key)
			sb.WriteByte(':')
			if err := jcs(sb, m.Val); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	}
	return nil
}

// PrefixeManifeste est P_M = "noortrace/manifeste/v0\n" (CT-1 §10.2).
var PrefixeManifeste = []byte("noortrace/manifeste/v0\n")

// PeriodHash rend SHA-256(P_M ‖ JCS(manifeste)) (CT-1 §10.2).
func PeriodHash(m *Value) ([]byte, error) {
	c, err := JCS(m)
	if err != nil {
		return nil, err
	}
	return Sha256(concat(PrefixeManifeste, []byte(c))), nil
}

// RacineRFC6962 rend la racine d'un arbre de feuilles D[i] (CT-1 §9.1 :
// feuille SHA-256(0x00 ‖ D[i]), nœud SHA-256(0x01 ‖ g ‖ d), k la plus grande
// puissance de 2 strictement inférieure à n ; période vide : 32 octets nuls,
// CT-1 §9.2).
func RacineRFC6962(d [][]byte) []byte {
	if len(d) == 0 {
		return make([]byte, 32)
	}
	return mth(d)
}

func mth(d [][]byte) []byte {
	if len(d) == 1 {
		return Sha256(concat([]byte{0}, d[0]))
	}
	k := 1
	for k*2 < len(d) {
		k *= 2
	}
	return Sha256(concat([]byte{1}, mth(d[:k]), mth(d[k:])))
}
