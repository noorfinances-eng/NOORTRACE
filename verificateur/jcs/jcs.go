// Paquet jcs : forme canonique JCS v0 de CT-1 §4 (RFC 8785 restreinte aux
// nombres entiers de l'intervalle sûr).
package jcs

import (
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/noorfinances-eng/noortrace/verificateur/jsonv"
)

// Erreur de forme canonique : la valeur n'a pas de forme JCS v0 (CT-1 E-2).
type Erreur struct{ Motif string }

func (e *Erreur) Error() string { return "forme canonique non calculable : " + e.Motif }

var maxSur = big.NewInt(9007199254740991)

// Canonique rend la forme canonique de la valeur, en octets UTF-8.
func Canonique(v *jsonv.Valeur) ([]byte, error) {
	var sb strings.Builder
	if err := ecrire(&sb, v); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}

// Calculable dit si la valeur a une forme canonique, et pourquoi sinon.
func Calculable(v *jsonv.Valeur) error {
	_, err := Canonique(v)
	return err
}

func ecrire(sb *strings.Builder, v *jsonv.Valeur) error {
	if v == nil {
		return &Erreur{"valeur absente"}
	}
	switch v.Genre {
	case jsonv.Nul:
		sb.WriteString("null")
	case jsonv.Booleen:
		if v.Bool {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
	case jsonv.Nombre:
		s, err := nombre(v.Texte)
		if err != nil {
			return err
		}
		sb.WriteString(s)
	case jsonv.Chaine:
		if v.SubstitutIsole {
			return &Erreur{"substitut isolé dans une chaîne"}
		}
		ecrireChaine(sb, v.Chaine)
	case jsonv.Tableau:
		sb.WriteByte('[')
		for i, e := range v.Elements {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := ecrire(sb, e); err != nil {
				return err
			}
		}
		sb.WriteByte(']')
	case jsonv.Objet:
		if v.Doublon {
			return &Erreur{"nom de membre en double"}
		}
		type cle struct {
			nom   string
			u16   []uint16
			index int
		}
		cles := make([]cle, 0, len(v.Membres))
		for i, m := range v.Membres {
			if m.NomSubstitut {
				return &Erreur{"substitut isolé dans un nom de membre"}
			}
			cles = append(cles, cle{m.Nom, utf16.Encode([]rune(m.Nom)), i})
		}
		sort.Slice(cles, func(a, b int) bool { return inferieur(cles[a].u16, cles[b].u16) })
		sb.WriteByte('{')
		for i, c := range cles {
			if i > 0 {
				sb.WriteByte(',')
			}
			ecrireChaine(sb, c.nom)
			sb.WriteByte(':')
			if err := ecrire(sb, v.Membres[c.index].Valeur); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	default:
		return &Erreur{"genre inconnu"}
	}
	return nil
}

func inferieur(a, b []uint16) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// nombre vérifie qu'un nombre est un entier écrit sans fraction ni exposant,
// dans [-(2^53-1), 2^53-1], et rend sa forme canonique (« -0 » devient « 0 »).
func nombre(texte string) (string, error) {
	t := texte
	neg := strings.HasPrefix(t, "-")
	if neg {
		t = t[1:]
	}
	if t == "" {
		return "", &Erreur{"nombre vide"}
	}
	for _, c := range t {
		if c < '0' || c > '9' {
			return "", &Erreur{fmt.Sprintf("nombre non entier ou avec exposant (%s)", texte)}
		}
	}
	if len(t) > 1 && t[0] == '0' {
		return "", &Erreur{fmt.Sprintf("nombre avec zéro de tête (%s)", texte)}
	}
	n, ok := new(big.Int).SetString(t, 10)
	if !ok {
		return "", &Erreur{"nombre illisible"}
	}
	if n.Cmp(maxSur) > 0 {
		return "", &Erreur{fmt.Sprintf("nombre hors de l'intervalle sûr (%s)", texte)}
	}
	if n.Sign() == 0 {
		return "0", nil
	}
	if neg {
		return "-" + n.String(), nil
	}
	return n.String(), nil
}

// ecrireChaine sérialise une chaîne comme JSON.stringify (CT-1 §4, règle 3).
func ecrireChaine(sb *strings.Builder, s string) {
	sb.WriteByte('"')
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == '"':
			sb.WriteString(`\"`)
		case r == '\\':
			sb.WriteString(`\\`)
		case r == '\b':
			sb.WriteString(`\b`)
		case r == '\t':
			sb.WriteString(`\t`)
		case r == '\n':
			sb.WriteString(`\n`)
		case r == '\f':
			sb.WriteString(`\f`)
		case r == '\r':
			sb.WriteString(`\r`)
		case r < 0x20:
			fmt.Fprintf(sb, `\u%04x`, r)
		default:
			sb.WriteString(s[i : i+n])
		}
		i += n
	}
	sb.WriteByte('"')
}

// ErrNonCanonique est rendue par les appelants qui exigent une forme
// canonique.
var ErrNonCanonique = errors.New("forme canonique non calculable")
