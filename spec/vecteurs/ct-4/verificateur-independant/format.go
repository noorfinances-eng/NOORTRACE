// Écriture des valeurs JSON et utilitaires d'octets.
//
// Stringify2 reproduit JSON.stringify(valeur, null, 2) d'ECMAScript 2019,
// forme que CT-4 EX-A.1 impose aux fichiers des vecteurs (« écrits par
// JSON.stringify(objet, null, 2) suivi d'un saut de ligne ») : indentation de
// deux espaces, « "clé": valeur », conteneurs vides « {} » et « [] »,
// chaînes avec l'échappement minimal de CT-1 §4, règle 3 (", \, \b, \f, \n,
// \r, \t, les autres contrôles en \u00xx minuscules, un substitut isolé en
// \udxxx). Les vecteurs de CT-4 ne portent que des entiers : un nombre non
// entier n'est pas pris en charge et le dit.

package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"unicode/utf8"
)

// EchapperChaine écrit une chaîne JSON comme JSON.stringify (CT-1 §4,
// règle 3), substituts isolés (forme WTF-8 de json.go) en \udxxx.
func EchapperChaine(sb *strings.Builder, s string) {
	sb.WriteByte('"')
	for i := 0; i < len(s); {
		c := s[i]
		if c < 0x80 {
			switch c {
			case '"':
				sb.WriteString(`\"`)
			case '\\':
				sb.WriteString(`\\`)
			case '\b':
				sb.WriteString(`\b`)
			case '\f':
				sb.WriteString(`\f`)
			case '\n':
				sb.WriteString(`\n`)
			case '\r':
				sb.WriteString(`\r`)
			case '\t':
				sb.WriteString(`\t`)
			default:
				if c < 0x20 {
					fmt.Fprintf(sb, `\u%04x`, c)
				} else {
					sb.WriteByte(c)
				}
			}
			i++
			continue
		}
		r, t := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && t == 1 && i+2 < len(s) && s[i] == 0xED && s[i+1] >= 0xA0 && s[i+1] <= 0xBF {
			u := int(s[i]&0x0F)<<12 | int(s[i+1]&0x3F)<<6 | int(s[i+2]&0x3F)
			fmt.Fprintf(sb, `\u%04x`, u)
			i += 3
			continue
		}
		sb.WriteString(s[i : i+t])
		i += t
	}
	sb.WriteByte('"')
}

// RationnelDe rend la valeur exacte d'un littéral numérique JSON.
func RationnelDe(lit string) (*big.Rat, bool) {
	r, ok := new(big.Rat).SetString(lit)
	return r, ok
}

// EntierLitteral dit si un littéral JSON est un entier écrit sans fraction ni
// exposant, et rend sa valeur.
func EntierLitteral(lit string) (*big.Int, bool) {
	if lit == "" || strings.ContainsAny(lit, ".eE") {
		return nil, false
	}
	n, ok := new(big.Int).SetString(lit, 10)
	return n, ok
}

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
		n, ok := EntierLitteral(v.Num)
		if !ok {
			return fmt.Errorf("nombre non entier %s : non pris en charge", v.Num)
		}
		if n.CmpAbs(big.NewInt(1<<53-1)) > 0 {
			return fmt.Errorf("entier %s hors de [-(2^53-1), 2^53-1]", v.Num)
		}
		sb.WriteString(n.String())
	case KindString:
		EchapperChaine(sb, v.Str)
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
			EchapperChaine(sb, m.Key)
			sb.WriteString(": ")
			if err := stringify(sb, m.Val, ind+"  "); err != nil {
				return err
			}
		}
		sb.WriteString("\n" + ind + "}")
	}
	return nil
}

// ------------------------------------------------------------ octets

// Hex0x écrit des octets en hexadécimal minuscule préfixé 0x (CT-1 §3).
func Hex0x(b []byte) string { return "0x" + hex.EncodeToString(b) }

// DecoderHex lit une chaîne 0x… en hexadécimal minuscule (CT-1 §3) ; les
// majuscules sont refusées.
func DecoderHex(s string) ([]byte, error) {
	if !strings.HasPrefix(s, "0x") {
		return nil, fmt.Errorf("%q : préfixe 0x attendu", s)
	}
	h := s[2:]
	if len(h)%2 != 0 {
		return nil, fmt.Errorf("%q : nombre impair de chiffres", s)
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return nil, fmt.Errorf("%q : chiffre hexadécimal minuscule attendu", s)
		}
	}
	return hex.DecodeString(h)
}

// DecoderHexN lit exactement n octets.
func DecoderHexN(s string, n int) ([]byte, error) {
	b, err := DecoderHex(s)
	if err != nil {
		return nil, err
	}
	if len(b) != n {
		return nil, fmt.Errorf("%q : %d octets attendus, %d lus", s, n, len(b))
	}
	return b, nil
}

// DecoderHexLibre lit une chaîne hexadécimale préfixée 0x ou 0X, en
// minuscules ou en majuscules (réponses brutes d'un nœud, adresses en casse
// mixte EIP-55).
func DecoderHexLibre(s string) ([]byte, error) {
	if len(s) < 2 || s[0] != '0' || (s[1] != 'x' && s[1] != 'X') {
		return nil, fmt.Errorf("%q : préfixe 0x attendu", s)
	}
	h := s[2:]
	if len(h)%2 != 0 {
		return nil, fmt.Errorf("%q : nombre impair de chiffres", s)
	}
	return hex.DecodeString(h)
}

// Quantite lit une quantité JSON-RPC (hexadécimal sans zéro de tête, CT-4 §0).
func Quantite(s string) (*big.Int, error) {
	if !strings.HasPrefix(s, "0x") || len(s) < 3 {
		return nil, fmt.Errorf("quantité %q : préfixe 0x attendu", s)
	}
	h := s[2:]
	if len(h) > 1 && h[0] == '0' {
		return nil, fmt.Errorf("quantité %q : zéro de tête", s)
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return nil, fmt.Errorf("quantité %q : chiffre hexadécimal minuscule attendu", s)
		}
	}
	n, ok := new(big.Int).SetString(h, 16)
	if !ok {
		return nil, fmt.Errorf("quantité %q illisible", s)
	}
	return n, nil
}

// QuantiteHex écrit une quantité JSON-RPC.
func QuantiteHex(n *big.Int) string { return "0x" + n.Text(16) }

// Decimal lit un entier décimal non signé écrit en chaîne (CT-4 §0 :
// entiers de 64 bits en chaînes décimales).
func Decimal(s string) (*big.Int, error) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return nil, fmt.Errorf("entier décimal %q mal formé", s)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return nil, fmt.Errorf("entier décimal %q mal formé", s)
		}
	}
	n, _ := new(big.Int).SetString(s, 10)
	return n, nil
}

// u256 écrit l'entier non signé x sur 32 octets grand-boutistes (CT-4 §0).
func u256(x *big.Int) []byte {
	b := make([]byte, 32)
	x.FillBytes(b)
	return b
}

// u256i écrit un petit entier sur 32 octets.
func u256i(x uint64) []byte { return u256(new(big.Int).SetUint64(x)) }

// u64be écrit x sur 8 octets grand-boutistes.
func u64be(x uint64) []byte {
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = byte(x)
		x >>= 8
	}
	return b
}

// concat concatène des tranches d'octets (‖ de CT-4 §0).
func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// estNul dit si tous les octets sont nuls.
func estNul(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

var errAbsent = errors.New("membre absent")

// Champ rend la chaîne d'un membre, ou une erreur s'il manque ou n'est pas
// une chaîne.
func Champ(v *Value, cle string) (string, error) {
	m := v.Get(cle)
	if m == nil {
		return "", fmt.Errorf("%s : %w", cle, errAbsent)
	}
	if m.Kind != KindString {
		return "", fmt.Errorf("%s : chaîne attendue", cle)
	}
	return m.Str, nil
}

// EntierChamp rend la valeur d'un membre entier JSON.
func EntierChamp(v *Value, cle string) (*big.Int, error) {
	m := v.Get(cle)
	if m == nil {
		return nil, fmt.Errorf("%s : %w", cle, errAbsent)
	}
	if m.Kind != KindNumber {
		return nil, fmt.Errorf("%s : nombre attendu", cle)
	}
	n, ok := EntierLitteral(m.Num)
	if !ok {
		return nil, fmt.Errorf("%s : entier attendu", cle)
	}
	return n, nil
}

// SansMembre rend une copie d'un objet privé d'un membre (récursivement si
// profond est vrai), pour les comparaisons « hors source ».
func SansMembre(v *Value, cle string, profond bool) *Value {
	if v == nil {
		return nil
	}
	c := &Value{Kind: v.Kind, Bool: v.Bool, Num: v.Num, Str: v.Str}
	switch v.Kind {
	case KindArray:
		c.Arr = make([]*Value, len(v.Arr))
		for i, e := range v.Arr {
			if profond {
				c.Arr[i] = SansMembre(e, cle, true)
			} else {
				c.Arr[i] = Copier(e)
			}
		}
	case KindObject:
		c.Obj = []Member{}
		for _, m := range v.Obj {
			if m.Key == cle {
				continue
			}
			if profond {
				c.Obj = append(c.Obj, Member{Key: m.Key, Val: SansMembre(m.Val, cle, true)})
			} else {
				c.Obj = append(c.Obj, Member{Key: m.Key, Val: Copier(m.Val)})
			}
		}
	}
	return c
}
