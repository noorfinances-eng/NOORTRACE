// Construction et rendu de valeurs JSON (type Value de json.go) : les
// actions et les demandes du planificateur sont bâties en Value puis mises en
// forme canonique JCS v0 pour la confrontation ; les rendus du rapport
// gardent les nombres non entiers (formule de coût, précision d'un jeton).

package main

import (
	"math"
	"sort"
	"strconv"
	"strings"
)

func vNull() *Value               { return &Value{Kind: KindNull} }
func vBool(b bool) *Value         { return &Value{Kind: KindBool, Bool: b} }
func vInt(n int64) *Value         { return &Value{Kind: KindNumber, Num: strconv.FormatInt(n, 10)} }
func vStr(s string) *Value        { return &Value{Kind: KindString, Str: s} }
func vArr(items ...*Value) *Value { return &Value{Kind: KindArray, Arr: append([]*Value{}, items...)} }

// vNum rend un nombre tel que JSON.stringify l'écrirait (entier sans point,
// sinon la plus courte représentation exacte).
func vNum(f float64) *Value {
	if f == math.Trunc(f) && math.Abs(f) < 1e21 {
		return &Value{Kind: KindNumber, Num: strconv.FormatInt(int64(f), 10)}
	}
	return &Value{Kind: KindNumber, Num: strconv.FormatFloat(f, 'f', -1, 64)}
}

// vObj construit un objet depuis des paires clé, valeur (dans l'ordre donné).
func vObj(kv ...any) *Value {
	v := &Value{Kind: KindObject}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Obj = append(v.Obj, Member{Key: kv[i].(string), Val: kv[i+1].(*Value)})
	}
	return v
}
func vStrOuNul(s *string) *Value {
	if s == nil {
		return vNull()
	}
	return vStr(*s)
}
func vIntOuNul(n *int64) *Value {
	if n == nil {
		return vNull()
	}
	return vInt(*n)
}
func vBoolOuNul(b *bool) *Value {
	if b == nil {
		return vNull()
	}
	return vBool(*b)
}
func vChaines(l []string) *Value {
	v := &Value{Kind: KindArray, Arr: []*Value{}}
	for _, s := range l {
		v.Arr = append(v.Arr, vStr(s))
	}
	return v
}
func vEntiers(l []int64) *Value {
	v := &Value{Kind: KindArray, Arr: []*Value{}}
	for _, n := range l {
		v.Arr = append(v.Arr, vInt(n))
	}
	return v
}

// Rendu écrit une valeur en JSON compact, membres triés comme JCS, nombres
// tels quels : forme de confrontation des familles qui portent des nombres
// non entiers, et texte des rapports.
func Rendu(v *Value) string {
	var sb strings.Builder
	rendre(&sb, v)
	return sb.String()
}

func rendre(sb *strings.Builder, v *Value) {
	if v == nil {
		sb.WriteString("null")
		return
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
		sb.WriteString(nombreNormalise(v.Num))
	case KindString:
		EchapperChaine(sb, v.Str)
	case KindArray:
		sb.WriteByte('[')
		for i, e := range v.Arr {
			if i > 0 {
				sb.WriteByte(',')
			}
			rendre(sb, e)
		}
		sb.WriteByte(']')
	case KindObject:
		membres := make([]Member, len(v.Obj))
		copy(membres, v.Obj)
		sort.SliceStable(membres, func(i, j int) bool { return ComparerUTF16(membres[i].Key, membres[j].Key) < 0 })
		sb.WriteByte('{')
		for i, m := range membres {
			if i > 0 {
				sb.WriteByte(',')
			}
			EchapperChaine(sb, m.Key)
			sb.WriteByte(':')
			rendre(sb, m.Val)
		}
		sb.WriteByte('}')
	}
}

// nombreNormalise ramène un littéral numérique JSON à la forme de
// JSON.stringify (1.0 → 1, 2.50 → 2.5), pour comparer des nombres égaux.
func nombreNormalise(lit string) string {
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil {
		return lit
	}
	return vNum(f).Num
}

// CanoniqueOuRendu rend la forme canonique JCS v0, ou le rendu compact si la
// valeur porte un nombre que JCS v0 refuse.
func CanoniqueOuRendu(v *Value) string {
	if b, err := Canonique(v); err == nil {
		return string(b)
	}
	return Rendu(v)
}

// --- lecture ---------------------------------------------------------------

// champ descend dans un objet par une suite de clés ; nil si absent.
func champ(v *Value, cles ...string) *Value {
	for _, k := range cles {
		v = v.Get(k)
		if v == nil {
			return nil
		}
	}
	return v
}
func chaineDe(v *Value, cles ...string) (string, bool) {
	c := champ(v, cles...)
	if c == nil || c.Kind != KindString {
		return "", false
	}
	return c.Str, true
}
func entierDe(v *Value, cles ...string) (int64, bool) {
	c := champ(v, cles...)
	if c == nil || c.Kind != KindNumber {
		return 0, false
	}
	n, err := strconv.ParseInt(c.Num, 10, 64)
	if err != nil {
		f, err2 := strconv.ParseFloat(c.Num, 64)
		if err2 != nil || f != math.Trunc(f) {
			return 0, false
		}
		return int64(f), true
	}
	return n, true
}
func nombreDe(v *Value, cles ...string) (float64, bool) {
	c := champ(v, cles...)
	if c == nil || c.Kind != KindNumber {
		return 0, false
	}
	f, err := strconv.ParseFloat(c.Num, 64)
	return f, err == nil
}
func booleenDe(v *Value, cles ...string) (bool, bool) {
	c := champ(v, cles...)
	if c == nil || c.Kind != KindBool {
		return false, false
	}
	return c.Bool, true
}
func estNul(v *Value, cles ...string) bool {
	c := champ(v, cles...)
	return c == nil || c.Kind == KindNull
}
func chainesDe(v *Value, cles ...string) []string {
	c := champ(v, cles...)
	if c == nil || c.Kind != KindArray {
		return nil
	}
	out := []string{}
	for _, e := range c.Arr {
		if e.Kind == KindString {
			out = append(out, e.Str)
		}
	}
	return out
}
func entiersDe(v *Value, cles ...string) []int64 {
	c := champ(v, cles...)
	if c == nil || c.Kind != KindArray {
		return nil
	}
	out := []int64{}
	for _, e := range c.Arr {
		if n, err := strconv.ParseInt(e.Num, 10, 64); e.Kind == KindNumber && err == nil {
			out = append(out, n)
		}
	}
	return out
}
func ptrChaine(v *Value, cles ...string) *string {
	if s, ok := chaineDe(v, cles...); ok {
		return &s
	}
	return nil
}
func ptrEntier(v *Value, cles ...string) *int64 {
	if n, ok := entierDe(v, cles...); ok {
		return &n
	}
	return nil
}
func ptrBool(v *Value, cles ...string) *bool {
	if b, ok := booleenDe(v, cles...); ok {
		return &b
	}
	return nil
}
func ptrNombre(v *Value, cles ...string) *float64 {
	if f, ok := nombreDe(v, cles...); ok {
		return &f
	}
	return nil
}
func chaineOu(v *Value, defaut string, cles ...string) string {
	if s, ok := chaineDe(v, cles...); ok {
		return s
	}
	return defaut
}
func entierOu(v *Value, defaut int64, cles ...string) int64 {
	if n, ok := entierDe(v, cles...); ok {
		return n
	}
	return defaut
}
func nombreOu(v *Value, defaut float64, cles ...string) float64 {
	if f, ok := nombreDe(v, cles...); ok {
		return f
	}
	return defaut
}
func booleenOu(v *Value, defaut bool, cles ...string) bool {
	if b, ok := booleenDe(v, cles...); ok {
		return b
	}
	return defaut
}
