// Constructeurs de valeurs JSON (ordre des membres conservé), pour écrire
// les rapports recalculés sous la forme que JSON.stringify leur donnerait.

package main

import "strconv"

// VObj construit un objet à partir de couples (nom, valeur).
func VObj(couples ...any) *Value {
	v := &Value{Kind: KindObject}
	for i := 0; i+1 < len(couples); i += 2 {
		v.Obj = append(v.Obj, Membre{Cle: couples[i].(string), Val: couples[i+1].(*Value)})
	}
	return v
}

// VStr construit une chaîne.
func VStr(s string) *Value { return &Value{Kind: KindString, Str: s} }

// VNum construit un nombre (texte de Number::toString).
func VNum(f float64) *Value { return &Value{Kind: KindNumber, Num: NombreES6(f)} }

// VInt construit un nombre entier.
func VInt(n int64) *Value { return &Value{Kind: KindNumber, Num: strconv.FormatInt(n, 10)} }

// VBool construit un booléen.
func VBool(b bool) *Value { return &Value{Kind: KindBool, Bool: b} }

// VNull construit null.
func VNull() *Value { return &Value{Kind: KindNull} }

// VArr construit un tableau.
func VArr(xs ...*Value) *Value { return &Value{Kind: KindArray, Arr: append([]*Value{}, xs...)} }

// VStrs construit un tableau de chaînes.
func VStrs(xs ...string) *Value {
	v := VArr()
	for _, s := range xs {
		v.Arr = append(v.Arr, VStr(s))
	}
	return v
}

// Copie rend la valeur elle-même, ou null si elle manque.
func Copie(v *Value) *Value {
	if v == nil {
		return VNull()
	}
	return v
}
