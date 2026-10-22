// JCS intégral (CT-2 §8.1, EX-8.1) : la RFC 8785 appliquée telle quelle,
// nombres compris. Membres d'objet triés par unités de code UTF-16, tableaux
// dans l'ordre, chaînes échappées comme en CT-1 §4 règle 3 (EchapperChaine,
// reprise du code CT-1), littéraux en minuscules, aucun espace, et nombres
// sérialisés par la règle ES6 Number::toString sur la valeur IEEE 754 double
// précision la plus proche du texte reçu, -0 sérialisé 0.
//
// encoding/json n'est pas employé pour la sortie : json.Marshal échappe <, >,
// & et U+2028, U+2029, et ne suit pas Number::toString pour les nombres.

package main

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// NombreDouble rend la valeur double précision la plus proche d'un littéral
// de nombre JSON (arrondi au plus proche, celui de strconv.ParseFloat et de
// ECMAScript). Un littéral dont la valeur dépasse la plus grande double finie
// est refusé : la RFC 8785 §3.2.2.3 exige une erreur pour NaN et Infinity, et
// le profil I-JSON (RFC 7493 §2.2) exclut ces nombres. Un dénormalisé trop
// petit devient 0 (arrondi), comme en ECMAScript.
func NombreDouble(lit string) (float64, error) {
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil {
		var ne *strconv.NumError
		if errors.As(err, &ne) && errors.Is(ne.Err, strconv.ErrRange) && math.IsInf(f, 0) {
			return 0, fmt.Errorf("nombre %q hors de la double précision finie (Infinity refusé, RFC 8785 §3.2.2.3)", lit)
		}
		if math.IsInf(f, 0) || math.IsNaN(f) {
			return 0, fmt.Errorf("nombre %q non fini", lit)
		}
		if !(errors.As(err, &ne) && errors.Is(ne.Err, strconv.ErrRange)) {
			return 0, fmt.Errorf("nombre %q illisible : %v", lit, err)
		}
	}
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return 0, fmt.Errorf("nombre %q non fini", lit)
	}
	return f, nil
}

// NombreES6 sérialise une double finie selon ECMAScript Number::toString
// (ECMA-262, 6.1.6.1.20) : chiffres les plus courts qui se relisent exactement
// (strconv.FormatFloat, précision -1), notation décimale pour
// 1e-7 ≤ |x| < 1e21, exponentielle sinon avec un signe explicite.
func NombreES6(f float64) string {
	if f == 0 {
		return "0" // 0 et -0
	}
	if f < 0 {
		return "-" + NombreES6(-f)
	}
	e := strconv.FormatFloat(f, 'e', -1, 64) // « d.ddde±XX »
	i := strings.IndexByte(e, 'e')
	mantisse, exposant := e[:i], e[i+1:]
	chiffres := strings.Replace(mantisse, ".", "", 1)
	x, _ := strconv.Atoi(exposant)
	k := len(chiffres) // nombre de chiffres significatifs
	n := x + 1         // valeur = 0.chiffres × 10^n
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

// CanoniqueIntegral rend le JCS intégral d'une valeur, en UTF-8.
func CanoniqueIntegral(v *Value) ([]byte, error) {
	var sb strings.Builder
	if err := ecrireIntegral(&sb, v, "$"); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}

// CanoniqueIntegralTexte analyse un texte JSON strictement (clés uniques,
// aucun substitut isolé, CT-1 §4) et rend son JCS intégral.
func CanoniqueIntegralTexte(src []byte) ([]byte, error) {
	v, err := ParseJSON(src)
	if err != nil {
		return nil, err
	}
	return CanoniqueIntegral(v)
}

// doitIntegral rend le JCS intégral ou une chaîne de diagnostic préfixée
// « ! » (pour les rapports).
func doitIntegral(v *Value) string {
	b, err := CanoniqueIntegral(v)
	if err != nil {
		return "! " + err.Error()
	}
	return string(b)
}

func ecrireIntegral(sb *strings.Builder, v *Value, chemin string) error {
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
		f, err := NombreDouble(v.Num)
		if err != nil {
			return &ErreurCanonique{Chemin: chemin, Msg: err.Error()}
		}
		sb.WriteString(NombreES6(f))
	case KindString:
		EchapperChaine(sb, v.Str)
	case KindArray:
		sb.WriteByte('[')
		for i, e := range v.Arr {
			if i > 0 {
				sb.WriteByte(',')
			}
			if err := ecrireIntegral(sb, e, fmt.Sprintf("%s[%d]", chemin, i)); err != nil {
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
		for i := 1; i < len(membres); i++ {
			if membres[i].Key == membres[i-1].Key {
				return &ErreurCanonique{Chemin: chemin, Msg: fmt.Sprintf("clé en double %q", membres[i].Key)}
			}
		}
		sb.WriteByte('{')
		for i, m := range membres {
			if i > 0 {
				sb.WriteByte(',')
			}
			EchapperChaine(sb, m.Key)
			sb.WriteByte(':')
			if err := ecrireIntegral(sb, m.Val, chemin+"."+m.Key); err != nil {
				return err
			}
		}
		sb.WriteByte('}')
	}
	return nil
}

// ---------------------------------------------------------------- valeurs

// Copier rend une copie profonde d'une valeur (sans les positions).
func Copier(v *Value) *Value {
	if v == nil {
		return nil
	}
	c := &Value{Kind: v.Kind, Bool: v.Bool, Num: v.Num, Str: v.Str}
	switch v.Kind {
	case KindArray:
		c.Arr = make([]*Value, len(v.Arr))
		for i, e := range v.Arr {
			c.Arr[i] = Copier(e)
		}
	case KindObject:
		c.Obj = make([]Member, len(v.Obj))
		for i, m := range v.Obj {
			c.Obj[i] = Member{Key: m.Key, Val: Copier(m.Val)}
		}
	}
	return c
}

// Chaine construit une valeur chaîne.
func Chaine(s string) *Value { return &Value{Kind: KindString, Str: s} }

// Nul construit le littéral null.
func Nul() *Value { return &Value{Kind: KindNull} }

// Booleen construit un booléen.
func Booleen(b bool) *Value { return &Value{Kind: KindBool, Bool: b} }

// Entier construit un nombre entier.
func Entier(n int64) *Value { return &Value{Kind: KindNumber, Num: strconv.FormatInt(n, 10)} }

// ObjetVide construit un objet sans membre.
func ObjetVide() *Value { return &Value{Kind: KindObject, Obj: []Member{}} }

// TableauVide construit un tableau sans élément.
func TableauVide() *Value { return &Value{Kind: KindArray, Arr: []*Value{}} }

// Definir remplace le membre nommé d'un objet, ou l'ajoute en fin.
func Definir(o *Value, cle string, val *Value) {
	if o == nil || o.Kind != KindObject {
		return
	}
	for i := range o.Obj {
		if o.Obj[i].Key == cle {
			o.Obj[i].Val = val
			return
		}
	}
	o.Obj = append(o.Obj, Member{Key: cle, Val: val})
}

// Retirer supprime le membre nommé d'un objet ; rend vrai s'il existait.
func Retirer(o *Value, cle string) bool {
	if o == nil || o.Kind != KindObject {
		return false
	}
	for i := range o.Obj {
		if o.Obj[i].Key == cle {
			o.Obj = append(o.Obj[:i], o.Obj[i+1:]...)
			return true
		}
	}
	return false
}

// Objet construit un objet à partir de paires clé, valeur.
func Objet(paires ...any) *Value {
	o := ObjetVide()
	for i := 0; i+1 < len(paires); i += 2 {
		o.Obj = append(o.Obj, Member{Key: paires[i].(string), Val: paires[i+1].(*Value)})
	}
	return o
}

// MemeValeur compare deux valeurs par leur JCS intégral (nombres à la
// précision double) ; deux valeurs non sérialisables ne sont pas égales.
func MemeValeur(a, b *Value) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	ca, err1 := CanoniqueIntegral(a)
	cb, err2 := CanoniqueIntegral(b)
	return err1 == nil && err2 == nil && string(ca) == string(cb)
}

// EstChaine dit si v est une chaîne.
func EstChaine(v *Value) bool { return v != nil && v.Kind == KindString }

// EstObjet dit si v est un objet.
func EstObjet(v *Value) bool { return v != nil && v.Kind == KindObject }

// EstTableau dit si v est un tableau.
func EstTableau(v *Value) bool { return v != nil && v.Kind == KindArray }

// EntierDe lit un nombre entier (littéral sans fraction ni exposant, ou
// double entière) ; rend faux sinon.
func EntierDe(v *Value) (int64, bool) {
	if v == nil || v.Kind != KindNumber {
		return 0, false
	}
	if n, err := strconv.ParseInt(v.Num, 10, 64); err == nil {
		return n, true
	}
	f, err := NombreDouble(v.Num)
	if err != nil || f != math.Trunc(f) || math.Abs(f) > 1<<53 {
		return 0, false
	}
	return int64(f), true
}
