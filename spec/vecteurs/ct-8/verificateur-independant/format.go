// Forme des fichiers JSON des vecteurs (CT-8 EX-A.1 : « indentés de deux
// espaces et finis par un saut de ligne ») et du manifeste (EX-13.12 :
// « JSON.stringify(manifeste, null, 2) suivi d'un saut de ligne »). Le texte
// est réécrit ici à partir de la valeur analysée (membres dans l'ordre du
// fichier), selon les règles de JSON.stringify d'ECMAScript : indentation de
// deux espaces, « "clé": valeur », conteneurs vides « {} » et « [] »,
// nombres par Number::toString, chaînes avec l'échappement minimal.
//
// Reprise de format.go et de NombreDouble, NombreES6 (jcs.go) du
// vérificateur indépendant de CT-3 (spec/vecteurs/ct-3/verificateur-
// independant/), adaptée à l'analyseur de json.go (membre Cle), qui refuse
// les substituts isolés : leur écriture \udxxx n'a donc plus d'objet.

package main

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Stringify2 rend JSON.stringify(v, null, 2).
func Stringify2(v *Value) (string, error) {
	var sb strings.Builder
	if err := stringify(&sb, v, ""); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// FormeVecteur dit si des octets sont exactement JSON.stringify(v, null, 2)
// suivi d'un saut de ligne, v étant la valeur qu'ils portent.
func FormeVecteur(octets []byte) (bool, string) {
	v, err := AnalyserJSON(octets)
	if err != nil {
		return false, err.Error()
	}
	s, err := Stringify2(v)
	if err != nil {
		return false, err.Error()
	}
	if s+"\n" != string(octets) {
		return false, "octets différents de JSON.stringify(valeur, null, 2) + \"\\n\""
	}
	return true, ""
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
			EchapperChaine(sb, m.Cle)
			sb.WriteString(": ")
			if err := stringify(sb, m.Val, ind+"  "); err != nil {
				return err
			}
		}
		sb.WriteString("\n" + ind + "}")
	}
	return nil
}

// NombreDouble lit un nombre JSON en double précision (arrondi au plus
// proche, comme ECMAScript).
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
