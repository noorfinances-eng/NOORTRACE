// Lecture d'une requête d'hôte par le frontal MCP (CT-2 4.4 pas 1, EX-4.3,
// EX-4.43, EX-4.44) et recopie des octets JSON sans blancs non significatifs.

package main

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
)

// Bornes par défaut de l'analyse d'une requête (4.4 pas 1 :
// limits.json_max_depth, limits.json_max_members).
const (
	ProfondeurRequeteMax = 128
	MembresRequeteMax    = 100000
)

// SansBlancs retire d'un texte JSON valide les blancs non significatifs
// (U+0020, U+0009, U+000A, U+000D hors des chaînes, EX-4.43) ; aucune valeur
// ne change.
func SansBlancs(t []byte) []byte {
	var out bytes.Buffer
	dansChaine := false
	for i := 0; i < len(t); i++ {
		c := t[i]
		switch {
		case dansChaine:
			out.WriteByte(c)
			if c == '\\' && i+1 < len(t) {
				i++
				out.WriteByte(t[i])
			} else if c == '"' {
				dansChaine = false
			}
		case c == '"':
			dansChaine = true
			out.WriteByte(c)
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
		default:
			out.WriteByte(c)
		}
	}
	return out.Bytes()
}

var reLitteralNombre = regexp.MustCompile(`^(-?)([0-9]+)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$`)

// decimal normalisé d'un littéral : signe, chiffres sans zéro de tête ni de
// queue, exposant (valeur = chiffres × 10^exposant) ; ok faux si l'exposant
// ne tient pas sur 64 bits.
func decimalNormalise(lit string) (signe, chiffres string, exposant int64, ok bool) {
	m := reLitteralNombre.FindStringSubmatch(lit)
	if m == nil {
		return "", "", 0, false
	}
	e := int64(0)
	if m[4] != "" {
		v, err := strconv.ParseInt(m[4], 10, 64)
		if err != nil {
			return "", "", 0, false
		}
		e = v
	}
	c := strings.TrimLeft(m[2]+m[3], "0")
	e -= int64(len(m[3]))
	if c == "" {
		return "", "0", 0, true
	}
	q := len(c) - len(strings.TrimRight(c, "0"))
	return m[1], c[:len(c)-q], e + int64(q), true
}

// NombreExact dit si un littéral de nombre JSON a exactement la valeur
// décimale de sa forme JCS intégral (EX-4.44) : 0.75, 1.0, 1e3 oui ;
// 12345678901234567890 (forme 12345678901234567000) et
// 0.10000000000000000001 (forme 0.1) non ; un nombre hors de la double
// précision non plus.
func NombreExact(lit string) bool {
	f, err := NombreDouble(lit)
	if err != nil {
		return false
	}
	s1, c1, e1, ok1 := decimalNormalise(lit)
	s2, c2, e2, ok2 := decimalNormalise(NombreES6(f))
	if !ok1 || !ok2 {
		return false
	}
	if c1 == "0" && c2 == "0" {
		return true
	}
	return s1 == s2 && c1 == c2 && e1 == e2
}

// nombresDe parcourt une valeur et appelle f sur chaque littéral de nombre.
func nombresDe(v *Value, f func(string)) {
	if v == nil {
		return
	}
	switch v.Kind {
	case KindNumber:
		f(v.Num)
	case KindArray:
		for _, x := range v.Arr {
			nombresDe(x, f)
		}
	case KindObject:
		for _, m := range v.Obj {
			nombresDe(m.Val, f)
		}
	}
}

// dansBornes vérifie la profondeur et le nombre de membres ou d'éléments.
func dansBornes(v *Value, prof int) bool {
	if prof > ProfondeurRequeteMax {
		return false
	}
	switch v.Kind {
	case KindArray:
		if len(v.Arr) > MembresRequeteMax {
			return false
		}
		for _, x := range v.Arr {
			if !dansBornes(x, prof+1) {
				return false
			}
		}
	case KindObject:
		if len(v.Obj) > MembresRequeteMax {
			return false
		}
		for _, m := range v.Obj {
			if !dansBornes(m.Val, prof+1) {
				return false
			}
		}
	}
	return true
}

// RequeteLue est le résultat de la lecture d'une requête d'hôte.
type RequeteLue struct {
	Msg     *Value // requête admise
	Erreur  *Value // objet error JSON-RPC rendu, si refus
	IDTexte string // octets de l'id tels que reçus, ou "null"
}

func erreurRPC(code int64, message, raison string) *Value {
	e := Objet("code", Entier(code), "message", Chaine(message))
	if raison != "" {
		Definir(e, "data", Objet("reason", Chaine(raison)))
	}
	return e
}

// LireRequeteHote applique le pas 1 de 4.4. cadrage vaut "ligne" (stdio,
// connecteur, démon : un CR est refusé) ou "corps" (corps POST HTTP).
func LireRequeteHote(texte []byte, cadrage string) RequeteLue {
	rien := RequeteLue{IDTexte: "null"}
	if cadrage != "corps" && bytes.IndexByte(texte, '\r') >= 0 {
		rien.Erreur = erreurRPC(-32700, "Parse error", "cr_dans_la_ligne")
		return rien
	}
	v, err := ParseJSON(texte)
	if err != nil || !dansBornes(v, 1) {
		rien.Erreur = erreurRPC(-32700, "Parse error", "")
		return rien
	}
	horsDouble := false
	nombresDe(v, func(l string) {
		if _, err := NombreDouble(l); err != nil {
			horsDouble = true
		}
	})
	if horsDouble {
		// l'analyse stricte s'arrête sur ce nombre : l'id n'est pas lu (EX-4.44)
		rien.Erreur = erreurRPC(-32602, "Invalid params", "arguments_non_canonisables")
		return rien
	}
	if v.Kind == KindArray {
		rien.Erreur = erreurRPC(-32600, "Invalid Request", "lot_non_pris_en_charge")
		return rien
	}
	if v.Kind != KindObject || chaineDe(v, "jsonrpc") != "2.0" || !EstChaine(v.Get("method")) {
		rien.Erreur = erreurRPC(-32600, "Invalid Request", "")
		return rien
	}
	lu := RequeteLue{Msg: v, IDTexte: "null"}
	if id := v.Get("id"); id != nil {
		lu.IDTexte = string(texte[id.Debut:id.Fin])
	}
	if chaineDe(v, "method") == "tools/call" {
		exact := true
		nombresDe(v.Get("params").Get("arguments"), func(l string) {
			if !NombreExact(l) {
				exact = false
			}
		})
		if !exact {
			lu.Erreur = erreurRPC(-32602, "Invalid params", "nombre_non_representable")
			lu.Msg = nil
		}
	}
	return lu
}
