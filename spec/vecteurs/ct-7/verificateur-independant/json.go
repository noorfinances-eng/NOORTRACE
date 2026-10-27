// Analyseur JSON strict (RFC 8259), écrit pour ce module : il conserve
// l'ordre des membres et le texte littéral des nombres, et refuse ce que la
// forme canonique JCS v0 (CT-1 §4, à laquelle CT-7 §5.6 et EX-7.2 renvoient)
// déclare invalide : nom de membre en double, substitut UTF-16 isolé, octets
// UTF-8 mal formés, marque d'ordre d'octets.
//
// encoding/json n'est pas employé pour l'analyse : il accepte les noms en
// double (le dernier l'emporte), remplace les substituts isolés et les
// octets invalides par U+FFFD et ne distingue pas 0 de 0.0 sans UseNumber.

package main

import (
	"fmt"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Kind est la sorte d'une valeur JSON.
type Kind int

// Les six sortes de valeurs JSON.
const (
	KindNull Kind = iota
	KindBool
	KindNumber
	KindString
	KindArray
	KindObject
)

func (k Kind) String() string {
	return [...]string{"null", "booléen", "nombre", "chaîne", "tableau", "objet"}[k]
}

// Membre est un couple (nom, valeur) d'un objet, dans l'ordre du texte.
type Membre struct {
	Cle string
	Val *Value
}

// Value est une valeur JSON analysée.
type Value struct {
	Kind Kind
	Bool bool
	Num  string // texte littéral du nombre
	Str  string
	Arr  []*Value
	Obj  []Membre
}

// Get rend la valeur du membre nommé, ou nil.
func (v *Value) Get(cle string) *Value {
	if v == nil || v.Kind != KindObject {
		return nil
	}
	for _, m := range v.Obj {
		if m.Cle == cle {
			return m.Val
		}
	}
	return nil
}

// Chemin suit une suite de noms de membres ; nil dès qu'un maillon manque.
func (v *Value) Chemin(cles ...string) *Value {
	for _, c := range cles {
		v = v.Get(c)
	}
	return v
}

// EstNull dit si la valeur existe et vaut null.
func (v *Value) EstNull() bool { return v != nil && v.Kind == KindNull }

// Chaine rend la chaîne, ou "" pour une autre sorte.
func (v *Value) Chaine() string {
	if v == nil || v.Kind != KindString {
		return ""
	}
	return v.Str
}

// Entier rend la valeur d'un nombre entier JSON qui tient dans un int64.
func (v *Value) Entier() (int64, bool) {
	if v == nil || v.Kind != KindNumber {
		return 0, false
	}
	n, err := EntierLitteral(v.Num)
	if err != nil {
		return 0, false
	}
	return n, true
}

// Cles rend les noms des membres d'un objet, dans l'ordre du texte.
func (v *Value) Cles() []string {
	var out []string
	if v != nil {
		for _, m := range v.Obj {
			out = append(out, m.Cle)
		}
	}
	return out
}

// Sans rend une copie superficielle d'un objet privé des membres nommés.
func (v *Value) Sans(noms ...string) *Value {
	c := &Value{Kind: KindObject}
	for _, m := range v.Obj {
		garder := true
		for _, n := range noms {
			if m.Cle == n {
				garder = false
			}
		}
		if garder {
			c.Obj = append(c.Obj, m)
		}
	}
	return c
}

// ErreurJSON décrit un texte refusé et la position du refus.
type ErreurJSON struct {
	Pos int
	Msg string
}

func (e *ErreurJSON) Error() string {
	return fmt.Sprintf("JSON refusé à l'octet %d : %s", e.Pos, e.Msg)
}

const profondeurMax = 256

// AnalyserJSON analyse un texte JSON complet (UTF-8 sans marque d'ordre
// d'octets, blancs autorisés autour de la valeur).
func AnalyserJSON(src []byte) (*Value, error) {
	if len(src) >= 3 && src[0] == 0xEF && src[1] == 0xBB && src[2] == 0xBF {
		return nil, &ErreurJSON{0, "marque d'ordre d'octets refusée"}
	}
	if !utf8.Valid(src) {
		return nil, &ErreurJSON{0, "texte UTF-8 mal formé"}
	}
	a := &analyseur{src: src}
	a.blancs()
	v, err := a.valeur(0)
	if err != nil {
		return nil, err
	}
	a.blancs()
	if a.pos != len(a.src) {
		return nil, a.erreur("données après la valeur")
	}
	return v, nil
}

// AnalyserJSONStrict analyse puis exige que tout nombre soit un entier de
// l'intervalle sûr (CT-1 §3 et §4 ; CR-1, AT-1).
func AnalyserJSONStrict(src []byte) (*Value, error) {
	v, err := AnalyserJSON(src)
	if err != nil {
		return nil, err
	}
	if err := VerifierEntiers(v, "$"); err != nil {
		return nil, err
	}
	return v, nil
}

// VerifierEntiers parcourt une valeur et refuse tout nombre non entier ou
// hors de [-(2^53-1), 2^53-1].
func VerifierEntiers(v *Value, chemin string) error {
	switch v.Kind {
	case KindNumber:
		if _, err := EntierLitteral(v.Num); err != nil {
			return fmt.Errorf("%s : %v", chemin, err)
		}
	case KindArray:
		for i, x := range v.Arr {
			if err := VerifierEntiers(x, fmt.Sprintf("%s[%d]", chemin, i)); err != nil {
				return err
			}
		}
	case KindObject:
		for _, m := range v.Obj {
			if err := VerifierEntiers(m.Val, chemin+"."+m.Cle); err != nil {
				return err
			}
		}
	}
	return nil
}

type analyseur struct {
	src []byte
	pos int
}

func (a *analyseur) erreur(msg string) error { return &ErreurJSON{a.pos, msg} }

func (a *analyseur) blancs() {
	for a.pos < len(a.src) {
		switch a.src[a.pos] {
		case ' ', '\t', '\n', '\r':
			a.pos++
		default:
			return
		}
	}
}

func (a *analyseur) valeur(prof int) (*Value, error) {
	if prof > profondeurMax {
		return nil, a.erreur("imbrication trop profonde")
	}
	if a.pos >= len(a.src) {
		return nil, a.erreur("fin de texte inattendue")
	}
	switch c := a.src[a.pos]; {
	case c == '{':
		return a.objet(prof)
	case c == '[':
		return a.tableau(prof)
	case c == '"':
		s, err := a.chaine()
		if err != nil {
			return nil, err
		}
		return &Value{Kind: KindString, Str: s}, nil
	case c == 't':
		return a.litteral("true", &Value{Kind: KindBool, Bool: true})
	case c == 'f':
		return a.litteral("false", &Value{Kind: KindBool})
	case c == 'n':
		return a.litteral("null", &Value{Kind: KindNull})
	case c == '-' || (c >= '0' && c <= '9'):
		return a.nombre()
	}
	return nil, a.erreur("valeur attendue")
}

func (a *analyseur) litteral(mot string, v *Value) (*Value, error) {
	if !strings.HasPrefix(string(a.src[a.pos:min(len(a.src), a.pos+len(mot))]), mot) {
		return nil, a.erreur("littéral invalide")
	}
	a.pos += len(mot)
	return v, nil
}

func (a *analyseur) objet(prof int) (*Value, error) {
	a.pos++
	v := &Value{Kind: KindObject, Obj: []Membre{}}
	vus := map[string]bool{}
	a.blancs()
	if a.pos < len(a.src) && a.src[a.pos] == '}' {
		a.pos++
		return v, nil
	}
	for {
		a.blancs()
		if a.pos >= len(a.src) || a.src[a.pos] != '"' {
			return nil, a.erreur("nom de membre attendu")
		}
		cle, err := a.chaine()
		if err != nil {
			return nil, err
		}
		if vus[cle] {
			return nil, a.erreur(fmt.Sprintf("nom de membre %q en double", cle))
		}
		vus[cle] = true
		a.blancs()
		if a.pos >= len(a.src) || a.src[a.pos] != ':' {
			return nil, a.erreur("« : » attendu")
		}
		a.pos++
		a.blancs()
		val, err := a.valeur(prof + 1)
		if err != nil {
			return nil, err
		}
		v.Obj = append(v.Obj, Membre{cle, val})
		a.blancs()
		if a.pos >= len(a.src) {
			return nil, a.erreur("fin de texte dans un objet")
		}
		switch a.src[a.pos] {
		case ',':
			a.pos++
		case '}':
			a.pos++
			return v, nil
		default:
			return nil, a.erreur("« , » ou « } » attendu")
		}
	}
}

func (a *analyseur) tableau(prof int) (*Value, error) {
	a.pos++
	v := &Value{Kind: KindArray, Arr: []*Value{}}
	a.blancs()
	if a.pos < len(a.src) && a.src[a.pos] == ']' {
		a.pos++
		return v, nil
	}
	for {
		a.blancs()
		x, err := a.valeur(prof + 1)
		if err != nil {
			return nil, err
		}
		v.Arr = append(v.Arr, x)
		a.blancs()
		if a.pos >= len(a.src) {
			return nil, a.erreur("fin de texte dans un tableau")
		}
		switch a.src[a.pos] {
		case ',':
			a.pos++
		case ']':
			a.pos++
			return v, nil
		default:
			return nil, a.erreur("« , » ou « ] » attendu")
		}
	}
}

// nombre reconnaît la grammaire de la RFC 8259 et garde le texte littéral.
func (a *analyseur) nombre() (*Value, error) {
	debut := a.pos
	chiffres := func() int {
		n := 0
		for a.pos < len(a.src) && a.src[a.pos] >= '0' && a.src[a.pos] <= '9' {
			a.pos++
			n++
		}
		return n
	}
	if a.src[a.pos] == '-' {
		a.pos++
	}
	if a.pos < len(a.src) && a.src[a.pos] == '0' {
		a.pos++
	} else if chiffres() == 0 {
		return nil, a.erreur("chiffre attendu")
	}
	if a.pos < len(a.src) && a.src[a.pos] == '.' {
		a.pos++
		if chiffres() == 0 {
			return nil, a.erreur("chiffre attendu après le point")
		}
	}
	if a.pos < len(a.src) && (a.src[a.pos] == 'e' || a.src[a.pos] == 'E') {
		a.pos++
		if a.pos < len(a.src) && (a.src[a.pos] == '+' || a.src[a.pos] == '-') {
			a.pos++
		}
		if chiffres() == 0 {
			return nil, a.erreur("chiffre attendu dans l'exposant")
		}
	}
	return &Value{Kind: KindNumber, Num: string(a.src[debut:a.pos])}, nil
}

func valeurHex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

func (a *analyseur) quatreHex() (rune, bool) {
	if a.pos+4 > len(a.src) {
		return 0, false
	}
	var r rune
	for i := 0; i < 4; i++ {
		h := valeurHex(a.src[a.pos+i])
		if h < 0 {
			return 0, false
		}
		r = r<<4 | rune(h)
	}
	a.pos += 4
	return r, true
}

// chaine décode une chaîne ; un substitut isolé est refusé (CT-1 §4, règle 3).
func (a *analyseur) chaine() (string, error) {
	a.pos++
	var sb strings.Builder
	for {
		if a.pos >= len(a.src) {
			return "", a.erreur("chaîne non terminée")
		}
		c := a.src[a.pos]
		switch {
		case c == '"':
			a.pos++
			return sb.String(), nil
		case c < 0x20:
			return "", a.erreur("caractère de contrôle non échappé dans une chaîne")
		case c == '\\':
			a.pos++
			if a.pos >= len(a.src) {
				return "", a.erreur("échappement non terminé")
			}
			e := a.src[a.pos]
			a.pos++
			switch e {
			case '"', '\\', '/':
				sb.WriteByte(e)
			case 'b':
				sb.WriteByte('\b')
			case 'f':
				sb.WriteByte('\f')
			case 'n':
				sb.WriteByte('\n')
			case 'r':
				sb.WriteByte('\r')
			case 't':
				sb.WriteByte('\t')
			case 'u':
				r, ok := a.quatreHex()
				if !ok {
					return "", a.erreur("échappement \\u invalide")
				}
				if utf16.IsSurrogate(r) {
					if r >= 0xDC00 {
						return "", a.erreur("substitut bas isolé")
					}
					if a.pos+2 > len(a.src) || a.src[a.pos] != '\\' || a.src[a.pos+1] != 'u' {
						return "", a.erreur("substitut haut isolé")
					}
					a.pos += 2
					r2, ok := a.quatreHex()
					if !ok || r2 < 0xDC00 || r2 > 0xDFFF {
						return "", a.erreur("substitut haut isolé")
					}
					r = utf16.DecodeRune(r, r2)
				}
				sb.WriteRune(r)
			default:
				return "", a.erreur("échappement inconnu")
			}
		default:
			r, n := utf8.DecodeRune(a.src[a.pos:])
			sb.WriteRune(r)
			a.pos += n
		}
	}
}
