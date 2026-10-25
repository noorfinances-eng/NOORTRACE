// Analyseur JSON (RFC 8259) qui conserve l'ordre des membres et le texte
// littéral des nombres.
//
// Copié tel quel du vérificateur indépendant CT-3
// (spec/vecteurs/ct-3/verificateur-independant/json.go, repris de
// l'analyseur strict de CT-1), ce que CT-4 EX-A.5 permet. Les clés en
// double, les octets UTF-8 mal formés et la marque d'ordre d'octets sont
// refusés ; un substitut UTF-16 isolé écrit en échappement est conservé sous
// sa forme WTF-8. Les fonctions EchapperChaine et RationnelDe, définies
// ailleurs dans le module CT-3, sont réécrites ici dans format.go.
//
// encoding/json n'est pas utilisé pour l'analyse : il accepte les clés en
// double et ne distingue pas 1 de 1.0 sans UseNumber.

package main

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Kind est la sorte d'une valeur JSON.
type Kind uint8

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
	switch k {
	case KindNull:
		return "null"
	case KindBool:
		return "booléen"
	case KindNumber:
		return "nombre"
	case KindString:
		return "chaîne"
	case KindArray:
		return "tableau"
	case KindObject:
		return "objet"
	}
	return "?"
}

// Value est une valeur JSON analysée. Pour un nombre, Num est le texte
// littéral du document ; pour un objet, Obj conserve l'ordre du document.
type Value struct {
	Kind Kind
	Bool bool
	Num  string
	Str  string
	Arr  []*Value
	Obj  []Member
}

// Member est un membre d'objet.
type Member struct {
	Key string
	Val *Value
}

// Get rend le membre nommé d'un objet, ou nil.
func (v *Value) Get(key string) *Value {
	if v == nil || v.Kind != KindObject {
		return nil
	}
	for _, m := range v.Obj {
		if m.Key == key {
			return m.Val
		}
	}
	return nil
}

// Has dit si un objet porte le membre nommé.
func (v *Value) Has(key string) bool { return v.Get(key) != nil }

// IsNull dit si la valeur est le littéral null.
func (v *Value) IsNull() bool { return v != nil && v.Kind == KindNull }

// S rend la chaîne d'une valeur chaîne, sinon "".
func (v *Value) S() string {
	if v == nil || v.Kind != KindString {
		return ""
	}
	return v.Str
}

// ErreurJSON est une erreur d'analyse.
type ErreurJSON struct {
	Pos int
	Msg string
}

func (e *ErreurJSON) Error() string {
	return fmt.Sprintf("JSON invalide (octet %d) : %s", e.Pos, e.Msg)
}

type analyseur struct {
	src []byte
	pos int
}

// ParseJSON analyse un document JSON complet.
func ParseJSON(src []byte) (*Value, error) {
	if len(src) >= 3 && src[0] == 0xEF && src[1] == 0xBB && src[2] == 0xBF {
		return nil, &ErreurJSON{Pos: 0, Msg: "marque d'ordre d'octets interdite"}
	}
	if !utf8.Valid(src) {
		return nil, &ErreurJSON{Pos: 0, Msg: "octets UTF-8 mal formés"}
	}
	a := &analyseur{src: src}
	a.blancs()
	v, err := a.valeur(0)
	if err != nil {
		return nil, err
	}
	a.blancs()
	if a.pos != len(a.src) {
		return nil, a.erreur("contenu après la valeur")
	}
	return v, nil
}

func (a *analyseur) erreur(msg string) error { return &ErreurJSON{Pos: a.pos, Msg: msg} }

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

const profondeurMax = 512

func (a *analyseur) valeur(prof int) (*Value, error) {
	if prof > profondeurMax {
		return nil, a.erreur("imbrication trop profonde")
	}
	if a.pos >= len(a.src) {
		return nil, a.erreur("fin inattendue")
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
		return a.litteral("false", &Value{Kind: KindBool, Bool: false})
	case c == 'n':
		return a.litteral("null", &Value{Kind: KindNull})
	case c == '-' || (c >= '0' && c <= '9'):
		return a.nombre()
	}
	return nil, a.erreur("caractère inattendu")
}

func (a *analyseur) litteral(mot string, v *Value) (*Value, error) {
	if strings.HasPrefix(string(a.src[a.pos:]), mot) {
		a.pos += len(mot)
		return v, nil
	}
	return nil, a.erreur("littéral inconnu")
}

func (a *analyseur) objet(prof int) (*Value, error) {
	a.pos++
	v := &Value{Kind: KindObject, Obj: []Member{}}
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
		debut := a.pos
		k, err := a.chaine()
		if err != nil {
			return nil, err
		}
		if vus[k] {
			return nil, &ErreurJSON{Pos: debut, Msg: fmt.Sprintf("clé en double %q", k)}
		}
		vus[k] = true
		a.blancs()
		if a.pos >= len(a.src) || a.src[a.pos] != ':' {
			return nil, a.erreur("':' attendu")
		}
		a.pos++
		a.blancs()
		val, err := a.valeur(prof + 1)
		if err != nil {
			return nil, err
		}
		v.Obj = append(v.Obj, Member{Key: k, Val: val})
		a.blancs()
		if a.pos >= len(a.src) {
			return nil, a.erreur("fin inattendue dans un objet")
		}
		switch a.src[a.pos] {
		case ',':
			a.pos++
		case '}':
			a.pos++
			return v, nil
		default:
			return nil, a.erreur("',' ou '}' attendu")
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
		val, err := a.valeur(prof + 1)
		if err != nil {
			return nil, err
		}
		v.Arr = append(v.Arr, val)
		a.blancs()
		if a.pos >= len(a.src) {
			return nil, a.erreur("fin inattendue dans un tableau")
		}
		switch a.src[a.pos] {
		case ',':
			a.pos++
		case ']':
			a.pos++
			return v, nil
		default:
			return nil, a.erreur("',' ou ']' attendu")
		}
	}
}

func (a *analyseur) nombre() (*Value, error) {
	debut := a.pos
	if a.src[a.pos] == '-' {
		a.pos++
	}
	if a.pos >= len(a.src) {
		return nil, a.erreur("chiffre attendu")
	}
	if a.src[a.pos] == '0' {
		a.pos++
	} else if a.src[a.pos] >= '1' && a.src[a.pos] <= '9' {
		for a.pos < len(a.src) && a.src[a.pos] >= '0' && a.src[a.pos] <= '9' {
			a.pos++
		}
	} else {
		return nil, a.erreur("chiffre attendu")
	}
	if a.pos < len(a.src) && a.src[a.pos] == '.' {
		a.pos++
		n := 0
		for a.pos < len(a.src) && a.src[a.pos] >= '0' && a.src[a.pos] <= '9' {
			a.pos++
			n++
		}
		if n == 0 {
			return nil, a.erreur("chiffre attendu après '.'")
		}
	}
	if a.pos < len(a.src) && (a.src[a.pos] == 'e' || a.src[a.pos] == 'E') {
		a.pos++
		if a.pos < len(a.src) && (a.src[a.pos] == '+' || a.src[a.pos] == '-') {
			a.pos++
		}
		n := 0
		for a.pos < len(a.src) && a.src[a.pos] >= '0' && a.src[a.pos] <= '9' {
			a.pos++
			n++
		}
		if n == 0 {
			return nil, a.erreur("chiffre attendu dans l'exposant")
		}
	}
	return &Value{Kind: KindNumber, Num: string(a.src[debut:a.pos])}, nil
}

func hexVal(c byte) int {
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

func (a *analyseur) quatreHex() (int, bool) {
	if a.pos+4 > len(a.src) {
		return 0, false
	}
	n := 0
	for i := 0; i < 4; i++ {
		h := hexVal(a.src[a.pos+i])
		if h < 0 {
			return 0, false
		}
		n = n<<4 | h
	}
	a.pos += 4
	return n, true
}

// ecrireWTF8 écrit un point de code de substitut isolé (U+D800 à U+DFFF)
// sous sa forme WTF-8 : trois octets, comme un point de code ordinaire de
// cette plage, ce que UTF-8 interdit.
func ecrireWTF8(sb *strings.Builder, u int) {
	sb.WriteByte(byte(0xE0 | (u >> 12)))
	sb.WriteByte(byte(0x80 | ((u >> 6) & 0x3F)))
	sb.WriteByte(byte(0x80 | (u & 0x3F)))
}

// chaine analyse une chaîne JSON (le curseur est sur le guillemet ouvrant).
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
		case c == '\\':
			a.pos++
			if a.pos >= len(a.src) {
				return "", a.erreur("échappement non terminé")
			}
			e := a.src[a.pos]
			a.pos++
			switch e {
			case '"':
				sb.WriteByte('"')
			case '\\':
				sb.WriteByte('\\')
			case '/':
				sb.WriteByte('/')
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
				u, ok := a.quatreHex()
				if !ok {
					return "", a.erreur("échappement \\u mal formé")
				}
				if u >= 0xD800 && u <= 0xDBFF {
					if a.pos+6 <= len(a.src) && a.src[a.pos] == '\\' && a.src[a.pos+1] == 'u' {
						sauv := a.pos
						a.pos += 2
						l, ok := a.quatreHex()
						if ok && l >= 0xDC00 && l <= 0xDFFF {
							sb.WriteRune(rune(0x10000 + (u-0xD800)<<10 + (l - 0xDC00)))
							continue
						}
						a.pos = sauv
					}
					ecrireWTF8(&sb, u)
					continue
				}
				if u >= 0xDC00 && u <= 0xDFFF {
					ecrireWTF8(&sb, u)
					continue
				}
				sb.WriteRune(rune(u))
			default:
				return "", a.erreur("échappement inconnu")
			}
		case c < 0x20:
			return "", a.erreur("caractère de contrôle brut dans une chaîne")
		default:
			r, taille := utf8.DecodeRune(a.src[a.pos:])
			if r == utf8.RuneError && taille == 1 {
				return "", a.erreur("octets UTF-8 mal formés")
			}
			sb.Write(a.src[a.pos : a.pos+taille])
			a.pos += taille
		}
	}
}

// ChaineBienFormee dit si une chaîne analysée est une suite de points de
// code bien formée, sans substitut isolé (CT-1 §4 règle 3, CT-3 EX-4.2
// point 4).
func ChaineBienFormee(s string) bool { return utf8.ValidString(s) }

// PointsDeCode rend le nombre de points de code d'une chaîne analysée ; un
// substitut isolé (forme WTF-8) compte pour un, comme le décompte
// des validateurs JSON Schema.
func PointsDeCode(s string) int {
	n := 0
	for i := 0; i < len(s); {
		r, t := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && t == 1 && i+2 < len(s) && s[i] == 0xED && s[i+1] >= 0xA0 && s[i+1] <= 0xBF {
			i += 3
		} else {
			i += t
		}
		n++
	}
	return n
}

// ------------------------------------------------------------- utilitaires

// EgalJSON compare deux valeurs JSON (ordre des membres d'objet indifférent,
// nombres comparés par leur valeur exacte).
func EgalJSON(a, b *Value) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if a.Kind != b.Kind {
		return false
	}
	switch a.Kind {
	case KindNull:
		return true
	case KindBool:
		return a.Bool == b.Bool
	case KindString:
		return a.Str == b.Str
	case KindNumber:
		ra, ok1 := RationnelDe(a.Num)
		rb, ok2 := RationnelDe(b.Num)
		if !ok1 || !ok2 {
			return a.Num == b.Num
		}
		return ra.Cmp(rb) == 0
	case KindArray:
		if len(a.Arr) != len(b.Arr) {
			return false
		}
		for i := range a.Arr {
			if !EgalJSON(a.Arr[i], b.Arr[i]) {
				return false
			}
		}
		return true
	case KindObject:
		if len(a.Obj) != len(b.Obj) {
			return false
		}
		for _, m := range a.Obj {
			o := b.Get(m.Key)
			if o == nil || !EgalJSON(m.Val, o) {
				return false
			}
		}
		return true
	}
	return false
}

// Copier rend une copie profonde.
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

// Constructeurs.

// Chaine construit une valeur chaîne.
func Chaine(s string) *Value { return &Value{Kind: KindString, Str: s} }

// Nul construit le littéral null.
func Nul() *Value { return &Value{Kind: KindNull} }

// Booleen construit un booléen.
func Booleen(b bool) *Value { return &Value{Kind: KindBool, Bool: b} }

// Entier construit un nombre entier.
func Entier(n int64) *Value { return &Value{Kind: KindNumber, Num: fmt.Sprint(n)} }

// Objet construit un objet à partir de paires clé, valeur.
func Objet(paires ...any) *Value {
	o := &Value{Kind: KindObject, Obj: []Member{}}
	for i := 0; i+1 < len(paires); i += 2 {
		o.Obj = append(o.Obj, Member{Key: paires[i].(string), Val: paires[i+1].(*Value)})
	}
	return o
}

// Tableau construit un tableau.
func Tableau(elts ...*Value) *Value {
	t := &Value{Kind: KindArray, Arr: []*Value{}}
	t.Arr = append(t.Arr, elts...)
	return t
}

// ChaineOuNul construit une chaîne, ou null si p est nil.
func ChaineOuNul(p *string) *Value {
	if p == nil {
		return Nul()
	}
	return Chaine(*p)
}

// TableauChaines construit un tableau de chaînes.
func TableauChaines(ss []string) *Value {
	t := Tableau()
	for _, s := range ss {
		t.Arr = append(t.Arr, Chaine(s))
	}
	return t
}

// Compact sérialise une valeur en JSON compact, membres dans l'ordre
// d'insertion (pour les rapports seulement).
func Compact(v *Value) string {
	var sb strings.Builder
	compact(&sb, v)
	return sb.String()
}

func compact(sb *strings.Builder, v *Value) {
	if v == nil {
		sb.WriteString("<absent>")
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
		sb.WriteString(v.Num)
	case KindString:
		EchapperChaine(sb, v.Str)
	case KindArray:
		sb.WriteByte('[')
		for i, e := range v.Arr {
			if i > 0 {
				sb.WriteByte(',')
			}
			compact(sb, e)
		}
		sb.WriteByte(']')
	case KindObject:
		sb.WriteByte('{')
		for i, m := range v.Obj {
			if i > 0 {
				sb.WriteByte(',')
			}
			EchapperChaine(sb, m.Key)
			sb.WriteByte(':')
			compact(sb, m.Val)
		}
		sb.WriteByte('}')
	}
}
