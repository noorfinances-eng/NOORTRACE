// Fichier copié du vérificateur indépendant de CT-1
// (spec/vecteurs/ct-1/verificateur-independant/json.go), comme CT-5 EX-A.4 l'admet ;
// aucune modification.
//
// Analyseur JSON strict (RFC 8259) qui conserve l'ordre des membres et le
// texte littéral des nombres, et qui refuse ce que la forme canonique JCS v0
// (CT-1 §4) déclare invalide : clé en double, substitut UTF-16 isolé, octets
// UTF-8 mal formés, marque d'ordre d'octets.
//
// Révision 0.5 de CT-1 (§3, §4 règle 7), dans l'ordre de CT-6 EX-4.16 :
//  1. codage : des octets qui ne sont pas de l'UTF-8 bien formé, ou qui
//     commencent par la marque d'ordre d'octets EF BB BF, ne sont pas un texte
//     JSON (erreur non canonique : le contrôle qui porte la partie échoue) ;
//     seule exception, un substitut écrit en octets (ED A0 80 à ED BF BF),
//     défaut de forme canonique (E-2), comme l'échappement \ud800 ;
//  2. syntaxe de la RFC 8259 ;
//  3. profondeur : objets et tableaux imbriqués, la racine comprise ([[1]]
//     vaut 2), au plus ProfondeurV0 = 128 pour un document du format v0
//     (ParseJSONV0) ; la lecture s'arrête au-delà, sans récursion dont la
//     hauteur dépende de l'entrée ;
//  4. forme canonique : un défaut (clé en double, substitut isolé) n'arrête
//     pas l'analyse, pour qu'une erreur de syntaxe ou de profondeur plus loin
//     l'emporte ; il est rendu à la fin. Les nombres non entiers ou hors de
//     l'intervalle sûr relèvent de Canonique (jcs.go).
//
// encoding/json n'est pas utilisé pour l'analyse : il accepte les clés en
// double (la dernière gagne), remplace les substituts isolés et les octets
// invalides par U+FFFD, et ne distingue pas 1 de 1.0 sans UseNumber.

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
// littéral tel qu'il figure dans le document ; pour un objet, Obj conserve
// l'ordre du document.
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

// Get rend le membre nommé d'un objet, ou nil s'il est absent ou si la valeur
// n'est pas un objet.
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

// Keys rend les noms des membres d'un objet, dans l'ordre du document.
func (v *Value) Keys() []string {
	if v == nil || v.Kind != KindObject {
		return nil
	}
	out := make([]string, 0, len(v.Obj))
	for _, m := range v.Obj {
		out = append(out, m.Key)
	}
	return out
}

// IsNull dit si la valeur est le littéral null.
func (v *Value) IsNull() bool { return v != nil && v.Kind == KindNull }

// ErreurJSON est une erreur d'analyse. Canonique est vrai quand l'erreur est
// une violation de la forme canonique v0 (contrôle E-2) et non une erreur de
// syntaxe JSON.
type ErreurJSON struct {
	Pos       int
	Msg       string
	Canonique bool
}

func (e *ErreurJSON) Error() string {
	if e.Canonique {
		return fmt.Sprintf("forme canonique impossible (octet %d) : %s", e.Pos, e.Msg)
	}
	return fmt.Sprintf("JSON invalide (octet %d) : %s", e.Pos, e.Msg)
}

type analyseur struct {
	src []byte
	pos int
	// max est la profondeur admise (objets et tableaux imbriqués, la racine
	// comprise).
	max int
	// canon est le premier défaut de forme canonique rencontré (clé en
	// double, substitut isolé), rendu une fois l'analyse finie.
	canon *ErreurJSON
}

// ProfondeurV0 est la profondeur d'au plus 128 d'un texte JSON du format v0
// (CT-1 §4, règle 7, révision 0.5 ; CT-6 EX-4.13).
const ProfondeurV0 = 128

// profondeurGenerique borne les autres documents (vecteurs, cas de tests) :
// une borne fixe, que l'entrée ne choisit pas.
const profondeurGenerique = 512

// ParseJSON analyse un document JSON complet (profondeur bornée à 512).
func ParseJSON(src []byte) (*Value, error) { return ParseJSONProfondeur(src, profondeurGenerique) }

// ParseJSONV0 analyse un document du format v0 (événement, manifeste,
// signature de manifeste, point de contrôle, partie JSON d'un dossier,
// cles.json) : profondeur d'au plus 128 (CT-1 §4, règle 7).
func ParseJSONV0(src []byte) (*Value, error) { return ParseJSONProfondeur(src, ProfondeurV0) }

// ParseJSONProfondeur analyse un document JSON complet dont la profondeur
// (objets et tableaux imbriqués, la racine comprise) est au plus max.
func ParseJSONProfondeur(src []byte, max int) (*Value, error) {
	if len(src) >= 3 && src[0] == 0xEF && src[1] == 0xBB && src[2] == 0xBF {
		return nil, &ErreurJSON{Pos: 0, Msg: "marque d'ordre d'octets : pas un texte JSON (CT-1 §3)"}
	}
	if pos, ok := codageAdmis(src); !ok {
		return nil, &ErreurJSON{Pos: pos, Msg: "octets UTF-8 mal formés : pas un texte JSON (CT-1 §3)"}
	}
	a := &analyseur{src: src, max: max}
	a.blancs()
	v, err := a.valeur(0)
	if err != nil {
		return nil, err
	}
	a.blancs()
	if a.pos != len(a.src) {
		return nil, a.erreur("contenu après la valeur")
	}
	if a.canon != nil {
		return nil, a.canon
	}
	return v, nil
}

// estSubstitutEnOctets reconnaît ED A0 80 à ED BF BF : un point de code de
// U+D800 à U+DFFF écrit en octets (forme dite CESU-8), que Go tient pour de
// l'UTF-8 mal formé et que CT-1 §3 (révision 0.5) range parmi les substituts
// isolés (E-2).
func estSubstitutEnOctets(b []byte) bool {
	return len(b) >= 3 && b[0] == 0xED && b[1] >= 0xA0 && b[1] <= 0xBF && b[2] >= 0x80 && b[2] <= 0xBF
}

// codageAdmis dit si les octets sont de l'UTF-8 bien formé aux substituts
// écrits en octets près ; sinon, rend la position du premier octet fautif.
func codageAdmis(src []byte) (int, bool) {
	for i := 0; i < len(src); {
		if src[i] < utf8.RuneSelf {
			i++
			continue
		}
		r, n := utf8.DecodeRune(src[i:])
		if r == utf8.RuneError && n == 1 {
			if estSubstitutEnOctets(src[i:]) {
				i += 3
				continue
			}
			return i, false
		}
		i += n
	}
	return 0, true
}

// defautCanonique consigne le premier défaut de forme canonique.
func (a *analyseur) defautCanonique(pos int, msg string) {
	if a.canon == nil {
		a.canon = &ErreurJSON{Pos: pos, Msg: msg, Canonique: true}
	}
}

// Profondeur rend la profondeur d'une valeur analysée (CT-1 §4, règle 7) :
// 0 pour un scalaire, 1 pour un objet ou un tableau vide, 1 + la plus grande
// profondeur de ses valeurs sinon. Parcours itératif, sans récursion.
func Profondeur(v *Value) int {
	type cadre struct {
		v *Value
		p int
	}
	max := 0
	pile := []cadre{{v, 0}}
	for len(pile) > 0 {
		c := pile[len(pile)-1]
		pile = pile[:len(pile)-1]
		if c.v == nil || (c.v.Kind != KindObject && c.v.Kind != KindArray) {
			continue
		}
		p := c.p + 1
		if p > max {
			max = p
		}
		for _, x := range c.v.Arr {
			pile = append(pile, cadre{x, p})
		}
		for _, m := range c.v.Obj {
			pile = append(pile, cadre{m.Val, p})
		}
	}
	return max
}

func (a *analyseur) erreur(msg string) error {
	return &ErreurJSON{Pos: a.pos, Msg: msg}
}

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

// valeur analyse une valeur ; prof est le nombre de conteneurs qui
// l'entourent.
func (a *analyseur) valeur(prof int) (*Value, error) {
	if a.pos >= len(a.src) {
		return nil, a.erreur("fin inattendue")
	}
	switch c := a.src[a.pos]; {
	case c == '{' || c == '[':
		// Un conteneur entouré de prof conteneurs est de niveau prof + 1.
		if prof+1 > a.max {
			return nil, a.erreur(fmt.Sprintf("profondeur au-delà de %d (objets et tableaux imbriqués, la racine comprise)", a.max))
		}
		if c == '{' {
			return a.objet(prof)
		}
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
	a.pos++ // {
	v := &Value{Kind: KindObject}
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
			a.defautCanonique(debut, fmt.Sprintf("clé en double %q", k))
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
	a.pos++ // [
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

// chaine analyse une chaîne JSON (le curseur est sur le guillemet ouvrant) et
// rend son contenu décodé. Un substitut isolé est une erreur canonique (E-2).
func (a *analyseur) chaine() (string, error) {
	a.pos++ // "
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
				debut := a.pos - 2
				u, ok := a.quatreHex()
				if !ok {
					return "", a.erreur("échappement \\u mal formé")
				}
				if u >= 0xD800 && u <= 0xDBFF {
					// substitut haut : un substitut bas doit suivre
					if a.pos+6 <= len(a.src) && a.src[a.pos] == '\\' && a.src[a.pos+1] == 'u' {
						sauv := a.pos
						a.pos += 2
						l, ok := a.quatreHex()
						if ok && l >= 0xDC00 && l <= 0xDFFF {
							r := rune(0x10000 + (u-0xD800)<<10 + (l - 0xDC00))
							sb.WriteRune(r)
							continue
						}
						a.pos = sauv
					}
					a.defautCanonique(debut, "substitut UTF-16 isolé")
					sb.WriteRune(utf8.RuneError)
					continue
				}
				if u >= 0xDC00 && u <= 0xDFFF {
					a.defautCanonique(debut, "substitut UTF-16 isolé")
					sb.WriteRune(utf8.RuneError)
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
				if !estSubstitutEnOctets(a.src[a.pos:]) {
					return "", &ErreurJSON{Pos: a.pos, Msg: "octets UTF-8 mal formés : pas un texte JSON (CT-1 §3)"}
				}
				// CT-1 §3 et §4 règle 3 (révision 0.5) : substitut écrit en
				// octets, apparié ou non, défaut de forme canonique.
				a.defautCanonique(a.pos, "substitut UTF-16 écrit en octets (ED A0 80 à ED BF BF)")
				sb.WriteRune(utf8.RuneError)
				a.pos += 3
				continue
			}
			sb.Write(a.src[a.pos : a.pos+taille])
			a.pos += taille
		}
	}
}
