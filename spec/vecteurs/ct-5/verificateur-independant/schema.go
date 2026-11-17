// Validation d'un document contre un schéma JSON (draft 2020-12), pour la
// règle « schema » d'AN-1 (CT-5 EX-4.9 : « le composant d'ancrage valide le
// document contre son schéma, puis applique les règles que le schéma
// n'exprime pas »). Seuls les mots-clés que le schéma ancrage-v0 emploie sont
// admis (EX-4.8 : « sans référence croisée, compilable en mode strict ») ; un
// autre mot-clé refuse le schéma au chargement plutôt que d'être ignoré.

package main

import (
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// motsCles sont les mots-clés de validation admis ; annotations, ceux qui
// n'ont aucun effet sur la validation.
var (
	motsCles    = []string{"$ref", "type", "const", "enum", "pattern", "minLength", "maxLength", "minimum", "maximum", "minItems", "maxItems", "uniqueItems", "items", "properties", "required", "additionalProperties", "oneOf", "anyOf", "allOf", "not", "if", "then", "else", "$defs"}
	annotations = []string{"$schema", "$id", "$comment", "title", "description", "default", "examples"}
)

// Schema est un schéma JSON chargé, ses motifs compilés.
type Schema struct {
	racine *Value
	motifs map[string]*regexp.Regexp
}

// ChargerSchema lit un schéma et compile ses motifs ; refuse un mot-clé
// hors du sous-ensemble admis et une référence non locale.
func ChargerSchema(octets []byte) (*Schema, error) {
	v, err := ParseJSON(octets)
	if err != nil {
		return nil, err
	}
	s := &Schema{racine: v, motifs: map[string]*regexp.Regexp{}}
	if err := s.preparer(v, "#"); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Schema) preparer(v *Value, chemin string) error {
	if v.Kind == KindBool {
		return nil
	}
	if v.Kind != KindObject {
		return fmt.Errorf("schéma %s : objet ou booléen attendu", chemin)
	}
	for _, m := range v.Obj {
		c := chemin + "/" + m.Key
		switch {
		case dans(m.Key, annotations):
		case !dans(m.Key, motsCles):
			return fmt.Errorf("schéma %s : mot-clé non admis", c)
		case m.Key == "pattern":
			if m.Val.Kind != KindString {
				return fmt.Errorf("schéma %s : chaîne attendue", c)
			}
			re, err := regexp.Compile(motifRE2(m.Val.Str))
			if err != nil {
				return fmt.Errorf("schéma %s : motif %q : %s", c, m.Val.Str, err.Error())
			}
			s.motifs[m.Val.Str] = re
		case m.Key == "$ref":
			if m.Val.Kind != KindString || !strings.HasPrefix(m.Val.Str, "#/$defs/") {
				return fmt.Errorf("schéma %s : référence locale #/$defs/… attendue", c)
			}
		case m.Key == "properties" || m.Key == "$defs":
			if m.Val.Kind != KindObject {
				return fmt.Errorf("schéma %s : objet attendu", c)
			}
			for _, p := range m.Val.Obj {
				if err := s.preparer(p.Val, c+"/"+p.Key); err != nil {
					return err
				}
			}
		case m.Key == "items" || m.Key == "additionalProperties" || m.Key == "not" || m.Key == "if" || m.Key == "then" || m.Key == "else":
			if err := s.preparer(m.Val, c); err != nil {
				return err
			}
		case m.Key == "oneOf" || m.Key == "anyOf" || m.Key == "allOf":
			if m.Val.Kind != KindArray {
				return fmt.Errorf("schéma %s : liste attendue", c)
			}
			for i, x := range m.Val.Arr {
				if err := s.preparer(x, fmt.Sprintf("%s/%d", c, i)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// motifRE2 traduit un motif ECMA-262 (JSON Schema) dans la syntaxe de
// regexp : \uXXXX devient \x{XXXX} ; \s devient la classe des blancs
// d'ECMA-262 (plus large que celle de RE2), dans une classe comme hors d'une
// classe ; une répétition {m,n} au-delà de 1000, que RE2 refuse, devient une
// suite de répétitions d'au plus 1000 de même sens (X{1,4095} :
// X{1,1000}X{0,1000}X{0,1000}X{0,1000}X{0,95}).
func motifRE2(motif string) string {
	const blancs = `\t\n\v\f\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}`
	var sb strings.Builder
	dansClasse := false
	debutAtome := 0
	var groupes []int
	for i := 0; i < len(motif); i++ {
		c := motif[i]
		if c == '\\' && i+1 < len(motif) {
			n := motif[i+1]
			if !dansClasse {
				debutAtome = sb.Len()
			}
			switch {
			case n == 'u' && i+5 < len(motif):
				sb.WriteString(`\x{` + motif[i+2:i+6] + `}`)
				i += 5
			case n == 's':
				if dansClasse {
					sb.WriteString(blancs)
				} else {
					sb.WriteString("[" + blancs + "]")
				}
				i++
			default:
				sb.WriteByte(c)
				sb.WriteByte(n)
				i++
			}
			continue
		}
		if dansClasse {
			if c == ']' {
				dansClasse = false
			}
			sb.WriteByte(c)
			continue
		}
		switch c {
		case '[':
			dansClasse = true
			debutAtome = sb.Len()
		case '(':
			groupes = append(groupes, sb.Len())
		case ')':
			if len(groupes) > 0 {
				debutAtome = groupes[len(groupes)-1]
				groupes = groupes[:len(groupes)-1]
			}
		case '{':
			if j := strings.IndexByte(motif[i:], '}'); j > 0 {
				var m, n int
				if k, err := fmt.Sscanf(motif[i:i+j+1], "{%d,%d}", &m, &n); err == nil && k == 2 && n > 1000 && m <= 1000 {
					atome := sb.String()[debutAtome:]
					fmt.Fprintf(&sb, "{%d,1000}", m)
					for reste := n - 1000; reste > 0; reste -= 1000 {
						fmt.Fprintf(&sb, "%s{0,%d}", atome, min(reste, 1000))
					}
					i += j
					continue
				}
			}
		case '*', '+', '?', '|', '^', '$':
		default:
			debutAtome = sb.Len()
		}
		sb.WriteByte(c)
	}
	return sb.String()
}

// Valider rend les écarts du document au schéma (chemin et raison) ; vide si
// le document est conforme.
func (s *Schema) Valider(doc *Value) []string {
	var ecarts []string
	s.valider(s.racine, doc, "", &ecarts, 0)
	return ecarts
}

func (s *Schema) definition(ref string) *Value {
	return s.racine.Get("$defs").Get(strings.TrimPrefix(ref, "#/$defs/"))
}

func nombreRat(v *Value) (*big.Rat, bool) {
	if v == nil || v.Kind != KindNumber {
		return nil, false
	}
	return new(big.Rat).SetString(v.Num)
}

// typeConforme dit si une valeur est du type JSON Schema donné ; un nombre
// entier est « integer » et « number ».
func typeConforme(v *Value, typ string) bool {
	switch typ {
	case "null":
		return v.Kind == KindNull
	case "boolean":
		return v.Kind == KindBool
	case "string":
		return v.Kind == KindString
	case "array":
		return v.Kind == KindArray
	case "object":
		return v.Kind == KindObject
	case "number":
		return v.Kind == KindNumber
	case "integer":
		r, ok := nombreRat(v)
		return ok && r.IsInt()
	}
	return false
}

// egalJSON est l'égalité de JSON Schema : nombres par valeur, objets sans
// ordre des membres.
func egalJSON(a, b *Value) bool {
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
		x, ok1 := nombreRat(a)
		y, ok2 := nombreRat(b)
		return ok1 && ok2 && x.Cmp(y) == 0
	case KindArray:
		if len(a.Arr) != len(b.Arr) {
			return false
		}
		for i := range a.Arr {
			if !egalJSON(a.Arr[i], b.Arr[i]) {
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
			if o == nil || !egalJSON(m.Val, o) {
				return false
			}
		}
		return true
	}
	return false
}

func (s *Schema) valider(sch, v *Value, chemin string, ecarts *[]string, prof int) {
	ecart := func(format string, args ...any) {
		c := chemin
		if c == "" {
			c = "/"
		}
		*ecarts = append(*ecarts, c+" : "+fmt.Sprintf(format, args...))
	}
	if prof > 64 {
		ecart("imbrication trop profonde")
		return
	}
	if sch.Kind == KindBool {
		if !sch.Bool {
			ecart("aucune valeur admise")
		}
		return
	}
	if r := sch.Get("$ref"); r != nil {
		d := s.definition(r.Str)
		if d == nil {
			ecart("référence %s introuvable", r.Str)
			return
		}
		s.valider(d, v, chemin, ecarts, prof+1)
	}
	if t := sch.Get("type"); t != nil {
		admis := false
		if t.Kind == KindString {
			admis = typeConforme(v, t.Str)
		} else if t.Kind == KindArray {
			for _, x := range t.Arr {
				admis = admis || typeConforme(v, x.Str)
			}
		}
		if !admis {
			ecart("type %s attendu", Rendu(t))
			return
		}
	}
	if c := sch.Get("const"); c != nil && !egalJSON(c, v) {
		ecart("valeur %s attendue", Rendu(c))
	}
	if e := sch.Get("enum"); e != nil {
		trouve := false
		for _, x := range e.Arr {
			trouve = trouve || egalJSON(x, v)
		}
		if !trouve {
			ecart("valeur hors de %s", Rendu(e))
		}
	}
	if v.Kind == KindString {
		n := int64(utf8.RuneCountInString(v.Str))
		if m, ok := entierDe(sch, "minLength"); ok && n < m {
			ecart("au moins %d caractères attendus", m)
		}
		if m, ok := entierDe(sch, "maxLength"); ok && n > m {
			ecart("au plus %d caractères attendus", m)
		}
		if p, ok := chaineDe(sch, "pattern"); ok && !s.motifs[p].MatchString(v.Str) {
			ecart("hors du motif %s", p)
		}
	}
	if x, ok := nombreRat(v); ok {
		if m, ok := nombreRat(sch.Get("minimum")); ok && x.Cmp(m) < 0 {
			ecart("au moins %s attendu", m.RatString())
		}
		if m, ok := nombreRat(sch.Get("maximum")); ok && x.Cmp(m) > 0 {
			ecart("au plus %s attendu", m.RatString())
		}
	}
	if v.Kind == KindArray {
		if m, ok := entierDe(sch, "minItems"); ok && int64(len(v.Arr)) < m {
			ecart("au moins %d éléments attendus", m)
		}
		if m, ok := entierDe(sch, "maxItems"); ok && int64(len(v.Arr)) > m {
			ecart("au plus %d éléments attendus", m)
		}
		if u, ok := booleenDe(sch, "uniqueItems"); ok && u {
			for i := range v.Arr {
				for j := i + 1; j < len(v.Arr); j++ {
					if egalJSON(v.Arr[i], v.Arr[j]) {
						ecart("éléments %d et %d égaux", i, j)
					}
				}
			}
		}
		if it := sch.Get("items"); it != nil {
			for i, x := range v.Arr {
				s.valider(it, x, fmt.Sprintf("%s/%d", chemin, i), ecarts, prof+1)
			}
		}
	}
	if v.Kind == KindObject {
		if r := sch.Get("required"); r != nil {
			for _, k := range r.Arr {
				if !v.Has(k.Str) {
					ecart("membre %s absent", k.Str)
				}
			}
		}
		props := sch.Get("properties")
		add := sch.Get("additionalProperties")
		cles := v.Keys()
		sort.Strings(cles)
		for _, k := range cles {
			if p := props.Get(k); p != nil {
				s.valider(p, v.Get(k), chemin+"/"+k, ecarts, prof+1)
			} else if add != nil {
				s.valider(add, v.Get(k), chemin+"/"+k, ecarts, prof+1)
			}
		}
	}
	sous := func(x *Value) bool {
		var e []string
		s.valider(x, v, chemin, &e, prof+1)
		return len(e) == 0
	}
	if l := sch.Get("allOf"); l != nil {
		for _, x := range l.Arr {
			s.valider(x, v, chemin, ecarts, prof+1)
		}
	}
	if l := sch.Get("anyOf"); l != nil {
		n := 0
		for _, x := range l.Arr {
			if sous(x) {
				n++
			}
		}
		if n == 0 {
			ecart("aucune branche d'anyOf admise")
		}
	}
	if l := sch.Get("oneOf"); l != nil {
		n := 0
		for _, x := range l.Arr {
			if sous(x) {
				n++
			}
		}
		if n != 1 {
			ecart("%d branche(s) de oneOf admise(s), une attendue", n)
		}
	}
	if x := sch.Get("not"); x != nil && sous(x) {
		ecart("valeur exclue par not")
	}
	if x := sch.Get("if"); x != nil {
		if sous(x) {
			if th := sch.Get("then"); th != nil {
				s.valider(th, v, chemin, ecarts, prof+1)
			}
		} else if el := sch.Get("else"); el != nil {
			s.valider(el, v, chemin, ecarts, prof+1)
		}
	}
}
