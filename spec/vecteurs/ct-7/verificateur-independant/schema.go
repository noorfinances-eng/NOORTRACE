// Validateur JSON Schema (draft 2020-12), réduit aux mots-clés qu'emploient
// les schémas que CT-7 nomme : ceremonie-cles-v0 (CR-1, EX-5.6),
// attestation-perimetre-v0 (AT-1, EX-7.2), modele-menace-v0 (RV-1, §3.8) et
// matrice-conformite-v0 (MX-1, §8.3). Tout mot-clé inconnu fait échouer la
// compilation : ce validateur ne passe jamais un mot-clé sous silence.
//
// Les motifs (pattern) sont des expressions ECMA-262 ; ils sont traduits pour
// le paquet regexp (RE2) : \uXXXX devient \x{XXXX}, \s prend la définition
// d'ECMAScript (espaces Unicode compris), et une répétition {m,n} de plus de
// 1000, que RE2 refuse, est découpée en répétitions qu'il accepte.

package main

import (
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Schema est un schéma chargé, racine de ses références locales.
type Schema struct {
	Nom    string
	Racine *Value
	motifs map[string]*regexp.Regexp
}

// motsCles sont les mots-clés admis ; les annotations sont ignorées.
var motsCles = map[string]bool{
	"$schema": true, "$id": true, "$defs": true, "$ref": true, "$comment": true,
	"title": true, "description": true, "examples": true,
	"type": true, "enum": true, "const": true,
	"properties": true, "required": true, "additionalProperties": true,
	"items": true, "prefixItems": true, "minItems": true, "maxItems": true,
	"uniqueItems": true, "contains": true,
	"minLength": true, "maxLength": true, "pattern": true,
	"minimum": true, "maximum": true,
	"oneOf": true, "anyOf": true, "allOf": true, "not": true,
	"if": true, "then": true, "else": true,
}

// ChargerSchema analyse un schéma et contrôle ses mots-clés et ses motifs.
func ChargerSchema(nom string, octets []byte) (*Schema, error) {
	v, err := AnalyserJSON(octets)
	if err != nil {
		return nil, fmt.Errorf("%s : %v", nom, err)
	}
	s := &Schema{Nom: nom, Racine: v, motifs: map[string]*regexp.Regexp{}}
	if err := s.controler(v, "#"); err != nil {
		return nil, fmt.Errorf("%s : %v", nom, err)
	}
	return s, nil
}

// controler parcourt le schéma : mots-clés connus, motifs compilables,
// références résolubles.
func (s *Schema) controler(v *Value, ou string) error {
	if v.Kind == KindBool {
		return nil
	}
	if v.Kind != KindObject {
		return fmt.Errorf("%s : schéma objet ou booléen attendu", ou)
	}
	for _, m := range v.Obj {
		if !motsCles[m.Cle] {
			return fmt.Errorf("%s : mot-clé %q non pris en charge", ou, m.Cle)
		}
		switch m.Cle {
		case "properties", "$defs":
			for _, p := range m.Val.Obj {
				if err := s.controler(p.Val, ou+"/"+m.Cle+"/"+p.Cle); err != nil {
					return err
				}
			}
		case "items", "contains", "not", "if", "then", "else", "additionalProperties":
			if err := s.controler(m.Val, ou+"/"+m.Cle); err != nil {
				return err
			}
		case "prefixItems", "oneOf", "anyOf", "allOf":
			for i, x := range m.Val.Arr {
				if err := s.controler(x, fmt.Sprintf("%s/%s/%d", ou, m.Cle, i)); err != nil {
					return err
				}
			}
		case "pattern":
			if _, err := s.motif(m.Val.Str); err != nil {
				return fmt.Errorf("%s : motif %q : %v", ou, m.Val.Str, err)
			}
		case "$ref":
			if _, err := s.resoudre(m.Val.Str); err != nil {
				return fmt.Errorf("%s : %v", ou, err)
			}
		}
	}
	return nil
}

// resoudre suit une référence locale (« # » ou « #/$defs/… »).
func (s *Schema) resoudre(ref string) (*Value, error) {
	if !strings.HasPrefix(ref, "#") {
		return nil, fmt.Errorf("référence externe %q non prise en charge", ref)
	}
	v := s.Racine
	if ref == "#" {
		return v, nil
	}
	for _, seg := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		seg = strings.ReplaceAll(strings.ReplaceAll(seg, "~1", "/"), "~0", "~")
		v = v.Get(seg)
		if v == nil {
			return nil, fmt.Errorf("référence %q introuvable", ref)
		}
	}
	return v, nil
}

// Sous rend le sous-schéma désigné par une référence locale, comme schéma à
// part entière (mêmes définitions).
func (s *Schema) Sous(ref string) (*Value, error) { return s.resoudre(ref) }

// Valider rend la liste des manquements d'une instance au schéma racine.
func (s *Schema) Valider(inst *Value) []string {
	return s.ValiderContre(s.Racine, inst)
}

// ValiderContre valide une instance contre un sous-schéma.
func (s *Schema) ValiderContre(sch, inst *Value) []string {
	var out []string
	s.valider(sch, inst, "$", &out)
	return out
}

func (s *Schema) valide(sch, inst *Value) bool {
	var out []string
	s.valider(sch, inst, "$", &out)
	return len(out) == 0
}

func typeJSON(v *Value) string {
	switch v.Kind {
	case KindNull:
		return "null"
	case KindBool:
		return "boolean"
	case KindNumber:
		if r, ok := new(big.Rat).SetString(v.Num); ok && r.IsInt() {
			return "integer"
		}
		return "number"
	case KindString:
		return "string"
	case KindArray:
		return "array"
	}
	return "object"
}

func typeAdmis(t string, v *Value) bool {
	r := typeJSON(v)
	return t == r || (t == "number" && r == "integer")
}

func nombreRat(v *Value) *big.Rat {
	r, ok := new(big.Rat).SetString(v.Num)
	if !ok {
		return new(big.Rat)
	}
	return r
}

func (s *Schema) valider(sch, inst *Value, ch string, out *[]string) {
	ajout := func(format string, args ...any) {
		*out = append(*out, ch+" : "+fmt.Sprintf(format, args...))
	}
	if sch.Kind == KindBool {
		if !sch.Bool {
			ajout("aucune valeur admise")
		}
		return
	}
	if r := sch.Get("$ref"); r != nil {
		cible, err := s.resoudre(r.Str)
		if err != nil {
			ajout("%v", err)
		} else {
			s.valider(cible, inst, ch, out)
		}
	}
	if t := sch.Get("type"); t != nil {
		ok := false
		if t.Kind == KindString {
			ok = typeAdmis(t.Str, inst)
		} else {
			for _, x := range t.Arr {
				ok = ok || typeAdmis(x.Str, inst)
			}
		}
		if !ok {
			ajout("type %s non admis", typeJSON(inst))
			return
		}
	}
	if c := sch.Get("const"); c != nil && !Egales(c, inst) {
		ajout("valeur différente de la constante")
	}
	if e := sch.Get("enum"); e != nil {
		ok := false
		for _, x := range e.Arr {
			ok = ok || Egales(x, inst)
		}
		if !ok {
			ajout("valeur hors de l'énumération")
		}
	}
	switch inst.Kind {
	case KindString:
		n := utf8.RuneCountInString(inst.Str)
		if m := sch.Get("minLength"); m != nil {
			if k, _ := m.Entier(); int64(n) < k {
				ajout("chaîne de %d caractères, au moins %d", n, k)
			}
		}
		if m := sch.Get("maxLength"); m != nil {
			if k, _ := m.Entier(); int64(n) > k {
				ajout("chaîne de %d caractères, au plus %d", n, k)
			}
		}
		if p := sch.Get("pattern"); p != nil {
			re, err := s.motif(p.Str)
			if err != nil || !re.MatchString(inst.Str) {
				ajout("chaîne non conforme au motif %s", p.Str)
			}
		}
	case KindNumber:
		if m := sch.Get("minimum"); m != nil && nombreRat(inst).Cmp(nombreRat(m)) < 0 {
			ajout("nombre %s inférieur au minimum %s", inst.Num, m.Num)
		}
		if m := sch.Get("maximum"); m != nil && nombreRat(inst).Cmp(nombreRat(m)) > 0 {
			ajout("nombre %s supérieur au maximum %s", inst.Num, m.Num)
		}
	case KindArray:
		n := len(inst.Arr)
		if m := sch.Get("minItems"); m != nil {
			if k, _ := m.Entier(); int64(n) < k {
				ajout("%d éléments, au moins %d", n, k)
			}
		}
		if m := sch.Get("maxItems"); m != nil {
			if k, _ := m.Entier(); int64(n) > k {
				ajout("%d éléments, au plus %d", n, k)
			}
		}
		if u := sch.Get("uniqueItems"); u != nil && u.Bool {
			for i := 0; i < n; i++ {
				for j := i + 1; j < n; j++ {
					if Egales(inst.Arr[i], inst.Arr[j]) {
						ajout("éléments %d et %d égaux", i, j)
					}
				}
			}
		}
		prefixe := 0
		if p := sch.Get("prefixItems"); p != nil {
			prefixe = len(p.Arr)
			for i := 0; i < n && i < prefixe; i++ {
				s.valider(p.Arr[i], inst.Arr[i], fmt.Sprintf("%s[%d]", ch, i), out)
			}
		}
		if it := sch.Get("items"); it != nil {
			for i := prefixe; i < n; i++ {
				s.valider(it, inst.Arr[i], fmt.Sprintf("%s[%d]", ch, i), out)
			}
		}
		if c := sch.Get("contains"); c != nil {
			ok := false
			for _, x := range inst.Arr {
				ok = ok || s.valide(c, x)
			}
			if !ok {
				ajout("aucun élément ne satisfait contains")
			}
		}
	case KindObject:
		if r := sch.Get("required"); r != nil {
			for _, x := range r.Arr {
				if inst.Get(x.Str) == nil {
					ajout("membre %q manquant", x.Str)
				}
			}
		}
		props := sch.Get("properties")
		ap := sch.Get("additionalProperties")
		for _, m := range inst.Obj {
			if p := props.Get(m.Cle); p != nil {
				s.valider(p, m.Val, ch+"."+m.Cle, out)
			} else if ap != nil {
				if ap.Kind == KindBool && !ap.Bool {
					ajout("membre %q non admis", m.Cle)
				} else if ap.Kind == KindObject {
					s.valider(ap, m.Val, ch+"."+m.Cle, out)
				}
			}
		}
	}
	if a := sch.Get("allOf"); a != nil {
		for _, x := range a.Arr {
			s.valider(x, inst, ch, out)
		}
	}
	if a := sch.Get("anyOf"); a != nil {
		ok := false
		for _, x := range a.Arr {
			ok = ok || s.valide(x, inst)
		}
		if !ok {
			ajout("aucune branche de anyOf ne convient")
		}
	}
	if o := sch.Get("oneOf"); o != nil {
		k := 0
		for _, x := range o.Arr {
			if s.valide(x, inst) {
				k++
			}
		}
		if k != 1 {
			ajout("%d branches de oneOf conviennent, une seule attendue", k)
		}
	}
	if n := sch.Get("not"); n != nil && s.valide(n, inst) {
		ajout("valeur admise par not")
	}
	if si := sch.Get("if"); si != nil {
		if s.valide(si, inst) {
			if t := sch.Get("then"); t != nil {
				s.valider(t, inst, ch, out)
			}
		} else if e := sch.Get("else"); e != nil {
			s.valider(e, inst, ch, out)
		}
	}
}

// motif rend l'expression compilée d'un motif ECMA-262 (mise en cache).
func (s *Schema) motif(p string) (*regexp.Regexp, error) {
	if re, ok := s.motifs[p]; ok {
		return re, nil
	}
	re, err := CompilerMotif(p)
	if err != nil {
		return nil, err
	}
	s.motifs[p] = re
	return re, nil
}

// blancsECMAScript est le contenu de la classe \s d'ECMAScript
// (WhiteSpace et LineTerminator d'ECMA-262).
const blancsECMAScript = `\t\n\x{0B}\f\r \x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}`

var reRepetition = regexp.MustCompile(`\{([0-9]+),([0-9]+)\}`)

// CompilerMotif traduit un motif ECMA-262 (sous-ensemble des schémas) en
// expression RE2 et la compile. Les motifs ne sont pas ancrés implicitement
// (JSON Schema) : leurs propres ^ et $ les ancrent.
func CompilerMotif(p string) (*regexp.Regexp, error) {
	var sb strings.Builder
	dansClasse := false
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c == '\\' && i+1 < len(p):
			n := p[i+1]
			switch {
			case n == 'u' && i+5 < len(p):
				fmt.Fprintf(&sb, `\x{%s}`, p[i+2:i+6])
				i += 5
			case n == 's':
				if dansClasse {
					sb.WriteString(blancsECMAScript)
				} else {
					sb.WriteString("[" + blancsECMAScript + "]")
				}
				i++
			case n == 'd':
				sb.WriteString(`[0-9]`)
				if dansClasse {
					return nil, fmt.Errorf("\\d dans une classe non pris en charge")
				}
				i++
			case n == 'S' || n == 'D' || n == 'w' || n == 'W' || n == 'b' || n == 'B':
				return nil, fmt.Errorf("échappement \\%c non pris en charge", n)
			default:
				sb.WriteByte(c)
				sb.WriteByte(n)
				i++
			}
		case c == '[' && !dansClasse:
			dansClasse = true
			sb.WriteByte(c)
		case c == ']' && dansClasse:
			dansClasse = false
			sb.WriteByte(c)
		case c == '.' && !dansClasse:
			// ECMAScript : tout sauf les terminateurs de ligne.
			sb.WriteString(`[^\n\r\x{2028}\x{2029}]`)
		default:
			sb.WriteByte(c)
		}
	}
	t := decouperRepetitions(sb.String())
	return regexp.Compile(t)
}

// decouperRepetitions remplace X{m,n} (n > 1000) par X{m}(?:X{0,100})…, qui
// admet les mêmes nombres de répétitions (des tranches de 100, parce que RE2
// borne aussi le produit des répétitions imbriquées à 1000). X est l'atome qui précède : un
// groupe entre parenthèses, une classe entre crochets ou un caractère.
func decouperRepetitions(t string) string {
	for {
		loc := reRepetition.FindStringSubmatchIndex(t)
		trouve := false
		for loc != nil {
			m, _ := strconv.Atoi(t[loc[2]:loc[3]])
			n, _ := strconv.Atoi(t[loc[4]:loc[5]])
			if n > 1000 {
				debut := debutAtome(t, loc[0])
				if debut < 0 {
					return t
				}
				atome := t[debut:loc[0]]
				var sb strings.Builder
				sb.WriteString("(?:" + atome + fmt.Sprintf("){%d}", m))
				for reste := n - m; reste > 0; reste -= 100 {
					sb.WriteString("(?:" + atome + fmt.Sprintf("){0,%d}", min(reste, 100)))
				}
				t = t[:debut] + sb.String() + t[loc[1]:]
				trouve = true
				break
			}
			suivant := reRepetition.FindStringSubmatchIndex(t[loc[1]:])
			if suivant == nil {
				loc = nil
				break
			}
			for k := range suivant {
				suivant[k] += loc[1]
			}
			loc = suivant
		}
		if !trouve {
			return t
		}
	}
}

// debutAtome rend l'indice du début de l'atome qui finit en fin.
func debutAtome(t string, fin int) int {
	if fin == 0 {
		return -1
	}
	switch t[fin-1] {
	case ')':
		prof := 0
		for i := fin - 1; i >= 0; i-- {
			switch t[i] {
			case ')':
				prof++
			case '(':
				prof--
				if prof == 0 {
					return i
				}
			}
		}
		return -1
	case ']':
		for i := fin - 2; i >= 0; i-- {
			if t[i] == '[' && (i == 0 || t[i-1] != '\\') {
				return i
			}
		}
		return -1
	case '}':
		// atome suivi d'une répétition déjà écrite : X{a}{m,n} n'apparaît
		// pas dans les schémas ; on refuse.
		return -1
	}
	_, n := utf8.DecodeLastRuneInString(t[:fin])
	return fin - n
}
