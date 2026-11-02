package main

// Validateur JSON Schema (draft 2020-12) restreint aux mots-clés que
// spec/schemas/plan-de-tests-v0.schema.json emploie : type, const, enum,
// required, properties, additionalProperties, minProperties, items,
// minItems, maxItems, uniqueItems, pattern, minLength, maxLength, minimum,
// maximum, anyOf, allOf, if/then/else, not, $ref local (#/$defs/…) et les
// schémas booléens. Il rend toutes les violations (mot-clé et chemin), ce
// qui permet de confronter le verdict attendu d'un cas (valide ou invalide,
// mot-clé fautif) sans recourir à un validateur tiers.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Schema est un schéma chargé avec ses définitions.
type Schema struct {
	Racine any
	Defs   map[string]any
	motifs map[string]*regexp.Regexp
}

// Violation est un mot-clé violé à un chemin du document.
type Violation struct {
	Chemin string `json:"path"`
	MotCle string `json:"keyword"`
	Detail string `json:"detail"`
}

// ChargerSchema lit un schéma JSON.
func ChargerSchema(chemin string) (*Schema, error) {
	octets, err := os.ReadFile(chemin)
	if err != nil {
		return nil, err
	}
	doc, err := DecoderJSON(octets)
	if err != nil {
		return nil, fmt.Errorf("%s : %v", chemin, err)
	}
	racine, ok := doc.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s : objet attendu", chemin)
	}
	s := &Schema{Racine: racine, Defs: map[string]any{}, motifs: map[string]*regexp.Regexp{}}
	if d, ok := racine["$defs"].(map[string]any); ok {
		s.Defs = d
	}
	return s, nil
}

// DecoderJSON décode un document en conservant les nombres tels quels.
func DecoderJSON(octets []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(octets))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("données après le document")
	}
	return doc, nil
}

// LireDocument lit et décode un fichier JSON.
func LireDocument(chemin string) (any, error) {
	octets, err := os.ReadFile(chemin)
	if err != nil {
		return nil, err
	}
	doc, err := DecoderJSON(octets)
	if err != nil {
		return nil, fmt.Errorf("%s : %v", chemin, err)
	}
	return doc, nil
}

// Definition rend le sous-schéma d'une définition (« rapport_mesure ») ou la
// racine quand def est vide ou « racine ».
func (s *Schema) Definition(def string) (any, error) {
	if def == "" || def == "racine" {
		return s.Racine, nil
	}
	d, ok := s.Defs[def]
	if !ok {
		return nil, fmt.Errorf("définition %q absente du schéma", def)
	}
	return d, nil
}

// Valider valide un document contre une définition et rend ses violations.
func (s *Schema) Valider(def string, doc any) ([]Violation, error) {
	sch, err := s.Definition(def)
	if err != nil {
		return nil, err
	}
	var v []Violation
	s.valider(sch, doc, "", &v)
	return v, nil
}

// MotsCles rend l'ensemble trié des mots-clés violés.
func MotsCles(v []Violation) []string {
	vu := map[string]bool{}
	for _, x := range v {
		vu[x.MotCle] = true
	}
	var out []string
	for k := range vu {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func typeJSON(doc any) string {
	switch d := doc.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case json.Number:
		if estEntier(d) {
			return "integer"
		}
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return "inconnu"
}

func estEntier(n json.Number) bool {
	f, err := n.Float64()
	if err != nil {
		return false
	}
	return f == math.Trunc(f) && !math.IsInf(f, 0)
}

func nombre(doc any) (float64, bool) {
	n, ok := doc.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	return f, err == nil
}

// EgalJSON compare deux valeurs décodées (nombres comparés par valeur).
func EgalJSON(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case string:
		y, ok := b.(string)
		return ok && x == y
	case json.Number:
		y, ok := b.(json.Number)
		if !ok {
			return false
		}
		fx, e1 := x.Float64()
		fy, e2 := y.Float64()
		return e1 == nil && e2 == nil && fx == fy
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !EgalJSON(x[i], y[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for k, vx := range x {
			vy, ok := y[k]
			if !ok || !EgalJSON(vx, vy) {
				return false
			}
		}
		return true
	}
	return false
}

func (s *Schema) motif(p string) (*regexp.Regexp, error) {
	if re, ok := s.motifs[p]; ok {
		return re, nil
	}
	re, err := regexp.Compile(p)
	if err != nil {
		return nil, err
	}
	s.motifs[p] = re
	return re, nil
}

func (s *Schema) resoudre(ref string) any {
	if ref == "#" {
		return s.Racine
	}
	const prefixe = "#/$defs/"
	if strings.HasPrefix(ref, prefixe) {
		if d, ok := s.Defs[strings.TrimPrefix(ref, prefixe)]; ok {
			return d
		}
	}
	return nil
}

// passe dit si le document vérifie le sous-schéma sans enregistrer.
func (s *Schema) passe(sch, doc any, chemin string) bool {
	var v []Violation
	s.valider(sch, doc, chemin, &v)
	return len(v) == 0
}

func ajouter(v *[]Violation, chemin, motCle, format string, args ...any) {
	*v = append(*v, Violation{chemin, motCle, fmt.Sprintf(format, args...)})
}

func (s *Schema) valider(sch, doc any, chemin string, v *[]Violation) {
	switch b := sch.(type) {
	case bool:
		if !b {
			ajouter(v, chemin, "false schema", "schéma faux")
		}
		return
	case map[string]any:
		s.validerObjet(b, doc, chemin, v)
	}
}

func (s *Schema) validerObjet(sch map[string]any, doc any, chemin string, v *[]Violation) {
	if ref, ok := sch["$ref"].(string); ok {
		cible := s.resoudre(ref)
		if cible == nil {
			ajouter(v, chemin, "$ref", "référence %s introuvable", ref)
		} else {
			s.valider(cible, doc, chemin, v)
		}
	}
	if t, ok := sch["type"]; ok {
		var types []string
		switch x := t.(type) {
		case string:
			types = []string{x}
		case []any:
			for _, y := range x {
				if ys, ok := y.(string); ok {
					types = append(types, ys)
				}
			}
		}
		got := typeJSON(doc)
		ok := false
		for _, x := range types {
			if x == got || (x == "number" && got == "integer") {
				ok = true
			}
		}
		if !ok {
			ajouter(v, chemin, "type", "type %s, attendu %s", got, strings.Join(types, "|"))
		}
	}
	if c, ok := sch["const"]; ok && !EgalJSON(c, doc) {
		ajouter(v, chemin, "const", "valeur différente de la constante")
	}
	if e, ok := sch["enum"].([]any); ok {
		trouve := false
		for _, x := range e {
			if EgalJSON(x, doc) {
				trouve = true
			}
		}
		if !trouve {
			ajouter(v, chemin, "enum", "valeur hors de l'énumération")
		}
	}
	switch d := doc.(type) {
	case string:
		n := utf8.RuneCountInString(d)
		if m, ok := nombre(sch["minLength"]); ok && float64(n) < m {
			ajouter(v, chemin, "minLength", "%d caractères, minimum %v", n, m)
		}
		if m, ok := nombre(sch["maxLength"]); ok && float64(n) > m {
			ajouter(v, chemin, "maxLength", "%d caractères, maximum %v", n, m)
		}
		if p, ok := sch["pattern"].(string); ok {
			re, err := s.motif(p)
			if err != nil {
				ajouter(v, chemin, "pattern", "motif incompilable %q : %v", p, err)
			} else if !re.MatchString(d) {
				ajouter(v, chemin, "pattern", "ne vérifie pas %q", p)
			}
		}
	case json.Number:
		f, _ := nombre(d)
		if m, ok := nombre(sch["minimum"]); ok && f < m {
			ajouter(v, chemin, "minimum", "%v < %v", f, m)
		}
		if m, ok := nombre(sch["maximum"]); ok && f > m {
			ajouter(v, chemin, "maximum", "%v > %v", f, m)
		}
	case []any:
		if m, ok := nombre(sch["minItems"]); ok && float64(len(d)) < m {
			ajouter(v, chemin, "minItems", "%d éléments, minimum %v", len(d), m)
		}
		if m, ok := nombre(sch["maxItems"]); ok && float64(len(d)) > m {
			ajouter(v, chemin, "maxItems", "%d éléments, maximum %v", len(d), m)
		}
		if u, ok := sch["uniqueItems"].(bool); ok && u {
			for i := 0; i < len(d); i++ {
				for j := i + 1; j < len(d); j++ {
					if EgalJSON(d[i], d[j]) {
						ajouter(v, chemin, "uniqueItems", "éléments %d et %d égaux", i, j)
					}
				}
			}
		}
		if it, ok := sch["items"]; ok {
			for i, x := range d {
				s.valider(it, x, fmt.Sprintf("%s/%d", chemin, i), v)
			}
		}
	case map[string]any:
		if req, ok := sch["required"].([]any); ok {
			for _, r := range req {
				if k, ok := r.(string); ok {
					if _, present := d[k]; !present {
						ajouter(v, chemin, "required", "membre %s absent", k)
					}
				}
			}
		}
		if m, ok := nombre(sch["minProperties"]); ok && float64(len(d)) < m {
			ajouter(v, chemin, "minProperties", "%d membres, minimum %v", len(d), m)
		}
		props, _ := sch["properties"].(map[string]any)
		cles := make([]string, 0, len(d))
		for k := range d {
			cles = append(cles, k)
		}
		sort.Strings(cles)
		for _, k := range cles {
			x := d[k]
			if p, ok := props[k]; ok {
				s.valider(p, x, chemin+"/"+k, v)
				continue
			}
			if ap, ok := sch["additionalProperties"]; ok {
				if b, ok := ap.(bool); ok {
					if !b {
						ajouter(v, chemin, "additionalProperties", "membre %s non admis", k)
					}
				} else {
					s.valider(ap, x, chemin+"/"+k, v)
				}
			}
		}
	}
	if l, ok := sch["allOf"].([]any); ok {
		for _, x := range l {
			s.valider(x, doc, chemin, v)
		}
	}
	if l, ok := sch["anyOf"].([]any); ok {
		var sous []Violation
		ok := false
		for _, x := range l {
			var vx []Violation
			s.valider(x, doc, chemin, &vx)
			if len(vx) == 0 {
				ok = true
				break
			}
			sous = append(sous, vx...)
		}
		if !ok {
			*v = append(*v, sous...)
			ajouter(v, chemin, "anyOf", "aucune branche ne convient")
		}
	}
	if l, ok := sch["oneOf"].([]any); ok {
		n := 0
		for _, x := range l {
			if s.passe(x, doc, chemin) {
				n++
			}
		}
		if n != 1 {
			ajouter(v, chemin, "oneOf", "%d branches conviennent", n)
		}
	}
	if n, ok := sch["not"]; ok && s.passe(n, doc, chemin) {
		ajouter(v, chemin, "not", "le schéma interdit convient")
	}
	if cond, ok := sch["if"]; ok {
		if s.passe(cond, doc, chemin) {
			if th, ok := sch["then"]; ok {
				s.valider(th, doc, chemin, v)
			}
		} else if el, ok := sch["else"]; ok {
			s.valider(el, doc, chemin, v)
		}
	}
}
