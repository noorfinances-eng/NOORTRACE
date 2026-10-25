// Validateur JSON Schema (draft 2020-12) réduit aux mots-clés des schémas que
// CT-4 désigne (instance-registre-v0, inscription-client-v0,
// operations-registre-v0, et validateurs-v0 et registre-v0 de CT-6 pour les
// parties exportées), écrit ici. Un mot-clé inconnu est une erreur, jamais
// ignoré (« compilé en mode strict », CT-4 4.8).
//
// Les motifs (pattern) sont des expressions ECMAScript traduites pour
// regexp (RE2) : RE2 borne les répétitions à 1000 ; une borne haute
// supérieure ({1,524288} de raw_transaction) est remplacée par l'absence de
// borne haute, ce qui n'élargit le motif que pour des chaînes de plus de
// 2 × 1000 caractères répétés. \s de RE2 ne couvre que les espaces ASCII.

package main

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Schema est un document de schéma chargé.
type Schema struct {
	Nom  string
	Doc  *Value
	regs map[string]*regexp.Regexp
	mu   sync.Mutex
}

var motsCles = map[string]bool{
	"$schema": true, "$id": true, "title": true, "description": true, "$defs": true,
	"type": true, "const": true, "enum": true, "properties": true, "required": true,
	"additionalProperties": true, "items": true, "minItems": true, "maxItems": true,
	"uniqueItems": true, "minimum": true, "maximum": true, "minLength": true,
	"maxLength": true, "pattern": true, "oneOf": true, "anyOf": true, "allOf": true,
	"contains": true, "minContains": true, "maxContains": true, "if": true,
	"then": true, "else": true, "$ref": true, "not": true,
}

// ChargerSchema lit un schéma.
func ChargerSchema(chemin string) (*Schema, error) {
	b, err := os.ReadFile(chemin)
	if err != nil {
		return nil, err
	}
	v, err := ParseJSON(b)
	if err != nil {
		return nil, fmt.Errorf("%s : %v", chemin, err)
	}
	s := &Schema{Nom: filepath.Base(chemin), Doc: v, regs: map[string]*regexp.Regexp{}}
	if err := s.controler(v, "#"); err != nil {
		return nil, err
	}
	return s, nil
}

// controler refuse un mot-clé inconnu dans tout le schéma.
func (s *Schema) controler(v *Value, ptr string) error {
	if v.Kind == KindBool {
		return nil
	}
	if v.Kind != KindObject {
		return fmt.Errorf("%s %s : schéma objet attendu", s.Nom, ptr)
	}
	for _, m := range v.Obj {
		if !motsCles[m.Key] {
			return fmt.Errorf("%s %s : mot-clé %q non pris en charge", s.Nom, ptr, m.Key)
		}
		switch m.Key {
		case "properties", "$defs":
			for _, p := range m.Val.Obj {
				if err := s.controler(p.Val, ptr+"/"+m.Key+"/"+p.Key); err != nil {
					return err
				}
			}
		case "items", "additionalProperties", "contains", "if", "then", "else", "not":
			if err := s.controler(m.Val, ptr+"/"+m.Key); err != nil {
				return err
			}
		case "oneOf", "anyOf", "allOf":
			for i, e := range m.Val.Arr {
				if err := s.controler(e, ptr+"/"+m.Key+"/"+strconv.Itoa(i)); err != nil {
					return err
				}
			}
		case "pattern":
			if _, err := s.regexp(m.Val.Str); err != nil {
				return fmt.Errorf("%s %s : motif %q : %v", s.Nom, ptr, m.Val.Str, err)
			}
		}
	}
	return nil
}

var repetitionLongue = regexp.MustCompile(`\{([0-9]+),([0-9]+)\}`)

func (s *Schema) regexp(p string) (*regexp.Regexp, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.regs[p]; ok {
		return r, nil
	}
	q := repetitionLongue.ReplaceAllStringFunc(p, func(m string) string {
		sm := repetitionLongue.FindStringSubmatch(m)
		hi, _ := strconv.Atoi(sm[2])
		if hi > 1000 {
			return "{" + sm[1] + ",}"
		}
		return m
	})
	r, err := regexp.Compile(q)
	if err != nil {
		return nil, err
	}
	s.regs[p] = r
	return r, nil
}

// Pointeur résout un pointeur JSON « #/$defs/x » dans le schéma.
func (s *Schema) Pointeur(ptr string) (*Value, error) {
	if ptr == "" || ptr == "#" {
		return s.Doc, nil
	}
	if !strings.HasPrefix(ptr, "#/") {
		return nil, fmt.Errorf("référence %q non locale", ptr)
	}
	v := s.Doc
	for _, seg := range strings.Split(ptr[2:], "/") {
		seg = strings.ReplaceAll(strings.ReplaceAll(seg, "~1", "/"), "~0", "~")
		v = v.Get(seg)
		if v == nil {
			return nil, fmt.Errorf("référence %q introuvable", ptr)
		}
	}
	return v, nil
}

// Valider valide une instance contre le schéma (ou l'un de ses $defs) et
// rend la liste des erreurs, vide si l'instance est conforme.
func (s *Schema) Valider(inst *Value, ptr string) []string {
	sch, err := s.Pointeur(ptr)
	if err != nil {
		return []string{err.Error()}
	}
	var errs []string
	s.valider(sch, inst, "", &errs, 0)
	return errs
}

func typeJSON(v *Value) string {
	switch v.Kind {
	case KindNull:
		return "null"
	case KindBool:
		return "boolean"
	case KindString:
		return "string"
	case KindArray:
		return "array"
	case KindObject:
		return "object"
	case KindNumber:
		if r, ok := RationnelDe(v.Num); ok && r.IsInt() {
			return "integer"
		}
		return "number"
	}
	return "?"
}

func correspondType(t string, v *Value) bool {
	jt := typeJSON(v)
	return t == jt || (t == "number" && jt == "integer")
}

func nombre(v *Value) *big.Rat {
	r, _ := RationnelDe(v.Num)
	return r
}

func (s *Schema) valider(sch, inst *Value, chemin string, errs *[]string, prof int) {
	if prof > 64 {
		*errs = append(*errs, chemin+" : schéma trop profond")
		return
	}
	if sch.Kind == KindBool {
		if !sch.Bool {
			*errs = append(*errs, chemin+" : schéma faux")
		}
		return
	}
	ajouter := func(f string, a ...any) { *errs = append(*errs, cheminOuRacine(chemin)+" : "+fmt.Sprintf(f, a...)) }
	if ref := sch.Get("$ref"); ref != nil {
		cible, err := s.Pointeur(ref.Str)
		if err != nil {
			ajouter("%v", err)
		} else {
			s.valider(cible, inst, chemin, errs, prof+1)
		}
	}
	if t := sch.Get("type"); t != nil {
		ok := false
		if t.Kind == KindString {
			ok = correspondType(t.Str, inst)
		} else {
			for _, e := range t.Arr {
				ok = ok || correspondType(e.Str, inst)
			}
		}
		if !ok {
			ajouter("type %s au lieu de %s", typeJSON(inst), Compact(t))
			return
		}
	}
	if c := sch.Get("const"); c != nil && !EgalJSON(c, inst) {
		ajouter("valeur %s au lieu de la constante %s", Compact(inst), Compact(c))
	}
	if e := sch.Get("enum"); e != nil {
		ok := false
		for _, x := range e.Arr {
			ok = ok || EgalJSON(x, inst)
		}
		if !ok {
			ajouter("valeur %s hors de l'énumération", Compact(inst))
		}
	}
	switch inst.Kind {
	case KindNumber:
		if m := sch.Get("minimum"); m != nil && nombre(inst).Cmp(nombre(m)) < 0 {
			ajouter("%s < minimum %s", inst.Num, m.Num)
		}
		if m := sch.Get("maximum"); m != nil && nombre(inst).Cmp(nombre(m)) > 0 {
			ajouter("%s > maximum %s", inst.Num, m.Num)
		}
	case KindString:
		n := PointsDeCode(inst.Str)
		if m := sch.Get("minLength"); m != nil {
			if l, _ := strconv.Atoi(m.Num); n < l {
				ajouter("longueur %d < %d", n, l)
			}
		}
		if m := sch.Get("maxLength"); m != nil {
			if l, _ := strconv.Atoi(m.Num); n > l {
				ajouter("longueur %d > %d", n, l)
			}
		}
		if p := sch.Get("pattern"); p != nil {
			r, err := s.regexp(p.Str)
			if err != nil || !r.MatchString(inst.Str) {
				ajouter("%q ne vérifie pas le motif %s", inst.Str, p.Str)
			}
		}
	case KindArray:
		if m := sch.Get("minItems"); m != nil {
			if l, _ := strconv.Atoi(m.Num); len(inst.Arr) < l {
				ajouter("%d éléments < %d", len(inst.Arr), l)
			}
		}
		if m := sch.Get("maxItems"); m != nil {
			if l, _ := strconv.Atoi(m.Num); len(inst.Arr) > l {
				ajouter("%d éléments > %d", len(inst.Arr), l)
			}
		}
		if u := sch.Get("uniqueItems"); u != nil && u.Bool {
			for i := range inst.Arr {
				for j := i + 1; j < len(inst.Arr); j++ {
					if EgalJSON(inst.Arr[i], inst.Arr[j]) {
						ajouter("éléments %d et %d égaux", i, j)
					}
				}
			}
		}
		if it := sch.Get("items"); it != nil {
			for i, e := range inst.Arr {
				s.valider(it, e, chemin+"/"+strconv.Itoa(i), errs, prof+1)
			}
		}
		if c := sch.Get("contains"); c != nil {
			n := 0
			for _, e := range inst.Arr {
				var sous []string
				s.valider(c, e, chemin, &sous, prof+1)
				if len(sous) == 0 {
					n++
				}
			}
			min, max := 1, -1
			if m := sch.Get("minContains"); m != nil {
				min, _ = strconv.Atoi(m.Num)
			}
			if m := sch.Get("maxContains"); m != nil {
				max, _ = strconv.Atoi(m.Num)
			}
			if n < min || (max >= 0 && n > max) {
				ajouter("%d éléments correspondent à contains (bornes %d, %d)", n, min, max)
			}
		}
	case KindObject:
		if r := sch.Get("required"); r != nil {
			for _, k := range r.Arr {
				if !inst.Has(k.Str) {
					ajouter("membre requis %q absent", k.Str)
				}
			}
		}
		props := sch.Get("properties")
		for _, m := range inst.Obj {
			if props != nil {
				if p := props.Get(m.Key); p != nil {
					s.valider(p, m.Val, chemin+"/"+m.Key, errs, prof+1)
					continue
				}
			}
			if ap := sch.Get("additionalProperties"); ap != nil {
				if ap.Kind == KindBool && !ap.Bool {
					ajouter("membre %q non admis", m.Key)
				} else if ap.Kind == KindObject {
					s.valider(ap, m.Val, chemin+"/"+m.Key, errs, prof+1)
				}
			}
		}
	}
	if a := sch.Get("allOf"); a != nil {
		for _, e := range a.Arr {
			s.valider(e, inst, chemin, errs, prof+1)
		}
	}
	if a := sch.Get("anyOf"); a != nil {
		ok := false
		for _, e := range a.Arr {
			var sous []string
			s.valider(e, inst, chemin, &sous, prof+1)
			ok = ok || len(sous) == 0
		}
		if !ok {
			ajouter("aucune branche de anyOf")
		}
	}
	if o := sch.Get("oneOf"); o != nil {
		n := 0
		var detail []string
		for _, e := range o.Arr {
			var sous []string
			s.valider(e, inst, chemin, &sous, prof+1)
			if len(sous) == 0 {
				n++
			} else {
				detail = append(detail, sous...)
			}
		}
		if n != 1 {
			sort.Strings(detail)
			if len(detail) > 3 {
				detail = detail[:3]
			}
			ajouter("%d branches de oneOf au lieu d'une (%s)", n, strings.Join(detail, " ; "))
		}
	}
	if n := sch.Get("not"); n != nil {
		var sous []string
		s.valider(n, inst, chemin, &sous, prof+1)
		if len(sous) == 0 {
			ajouter("valeur conforme au schéma de not")
		}
	}
	if si := sch.Get("if"); si != nil {
		var sous []string
		s.valider(si, inst, chemin, &sous, prof+1)
		if len(sous) == 0 {
			if t := sch.Get("then"); t != nil {
				s.valider(t, inst, chemin, errs, prof+1)
			}
		} else if e := sch.Get("else"); e != nil {
			s.valider(e, inst, chemin, errs, prof+1)
		}
	}
}

func cheminOuRacine(c string) string {
	if c == "" {
		return "/"
	}
	return c
}

// Schemas tient les schémas lus dans spec/schemas.
type Schemas struct {
	rep  string
	docs map[string]*Schema
	err  map[string]error
}

// NouveauxSchemas prépare la lecture des schémas d'un répertoire.
func NouveauxSchemas(rep string) *Schemas {
	return &Schemas{rep: rep, docs: map[string]*Schema{}, err: map[string]error{}}
}

// Valider valide une instance contre « nom.schema.json#/$defs/x » ou
// « nom.schema.json ».
func (ss *Schemas) Valider(ref string, inst *Value) []string {
	fichier, ptr, _ := strings.Cut(ref, "#")
	s, ok := ss.docs[fichier]
	if !ok {
		if e, ko := ss.err[fichier]; ko {
			return []string{e.Error()}
		}
		var err error
		s, err = ChargerSchema(filepath.Join(ss.rep, fichier))
		if err != nil {
			ss.err[fichier] = err
			return []string{err.Error()}
		}
		ss.docs[fichier] = s
	}
	return s.Valider(inst, "#"+ptr)
}
