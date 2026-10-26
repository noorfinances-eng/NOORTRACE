// Validateur JSON Schema 2020-12 réduit aux mots-clés qu'emploient les
// schémas que CT-3 cite : politique-approbation-v0, ticket-v0, et, depuis la
// révision 0.3, annuaire-approbateurs-v0, console-approbation-v0 et
// console-service-v0 ; par renvoi, evenement-v0 (CT-1). Un mot-clé inconnu est une erreur du
// vérificateur, jamais ignoré en silence.
//
// Mots-clés : $id, $ref (local « #/$defs/… » ou absolu par $id), $defs,
// type, enum, const, pattern, minLength, maxLength (en points de code),
// minimum, maximum, minItems, maxItems, uniqueItems, prefixItems, items
// (appliqué aux éléments qui suivent ceux de prefixItems), required,
// properties, additionalProperties, propertyNames, maxProperties, allOf,
// anyOf, oneOf, not, if/then ; annotations : $schema, title, description.
//
// Motifs : écrits pour ECMAScript (drapeau u, comme le valide ajv) ; les
// échappements \uXXXX sont réécrits \x{XXXX} pour le paquet regexp de Go
// (RE2). Les motifs de ces schémas n'emploient ni rétro-référence ni
// assertion, que RE2 n'a pas.

package main

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Schemas regroupe les documents de schéma chargés, indexés par $id.
type Schemas struct {
	parID  map[string]*Value
	motifs map[string]*regexp.Regexp
}

// ChargerSchemas lit les fichiers de schéma donnés.
func ChargerSchemas(chemins ...string) (*Schemas, error) {
	s := &Schemas{parID: map[string]*Value{}, motifs: map[string]*regexp.Regexp{}}
	for _, c := range chemins {
		src, err := os.ReadFile(c)
		if err != nil {
			return nil, err
		}
		v, err := ParseJSON(src)
		if err != nil {
			return nil, fmt.Errorf("%s : %v", filepath.Base(c), err)
		}
		id := v.Get("$id").S()
		if id == "" {
			return nil, fmt.Errorf("%s : $id absent", filepath.Base(c))
		}
		s.parID[id] = v
	}
	return s, nil
}

// contexteSchema est un schéma et le document qui le porte (pour les $ref
// locaux).
type contexteSchema struct {
	doc *Value
	sch *Value
}

// Valider valide une instance contre « <$id>#/$defs/<nom> » (ou le document
// entier si le fragment est vide) et rend la liste des erreurs.
func (s *Schemas) Valider(ref string, inst *Value) []string {
	c, err := s.resoudre(nil, ref)
	if err != nil {
		return []string{err.Error()}
	}
	var errs []string
	s.valider(c, inst, "", &errs)
	return errs
}

func (s *Schemas) resoudre(doc *Value, ref string) (contexteSchema, error) {
	base, frag, _ := strings.Cut(ref, "#")
	d := doc
	if base != "" {
		d = s.parID[base]
		if d == nil {
			return contexteSchema{}, fmt.Errorf("schéma %q non chargé", base)
		}
	}
	if d == nil {
		return contexteSchema{}, fmt.Errorf("renvoi %q sans document", ref)
	}
	cur := d
	if frag != "" {
		if !strings.HasPrefix(frag, "/") {
			return contexteSchema{}, fmt.Errorf("fragment %q non pris en charge", frag)
		}
		for _, tok := range strings.Split(frag[1:], "/") {
			tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
			cur = cur.Get(tok)
			if cur == nil {
				return contexteSchema{}, fmt.Errorf("renvoi %q introuvable", ref)
			}
		}
	}
	return contexteSchema{doc: d, sch: cur}, nil
}

var reEchappementU = regexp.MustCompile(`\\u([0-9A-Fa-f]{4})`)

func (s *Schemas) motif(p string) (*regexp.Regexp, error) {
	if re, ok := s.motifs[p]; ok {
		return re, nil
	}
	gop := reEchappementU.ReplaceAllString(p, `\x{$1}`)
	re, err := regexp.Compile(gop)
	if err != nil {
		return nil, fmt.Errorf("motif %q non traduisible : %v", p, err)
	}
	s.motifs[p] = re
	return re, nil
}

var motsAnnotation = map[string]bool{"$schema": true, "$id": true, "$defs": true, "title": true, "description": true}

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
	}
	return "number"
}

func estEntierJSON(v *Value) bool {
	r, ok := RationnelDe(v.Num)
	return ok && r.IsInt()
}

func (s *Schemas) valider(c contexteSchema, inst *Value, ptr string, errs *[]string) {
	sch := c.sch
	if sch.Kind == KindBool {
		if !sch.Bool {
			*errs = append(*errs, fmt.Sprintf("%s : schéma false", ptrOuRacine(ptr)))
		}
		return
	}
	if sch.Kind != KindObject {
		*errs = append(*errs, fmt.Sprintf("%s : schéma mal formé", ptrOuRacine(ptr)))
		return
	}
	ajout := func(format string, args ...any) {
		*errs = append(*errs, ptrOuRacine(ptr)+" : "+fmt.Sprintf(format, args...))
	}
	sous := func(sv *Value) contexteSchema { return contexteSchema{doc: c.doc, sch: sv} }
	valide := func(sv *Value, x *Value) bool {
		var e []string
		s.valider(sous(sv), x, ptr, &e)
		return len(e) == 0
	}
	for _, m := range sch.Obj {
		k, sv := m.Key, m.Val
		switch k {
		case "$schema", "$id", "$defs", "title", "description":
		case "$ref":
			cc, err := s.resoudre(c.doc, sv.S())
			if err != nil {
				ajout("%v", err)
				continue
			}
			s.valider(cc, inst, ptr, errs)
		case "type":
			types := []string{}
			if sv.Kind == KindString {
				types = append(types, sv.Str)
			} else {
				for _, e := range sv.Arr {
					types = append(types, e.Str)
				}
			}
			ok := false
			for _, t := range types {
				tj := typeJSON(inst)
				if t == tj || (t == "integer" && tj == "number" && estEntierJSON(inst)) {
					ok = true
				}
			}
			if !ok {
				ajout("type %s attendu, %s trouvé", strings.Join(types, " ou "), typeJSON(inst))
			}
		case "enum":
			ok := false
			for _, e := range sv.Arr {
				if EgalJSON(e, inst) {
					ok = true
				}
			}
			if !ok {
				ajout("valeur hors de l'énumération %s", Compact(sv))
			}
		case "const":
			if !EgalJSON(sv, inst) {
				ajout("constante %s attendue", Compact(sv))
			}
		case "pattern":
			if inst.Kind == KindString {
				re, err := s.motif(sv.Str)
				if err != nil {
					ajout("%v", err)
				} else if !re.MatchString(inst.Str) {
					ajout("%q ne respecte pas le motif %s", inst.Str, sv.Str)
				}
			}
		case "minLength", "maxLength":
			if inst.Kind == KindString {
				n := PointsDeCode(inst.Str)
				b, _ := RationnelDe(sv.Num)
				lim := int(b.Num().Int64())
				if (k == "minLength" && n < lim) || (k == "maxLength" && n > lim) {
					ajout("longueur %d hors de %s %d", n, k, lim)
				}
			}
		case "minimum", "maximum":
			if inst.Kind == KindNumber {
				x, ok1 := RationnelDe(inst.Num)
				b, ok2 := RationnelDe(sv.Num)
				if !ok1 || !ok2 {
					ajout("nombre illisible")
				} else if (k == "minimum" && x.Cmp(b) < 0) || (k == "maximum" && x.Cmp(b) > 0) {
					ajout("%s hors de %s %s", inst.Num, k, sv.Num)
				}
			}
		case "minItems", "maxItems":
			if inst.Kind == KindArray {
				b, _ := RationnelDe(sv.Num)
				lim := int(b.Num().Int64())
				if (k == "minItems" && len(inst.Arr) < lim) || (k == "maxItems" && len(inst.Arr) > lim) {
					ajout("%d éléments hors de %s %d", len(inst.Arr), k, lim)
				}
			}
		case "uniqueItems":
			if inst.Kind == KindArray && sv.Bool {
				for i := range inst.Arr {
					for j := i + 1; j < len(inst.Arr); j++ {
						if EgalJSON(inst.Arr[i], inst.Arr[j]) {
							ajout("éléments %d et %d égaux", i, j)
						}
					}
				}
			}
		case "prefixItems":
			if inst.Kind == KindArray {
				for i, e := range inst.Arr {
					if i < len(sv.Arr) {
						s.valider(sous(sv.Arr[i]), e, fmt.Sprintf("%s/%d", ptr, i), errs)
					}
				}
			}
		case "items":
			if inst.Kind == KindArray {
				debut := 0
				if pi := sch.Get("prefixItems"); pi != nil && pi.Kind == KindArray {
					debut = len(pi.Arr)
				}
				for i := debut; i < len(inst.Arr); i++ {
					s.valider(sous(sv), inst.Arr[i], fmt.Sprintf("%s/%d", ptr, i), errs)
				}
			}
		case "required":
			if inst.Kind == KindObject {
				for _, r := range sv.Arr {
					if !inst.Has(r.Str) {
						ajout("membre %q requis", r.Str)
					}
				}
			}
		case "properties":
			if inst.Kind == KindObject {
				for _, p := range sv.Obj {
					if x := inst.Get(p.Key); x != nil {
						s.valider(sous(p.Val), x, ptr+"/"+echapperJeton(p.Key), errs)
					}
				}
			}
		case "additionalProperties":
			if inst.Kind == KindObject {
				props := sch.Get("properties")
				for _, m := range inst.Obj {
					if props != nil && props.Get(m.Key) != nil {
						continue
					}
					s.valider(sous(sv), m.Val, ptr+"/"+echapperJeton(m.Key), errs)
				}
			}
		case "propertyNames":
			if inst.Kind == KindObject {
				for _, m := range inst.Obj {
					s.valider(sous(sv), Chaine(m.Key), ptr+"/"+echapperJeton(m.Key), errs)
				}
			}
		case "maxProperties":
			if inst.Kind == KindObject {
				b, _ := RationnelDe(sv.Num)
				if len(inst.Obj) > int(b.Num().Int64()) {
					ajout("%d membres, au plus %s", len(inst.Obj), sv.Num)
				}
			}
		case "allOf":
			for _, e := range sv.Arr {
				s.valider(sous(e), inst, ptr, errs)
			}
		case "anyOf":
			ok := false
			for _, e := range sv.Arr {
				if valide(e, inst) {
					ok = true
					break
				}
			}
			if !ok {
				ajout("aucune branche de anyOf ne convient")
			}
		case "oneOf":
			n := 0
			for _, e := range sv.Arr {
				if valide(e, inst) {
					n++
				}
			}
			if n != 1 {
				ajout("%d branches de oneOf conviennent, une seule attendue", n)
			}
		case "not":
			if valide(sv, inst) {
				ajout("la valeur vérifie le schéma de not")
			}
		case "if":
			if valide(sv, inst) {
				if th := sch.Get("then"); th != nil {
					s.valider(sous(th), inst, ptr, errs)
				}
			} else if el := sch.Get("else"); el != nil {
				s.valider(sous(el), inst, ptr, errs)
			}
		case "then", "else":
		default:
			if !motsAnnotation[k] {
				ajout("mot-clé de schéma non pris en charge par ce vérificateur : %s", k)
			}
		}
	}
}

func ptrOuRacine(p string) string {
	if p == "" {
		return "(racine)"
	}
	return p
}

// echapperJeton écrit un jeton de pointeur JSON (RFC 6901 §3).
func echapperJeton(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

// grandEntier lit un entier JSON exact.
func grandEntier(v *Value) (*big.Int, bool) {
	if v == nil || v.Kind != KindNumber {
		return nil, false
	}
	r, ok := RationnelDe(v.Num)
	if !ok || !r.IsInt() {
		return nil, false
	}
	return new(big.Int).Set(r.Num()), true
}

// EntierJSON lit un entier JSON tenant dans un int64.
func EntierJSON(v *Value) (int64, bool) {
	b, ok := grandEntier(v)
	if !ok || !b.IsInt64() {
		return 0, false
	}
	return b.Int64(), true
}
