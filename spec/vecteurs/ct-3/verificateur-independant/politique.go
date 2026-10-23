// Politique d'approbation (CT-3 section 4) : lecture du document
// politique-approbation-v0 et validation au chargement (EX-4.2, EX-8.2).

package main

import (
	"fmt"
	"sort"
	"strings"
)

// Seuil est { required, size } (CT-1 §5.3).
type Seuil struct {
	Required, Size int64
}

// FenetreRegle est le membre window d'une règle fenetre (5.3).
type FenetreRegle struct {
	DureeMs        int64
	MaxAppels      int64
	MemesArguments []string
}

// Regle est un élément de rules (4.2).
type Regle struct {
	Nom       string
	Outils    []string
	Quand     *Value // nil : when null (condition VRAI)
	Niveau    string
	Decision  string // "" pour fenetre et revue
	Fenetre   *FenetreRegle
	ContestMs *int64
}

// Identite est un élément de separation.identities (10.1).
type Identite struct {
	LaunchedBy string
	Adresses   []string
}

// Politique est un document politique-approbation-v0 valide.
type Politique struct {
	Defaut struct {
		Nom       string
		Niveau    string
		Decision  string
		ContestMs *int64
	}
	Regles          []Regle
	JeuSource       string
	ChainID         int64
	Registre        string
	Membres         []string
	Seuil           *Seuil
	AutoApprobation string
	Identites       []Identite
}

// ErreurPolitique est une erreur de validation (annexe A.4) : code de
// $defs/code_erreur_politique et pointeur du membre fautif (nil pour
// schema).
type ErreurPolitique struct {
	Code     string
	Pointeur *string
}

func (e ErreurPolitique) String() string {
	if e.Pointeur == nil {
		return e.Code + " (null)"
	}
	return e.Code + " " + *e.Pointeur
}

func entierOuNil(v *Value) *int64 {
	if v == nil || v.Kind != KindNumber {
		return nil
	}
	n, ok := EntierJSON(v)
	if !ok {
		return nil
	}
	return &n
}

func chaines(v *Value) []string {
	var out []string
	if v == nil {
		return out
	}
	for _, e := range v.Arr {
		out = append(out, e.Str)
	}
	return out
}

// LirePolitique construit le modèle d'un document conforme au schéma.
func LirePolitique(doc *Value) *Politique {
	p := &Politique{}
	d := doc.Get("default")
	p.Defaut.Nom = d.Get("name").S()
	p.Defaut.Niveau = d.Get("level").S()
	p.Defaut.Decision = d.Get("decision").S()
	p.Defaut.ContestMs = entierOuNil(d.Get("contest_ms"))
	for _, r := range doc.Get("rules").Arr {
		rg := Regle{
			Nom:       r.Get("name").S(),
			Outils:    chaines(r.Get("tools")),
			Niveau:    r.Get("level").S(),
			Decision:  r.Get("decision").S(),
			ContestMs: entierOuNil(r.Get("contest_ms")),
		}
		if w := r.Get("when"); w != nil && !w.IsNull() {
			rg.Quand = w
		}
		if w := r.Get("window"); w != nil && !w.IsNull() {
			du, _ := EntierJSON(w.Get("duration_ms"))
			mc, _ := EntierJSON(w.Get("max_calls"))
			rg.Fenetre = &FenetreRegle{DureeMs: du, MaxAppels: mc, MemesArguments: chaines(w.Get("same_arguments"))}
		}
		p.Regles = append(p.Regles, rg)
	}
	js := doc.Get("approver_set")
	p.JeuSource = js.Get("source").S()
	if n, ok := EntierJSON(js.Get("chain_id")); ok {
		p.ChainID = n
	}
	p.Registre = js.Get("registry").S()
	if m := js.Get("members"); m != nil && m.Kind == KindArray {
		p.Membres = chaines(m)
	}
	if t := js.Get("threshold"); t != nil && t.Kind == KindObject {
		rq, _ := EntierJSON(t.Get("required"))
		sz, _ := EntierJSON(t.Get("size"))
		p.Seuil = &Seuil{Required: rq, Size: sz}
	}
	sep := doc.Get("separation")
	p.AutoApprobation = sep.Get("self_approval").S()
	for _, id := range sep.Get("identities").Arr {
		p.Identites = append(p.Identites, Identite{LaunchedBy: id.Get("launched_by").S(), Adresses: chaines(id.Get("addresses"))})
	}
	return p
}

// RefPolitique est le schéma du document (4.2).
const RefPolitique = "https://noortrace.example/schemas/v0/politique-approbation.schema.json"

// ValiderPolitique applique EX-4.2 : schéma d'abord ; un document non
// conforme donne exactement une entrée « schema », pointeur nul, quel que
// soit le nombre de non-conformités, et rien d'autre (annexe A.4). Un
// document conforme est soumis aux règles que le schéma n'exprime pas,
// toutes rapportées, triées par pointeur (unités UTF-16) puis par code.
func ValiderPolitique(sch *Schemas, doc *Value, environnement string, expireAfterMs int64) ([]ErreurPolitique, []string) {
	var out []ErreurPolitique
	detailsSchema := sch.Valider(RefPolitique, doc)
	if len(detailsSchema) > 0 {
		// EX-4.2 : une non-conformité au schéma donne exactement l'entrée
		// schema ; les règles 1 à 4 ne sont pas vérifiées.
		return []ErreurPolitique{{Code: "schema"}}, detailsSchema
	}
	ajout := func(code, ptr string) {
		p := ptr
		out = append(out, ErreurPolitique{Code: code, Pointeur: &p})
	}
	// 4. chaînes bien formées, partout dans le document
	parcourirChaines(doc, "", func(ptr string) { ajout("substitut_isole", ptr) })
	// 1. noms uniques, règle par défaut comprise
	vus := map[string]bool{}
	if n := doc.Get("default").Get("name"); n != nil && n.Kind == KindString {
		vus[n.Str] = true
	}
	regles := doc.Get("rules")
	if regles != nil && regles.Kind == KindArray {
		for i, r := range regles.Arr {
			n := r.Get("name")
			if n == nil || n.Kind != KindString {
				continue
			}
			if vus[n.Str] {
				ajout("nom_double", fmt.Sprintf("/rules/%d/name", i))
			}
			vus[n.Str] = true
		}
		for i, r := range regles.Arr {
			base := fmt.Sprintf("/rules/%d", i)
			// 2. pointeurs d'au plus 32 jetons, dans when et dans same_arguments
			if w := r.Get("when"); w != nil && w.Kind == KindObject {
				parcourirPredicats(w, base+"/when", func(pred *Value, ptr string) {
					if p := pred.Get("path"); p != nil && p.Kind == KindString && nombreJetons(p.Str) > 32 {
						ajout("pointeur_trop_long", ptr+"/path")
					}
				})
				// 3. profondeur et nombre de prédicats
				if profondeur(w) > 8 {
					ajout("condition_trop_profonde", base+"/when")
				}
				if nombrePredicats(w) > 64 {
					ajout("trop_de_predicats", base+"/when")
				}
			}
			if win := r.Get("window"); win != nil && win.Kind == KindObject {
				if sa := win.Get("same_arguments"); sa != nil && sa.Kind == KindArray {
					for j, p := range sa.Arr {
						if p.Kind == KindString && nombreJetons(p.Str) > 32 {
							ajout("pointeur_trop_long", fmt.Sprintf("%s/window/same_arguments/%d", base, j))
						}
					}
				}
			}
			// 6. contest_ms < expire_after_ms
			if c, ok := EntierJSON(r.Get("contest_ms")); ok && c >= expireAfterMs {
				ajout("contest_ms_trop_long", base+"/contest_ms")
			}
		}
	}
	if c, ok := EntierJSON(doc.Get("default").Get("contest_ms")); ok && c >= expireAfterMs {
		ajout("contest_ms_trop_long", "/default/contest_ms")
	}
	// 5. launched_by unique dans separation.identities
	if ids := doc.Get("separation").Get("identities"); ids != nil && ids.Kind == KindArray {
		lb := map[string]bool{}
		for i, id := range ids.Arr {
			l := id.Get("launched_by")
			if l == nil || l.Kind != KindString {
				continue
			}
			if lb[l.Str] {
				ajout("launched_by_double", fmt.Sprintf("/separation/identities/%d/launched_by", i))
			}
			lb[l.Str] = true
		}
	}
	// 7. approver_set statique (EX-8.2, points 1 et 2)
	if js := doc.Get("approver_set"); js != nil && js.Get("source").S() == "statique" {
		m := js.Get("members")
		t := js.Get("threshold")
		if m != nil && m.Kind == KindArray && t != nil && t.Kind == KindObject {
			rq, ok1 := EntierJSON(t.Get("required"))
			sz, ok2 := EntierJSON(t.Get("size"))
			if ok1 && ok2 && (sz != int64(len(m.Arr)) || rq > sz) {
				ajout("seuil_statique_incoherent", "/approver_set/threshold")
			}
		}
		if environnement == "production" {
			ajout("jeu_statique_en_production", "/approver_set/source")
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		pi, pj := "", ""
		if out[i].Pointeur != nil {
			pi = *out[i].Pointeur
		}
		if out[j].Pointeur != nil {
			pj = *out[j].Pointeur
		}
		if out[i].Pointeur == nil || out[j].Pointeur == nil {
			if (out[i].Pointeur == nil) != (out[j].Pointeur == nil) {
				return out[i].Pointeur == nil
			}
		} else if c := ComparerUTF16(pi, pj); c != 0 {
			return c < 0
		}
		return out[i].Code < out[j].Code
	})
	return out, detailsSchema
}

// parcourirChaines appelle f avec le pointeur de chaque chaîne (valeur ou
// nom de membre) qui contient un substitut isolé.
func parcourirChaines(v *Value, ptr string, f func(string)) {
	switch v.Kind {
	case KindString:
		if !ChaineBienFormee(v.Str) {
			f(ptr)
		}
	case KindArray:
		for i, e := range v.Arr {
			parcourirChaines(e, fmt.Sprintf("%s/%d", ptr, i), f)
		}
	case KindObject:
		for _, m := range v.Obj {
			p := ptr + "/" + echapperJeton(m.Key)
			if !ChaineBienFormee(m.Key) {
				f(p)
			}
			parcourirChaines(m.Val, p, f)
		}
	}
}

// combinaison rend la liste d'une combinaison all, any, none, et son nom.
func combinaison(c *Value) (string, *Value) {
	for _, k := range []string{"all", "any", "none"} {
		if l := c.Get(k); l != nil {
			return k, l
		}
	}
	return "", nil
}

func parcourirPredicats(c *Value, ptr string, f func(*Value, string)) {
	if c == nil || c.Kind != KindObject {
		return
	}
	if k, l := combinaison(c); l != nil {
		if l.Kind == KindArray {
			for i, e := range l.Arr {
				parcourirPredicats(e, fmt.Sprintf("%s/%s/%d", ptr, k, i), f)
			}
		}
		return
	}
	f(c, ptr)
}

// profondeur : un prédicat seul est au niveau 1, chaque all, any ou none
// ajoute un niveau (EX-4.2, point 3).
func profondeur(c *Value) int {
	if c == nil || c.Kind != KindObject {
		return 0
	}
	if _, l := combinaison(c); l != nil {
		m := 0
		if l.Kind == KindArray {
			for _, e := range l.Arr {
				if p := profondeur(e); p > m {
					m = p
				}
			}
		}
		return 1 + m
	}
	return 1
}

func nombrePredicats(c *Value) int {
	n := 0
	parcourirPredicats(c, "", func(*Value, string) { n++ })
	return n
}

// nombreJetons : le pointeur est découpé sur « / » après son premier
// caractère (EX-4.4) ; « /arguments/a » a deux jetons.
func nombreJetons(p string) int {
	if p == "" {
		return 0
	}
	return strings.Count(p, "/")
}
