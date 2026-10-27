// Matrice de conformité (CT-7 section 8, annexe A.8) : ce module rejoue
// MX-1 à MX-3, MX-5 et MX-9 (EX-A.23) ; MX-4, MX-6, MX-7 et MX-8 restent au
// vérificateur de renvois et sont rapportées hors périmètre.

package main

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// idsMXExecutees sont les vérifications que ce module exécute.
var idsMXExecutees = []string{"MX-1", "MX-2", "MX-3", "MX-5", "MX-9"}

// ContexteMatrice porte ce que MX-5 et MX-9 lisent dans le texte de CT-7 :
// les sous-sections de l'annexe C (identifiant et titre) et les faits des
// tables de l'annexe B.
type ContexteMatrice struct {
	Clauses map[string]string // CL-n → titre
	Faits   map[string]bool
}

var (
	reFait      = regexp.MustCompile(`R([0-9]+)-F([0-9]+)(?: à R([0-9]+)-F([0-9]+))?`)
	reSousTitre = regexp.MustCompile(`^(CL-[0-9]+) (.+)$`)
)

// LireContexteMatrice extrait de CT-7 les clauses de l'annexe C et les
// faits de l'annexe B (première cellule des tables, plages « R7-F4 à
// R7-F8 » développées).
func LireContexteMatrice(t *Texte) (*ContexteMatrice, error) {
	c := &ContexteMatrice{Clauses: map[string]string{}, Faits: map[string]bool{}}
	annC, err := t.Section("## Annexe C")
	if err != nil {
		return nil, err
	}
	for _, ti := range Titres(annC, "###") {
		if m := reSousTitre.FindStringSubmatch(ti); m != nil {
			c.Clauses[m[1]] = m[2]
		}
	}
	annB, err := t.Section("## Annexe B")
	if err != nil {
		return nil, err
	}
	for _, tb := range Tables(annB) {
		if len(tb.Entete) == 0 || tb.Entete[0] != "Renvoi" {
			continue
		}
		for _, l := range tb.Lignes {
			for _, m := range reFait.FindAllStringSubmatch(l[0], -1) {
				n1, _ := strconv.Atoi(m[2])
				n2 := n1
				if m[3] != "" && m[3] == m[1] {
					n2, _ = strconv.Atoi(m[4])
				}
				for n := n1; n <= n2; n++ {
					c.Faits[fmt.Sprintf("R%s-F%d", m[1], n)] = true
				}
			}
		}
	}
	return c, nil
}

// StatutDerive calcule le statut d'une ligne selon EX-8.3.
func StatutDerive(ligne *Value) string {
	compte := map[string]int{}
	for _, e := range ligne.Get("elements").Arr {
		rel := e.Get("relation").Chaine()
		// Un élément repond_a qui porte une condition compte comme contribue_a (EX-8.3).
		if c := e.Get("condition"); rel == "repond_a" && c != nil && !c.EstNull() {
			rel = "contribue_a"
		}
		compte[rel]++
	}
	switch {
	case compte["repond_a"] == 0 && compte["contribue_a"] == 0:
		return "hors_perimetre"
	case compte["repond_a"] >= 1 && compte["contribue_a"] == 0 && compte["ne_couvre_pas"] == 0:
		return "couvert"
	}
	return "partiel"
}

// numerosDansLOrdre dit si le i-ième identifiant est préfixe-i (MX-2 :
// numérotés 1 à n dans l'ordre du fichier).
func numerosDansLOrdre(ids []string, prefixe string) error {
	for i, id := range ids {
		if id != fmt.Sprintf("%s%d", prefixe, i+1) {
			return fmt.Errorf("%s à la position %d, %s%d attendu (numérotation 1 à n dans l'ordre du fichier)", id, i+1, prefixe, i+1)
		}
	}
	return nil
}

// numerosSansTrou dit si les identifiants préfixe-n sont uniques et
// couvrent exactement 1 à n, quel que soit leur ordre (RV-2).
func numerosSansTrou(ids []string, prefixe string) error {
	vus := map[int]bool{}
	for _, id := range ids {
		n, err := strconv.Atoi(strings.TrimPrefix(id, prefixe))
		if !strings.HasPrefix(id, prefixe) || err != nil || n < 1 {
			return fmt.Errorf("identifiant %q", id)
		}
		if vus[n] {
			return fmt.Errorf("identifiant %s en double", id)
		}
		vus[n] = true
	}
	for n := 1; n <= len(ids); n++ {
		if !vus[n] {
			return fmt.Errorf("%s%d manquant (numérotation avec un trou)", prefixe, n)
		}
	}
	return nil
}

// VerifierMatrice rend, pour chaque MX- exécutée, la liste de ses échecs.
func VerifierMatrice(m *Value, sch *Schema, ctx *ContexteMatrice) map[string][]string {
	out := map[string][]string{}
	ajout := func(id, format string, args ...any) {
		out[id] = append(out[id], fmt.Sprintf(format, args...))
	}
	// MX-1 : schéma.
	for _, x := range sch.Valider(m) {
		ajout("MX-1", "%s", x)
	}
	textes := map[string]*Value{}
	var idsT, idsMC, idsCL, idsL []string
	for _, t := range m.Get("texts").Arr {
		idsT = append(idsT, t.Get("id").Chaine())
		textes[t.Get("id").Chaine()] = t
	}
	for _, l := range m.Get("rows").Arr {
		idsMC = append(idsMC, l.Get("id").Chaine())
	}
	for _, c := range m.Get("clauses").Arr {
		idsCL = append(idsCL, c.Get("id").Chaine())
	}
	for _, g := range m.Get("gaps").Arr {
		idsL = append(idsL, g.Get("id").Chaine())
	}
	// MX-2 : identifiants, textes des lignes, champs recopiés du texte.
	for _, x := range []struct {
		ids []string
		p   string
	}{{idsT, "T-"}, {idsMC, "MC-"}, {idsCL, "CL-"}, {idsL, "L-"}} {
		if err := numerosDansLOrdre(x.ids, x.p); err != nil {
			ajout("MX-2", "%v", err)
		}
	}
	for _, l := range m.Get("rows").Arr {
		id := l.Get("id").Chaine()
		t := textes[l.Get("text").Chaine()]
		if t == nil {
			ajout("MX-2", "%s : texte %s inexistant", id, l.Get("text").Chaine())
			continue
		}
		if l.Get("source_url").Chaine() != t.Get("url").Chaine() {
			ajout("MX-2", "%s : source_url ≠ url de %s", id, t.Get("id").Chaine())
		}
		if l.Get("read_on").Chaine() != t.Get("read_on").Chaine() {
			ajout("MX-2", "%s : read_on ≠ read_on de %s", id, t.Get("id").Chaine())
		}
		if l.Get("applicability").Chaine() != t.Chemin("applicability", "status").Chaine() {
			ajout("MX-2", "%s : applicability ≠ applicability.status de %s", id, t.Get("id").Chaine())
		}
	}
	// MX-3 : statut dérivé.
	for _, l := range m.Get("rows").Arr {
		if d := StatutDerive(l); d != l.Get("status").Chaine() {
			ajout("MX-3", "%s : statut %s, recalculé %s (EX-8.3)", l.Get("id").Chaine(), l.Get("status").Chaine(), d)
		}
	}
	// MX-5 : clauses.
	sert := map[string][]string{}
	for _, l := range m.Get("rows").Arr {
		cites := map[string]bool{}
		for _, e := range l.Get("elements").Arr {
			for _, p := range e.Get("pieces").Arr {
				if p.Get("kind").Chaine() == "clause" {
					cites[p.Get("ref").Chaine()] = true
				}
			}
		}
		for c := range cites {
			sert[c] = append(sert[c], l.Get("id").Chaine())
		}
	}
	parID := map[string]*Value{}
	for _, c := range m.Get("clauses").Arr {
		id := c.Get("id").Chaine()
		parID[id] = c
		var declares []string
		for _, s := range c.Get("serves").Arr {
			declares = append(declares, s.Chaine())
		}
		if Liste(declares) != Liste(sert[id]) {
			ajout("MX-5", "%s : serves %s, lignes qui la citent %s", id, Liste(declares), Liste(sert[id]))
		}
		if len(sert[id]) == 0 {
			ajout("MX-5", "%s ne sert aucune ligne", id)
		}
	}
	var sousSections []string
	for id := range ctx.Clauses {
		sousSections = append(sousSections, id)
	}
	sort.Strings(sousSections)
	for _, id := range sousSections {
		c := parID[id]
		if c == nil {
			ajout("MX-5", "sous-section %s de l'annexe C sans clause", id)
		} else if c.Get("title").Chaine() != ctx.Clauses[id] {
			ajout("MX-5", "%s : titre %q ≠ titre de la sous-section %q", id, c.Get("title").Chaine(), ctx.Clauses[id])
		}
	}
	// MX-9 : textes pas encore applicables datés ; faits de l'annexe B.
	date := m.Get("date").Chaine()
	for _, t := range m.Get("texts").Arr {
		if t.Chemin("applicability", "status").Chaine() != "pas_encore_applicable" {
			continue
		}
		// Au moins une date from, et toutes postérieures à date (MX-9).
		dates := t.Chemin("applicability", "from").Arr
		toutes := len(dates) > 0
		for _, f := range dates {
			toutes = toutes && f.Get("date").Chaine() > date
		}
		if !toutes {
			ajout("MX-9", "%s pas_encore_applicable sans date from, ou avec une date from qui n'est pas postérieure à %s", t.Get("id").Chaine(), date)
		}
	}
	for _, l := range m.Get("rows").Arr {
		for _, f := range l.Get("facts").Arr {
			if !ctx.Faits[f.Chaine()] {
				ajout("MX-9", "%s : fait %s absent des tables de l'annexe B", l.Get("id").Chaine(), f.Chaine())
			}
		}
	}
	return out
}
