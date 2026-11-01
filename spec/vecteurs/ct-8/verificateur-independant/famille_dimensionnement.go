// Famille « dimensionnement » (CT-8 §9, annexe A.5, EX-A.22) : l'exemple
// de 9.5 recalculé et égal à la sortie imprimée ; chaque cas de
// spec/vecteurs/ct-8/dimensionnement recalculé depuis ses `entrees` et
// confronté à `attendu`, nombre par nombre à l'égalité exacte ; la table de
// 9.6 relue et confrontée aux sorties recalculées.

package main

import (
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// ValeurSortieDim rend une sortie sous forme de valeur JSON, membres dans
// l'ordre de la sortie imprimée en 9.5.
func ValeurSortieDim(s SortieDim) *Value {
	if !s.Valide {
		errs := VArr()
		for _, e := range s.Erreurs {
			errs.Arr = append(errs.Arr, VObj("journal", VStr(e.Journal), "code", VStr(e.Code)))
		}
		return VObj("version", VInt(0), "valid", VBool(false), "errors", errs)
	}
	champ := func(c Champ) *Value {
		switch {
		case c.Null:
			return VNull()
		case c.Bool != nil:
			return VBool(*c.Bool)
		case c.Str != nil:
			return VStr(*c.Str)
		}
		return VNum(c.Nombre)
	}
	js := VArr()
	for _, j := range s.Journaux {
		o := VObj()
		for _, c := range j {
			o.Obj = append(o.Obj, Membre{Cle: c.Nom, Val: champ(c)})
		}
		js.Arr = append(js.Arr, o)
	}
	t := VObj()
	for _, c := range s.Totaux {
		t.Obj = append(t.Obj, Membre{Cle: c.Nom, Val: champ(c)})
	}
	return VObj("version", VInt(0), "valid", VBool(true), "journals", js, "totals", t)
}

func totalDim(s SortieDim, nom string) float64 {
	for _, c := range s.Totaux {
		if c.Nom == nom {
			return c.Nombre
		}
	}
	return math.NaN()
}

func journalDim(s SortieDim, i int, nom string) float64 {
	for _, c := range s.Journaux[i] {
		if c.Nom == nom {
			return c.Nombre
		}
	}
	return math.NaN()
}

// nombreFr lit un nombre écrit à la française (« 390 925,968 »).
func nombreFr(s string) (float64, error) {
	s = strings.ReplaceAll(strings.TrimSpace(s), " ", "")
	return strconv.ParseFloat(strings.ReplaceAll(s, ",", "."), 64)
}

// gio rend des octets en Gio, arrondis à trois décimales.
func enGio(o float64) float64 { return math.Round(o/gio*1000) / 1000 }

var reCode = regexp.MustCompile("`([a-z0-9_]+)`")

// FamilleDimensionnement recalcule l'exemple de 9.5 et chaque cas.
func FamilleDimensionnement(c *Contexte) {
	const f = "dimensionnement"
	coef, err := LireCoefficients(c.Texte)
	if err != nil {
		c.Rap.Erreur("%v", err)
		return
	}
	// Exemple de 9.5.
	sec, err := c.Texte.Section("### 9.5 ")
	if err != nil {
		c.Rap.Erreur("%v", err)
		return
	}
	be, err1 := BlocApres(sec, "<!-- schema: dimensionnement -->")
	bs, err2 := BlocApres(sec, "<!-- schema: dimensionnement/sorties -->")
	if err1 != nil || err2 != nil {
		c.Rap.Erreur("9.5 : blocs d'exemple introuvables")
		return
	}
	ex, err1 := AnalyserJSON([]byte(be))
	exs, err2 := AnalyserJSON([]byte(bs))
	if err1 != nil || err2 != nil {
		c.Rap.Erreur("9.5 : exemple illisible (%v, %v)", err1, err2)
		return
	}
	c.ValiderSchema(f, "exemple 9.5", "dimensionnement-v0", "", ex)
	c.ValiderSchema(f, "exemple 9.5", "dimensionnement-v0", "#/$defs/sorties", exs)
	sortieEx := Dimensionner(ex, coef)
	ComparerSortieDim(c.Rap, f, "exemple 9.5", sortieEx, exs)
	t1, _ := Stringify2(ValeurSortieDim(sortieEx))
	t2, _ := Stringify2(exs)
	c.Rap.Comparer(f, "exemple 9.5", "sortie entière (JSON.stringify)", t2, t1)
	c.Rap.Comparer(f, "exemple 9.5", "J × 63 transactions par heure, capacité 253 440 (EX-9.2, lecture)", "63 ; 253440",
		NombreES6(totalDim(sortieEx, "registry_tx_per_hour_max"))+" ; "+NombreES6(totalDim(sortieEx, "registry_capacity_tx_per_hour")))

	// Cas de la famille.
	rep := c.Chemin("dimensionnement")
	sorties := map[string]SortieDim{}
	var noms []string
	for _, nf := range Fichiers(rep, ".json") {
		cas := strings.TrimSuffix(nf, ".json")
		noms = append(noms, cas)
		v, b, ok := c.LireJSON(filepath.Join(rep, nf))
		if !ok {
			continue
		}
		c.Forme(f, cas, b)
		c.ValiderSchema(f, cas, "dimensionnement-v0", "#/$defs/cas", v)
		s := Dimensionner(v.Get("entrees"), coef)
		sorties[cas] = s
		ComparerSortieDim(c.Rap, f, cas, s, v.Get("attendu"))
		if cas == "reference" {
			c.Rap.Constater(f, cas, "entrées égales à l'exemple de 9.5", Egales(v.Get("entrees"), ex), "")
		}
	}

	// Table de 9.6.
	sec6, err := c.Texte.Section("### 9.6 ")
	if err != nil {
		c.Rap.Erreur("%v", err)
		return
	}
	tab, err := TableEntete(sec6, "Cas", "Variation")
	if err != nil {
		c.Rap.Erreur("9.6 : %v", err)
		return
	}
	var dansTable []string
	for _, l := range tab.Lignes {
		cas := SansCode(l[0])
		dansTable = append(dansTable, cas)
		s, ok := sorties[cas]
		if !ok {
			c.Rap.Comparer(f, cas, "cas de la table de 9.6 présent", "présent", "absent")
			continue
		}
		if strings.HasPrefix(l[2], "refus") {
			var att, obt []string
			for _, m := range reCode.FindAllStringSubmatch(l[2], -1) {
				att = append(att, m[1])
			}
			for _, e := range s.Erreurs {
				obt = append(obt, e.Code)
			}
			c.Rap.Comparer(f, cas, "9.6 : refus", Liste(att), Liste(obt))
			continue
		}
		if !s.Valide {
			c.Rap.Comparer(f, cas, "9.6 : calcul fait", "valide", "refus")
			continue
		}
		cmpGio := func(col int, nom string) {
			x, err := nombreFr(l[col])
			got := enGio(totalDim(s, nom))
			if err == nil && x == got {
				c.Rap.Comparer(f, cas, "9.6 : "+nom+" (Gio)", l[col], l[col])
			} else {
				c.Rap.Comparer(f, cas, "9.6 : "+nom+" (Gio)", l[col], strconv.FormatFloat(got, 'f', 3, 64))
			}
		}
		cmpGio(2, "local_bytes")
		cmpGio(3, "worm_bytes")
		jet := strings.Split(l[4], "/")
		q, e1 := nombreFr(jet[0])
		o, e2 := nombreFr(jet[len(jet)-1])
		c.Rap.Comparer(f, cas, "9.6 : jetons qualifiés / autres", l[4],
			ifElse(e1 == nil && e2 == nil && q == totalDim(s, "tokens_qualified_per_year") && o == totalDim(s, "tokens_other_per_year"), l[4],
				fmt.Sprintf("%v / %v", totalDim(s, "tokens_qualified_per_year"), totalDim(s, "tokens_other_per_year"))))
		parts := strings.Split(l[5], ";")
		tx, e1 := nombreFr(parts[0])
		part, e2 := nombreFr(parts[1])
		okTx := e1 == nil && e2 == nil && tx == totalDim(s, "registry_tx_per_hour_max") && part == totalDim(s, "registry_capacity_share")
		c.Rap.Comparer(f, cas, "9.6 : transactions par heure ; part", strings.Join(parts[:2], ";"),
			ifElse(okTx, strings.Join(parts[:2], ";"), fmt.Sprintf("%v ; %v", totalDim(s, "registry_tx_per_hour_max"), totalDim(s, "registry_capacity_share"))))
		for _, p := range parts[2:] {
			p = strings.TrimSpace(p)
			switch {
			case strings.HasPrefix(p, "pointe "):
				champs := strings.Fields(p)
				v, err := nombreFr(champs[1])
				got := journalDim(s, 0, "peak_events_per_s")
				c.Rap.Comparer(f, cas, "9.6 : pointe", p, ifElse(err == nil && v == got && journalOui(s, "peak_over_target"), p, fmt.Sprintf("pointe %v", got)))
			case strings.Contains(p, "J_max"):
				i := strings.LastIndex(p, "=")
				v, err := nombreFr(p[i+1:])
				got := journalDim(s, 0, "registry_journals_max")
				c.Rap.Comparer(f, cas, "9.6 : J_max", p, ifElse(err == nil && v == got, p, fmt.Sprintf("J_max = %v", got)))
			default:
				c.Rap.Erreur("9.6 : cellule %q non lue", p)
			}
		}
	}
	c.Rap.Comparer(f, "ct-8/dimensionnement", "cas des fichiers = cas de la table de 9.6 (A.5 : quinze cas)", Liste(dansTable), Liste(trierCas(noms, dansTable)))
}

func journalOui(s SortieDim, nom string) bool {
	for _, c := range s.Journaux[0] {
		if c.Nom == nom && c.Bool != nil {
			return *c.Bool
		}
	}
	return false
}

func ifElse(b bool, x, y string) string {
	if b {
		return x
	}
	return y
}

// trierCas rend les noms dans l'ordre d'une référence, puis les autres.
func trierCas(noms, ordre []string) []string {
	vus := map[string]bool{}
	for _, n := range noms {
		vus[n] = true
	}
	var out []string
	for _, n := range ordre {
		if vus[n] {
			out = append(out, n)
			delete(vus, n)
		}
	}
	for _, n := range noms {
		if vus[n] {
			out = append(out, n)
		}
	}
	return out
}
