// Rapport : décompte par famille des valeurs recalculées, concordantes,
// discordantes et hors périmètre ; chaque discordance avec l'attendu, la
// valeur recalculée et la phrase de la spécification qui fonde le calcul.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Discordance est une valeur recalculée différente de l'attendu.
type Discordance struct {
	Famille   string `json:"family"`
	Cas       string `json:"case"`
	Valeur    string `json:"value"`
	Attendu   string `json:"expected"`
	Recalcule string `json:"recomputed"`
	Regle     string `json:"rule"`
}

// HorsPerimetre est une valeur des vecteurs que la spécification ne permet
// pas de recalculer, avec sa raison.
type HorsPerimetre struct {
	Famille string `json:"family"`
	Cas     string `json:"case"`
	Valeur  string `json:"value"`
	Raison  string `json:"reason"`
}

// Famille porte le décompte d'une famille.
type Famille struct {
	Nom          string          `json:"family"`
	Recalculees  int             `json:"recomputed"`
	Concordantes int             `json:"matching"`
	Discordantes int             `json:"mismatching"`
	NbHors       int             `json:"out_of_scope"`
	Discordances []Discordance   `json:"mismatches"`
	ListeHors    []HorsPerimetre `json:"out_of_scope_values"`
	Concordances []string        `json:"-"`
	Cas          int             `json:"cases"`
	casVus       map[string]bool `json:"-"`
}

// Rapport est le rapport complet.
type Rapport struct {
	Racine   string     `json:"root"`
	Familles []*Famille `json:"families"`
	index    map[string]*Famille
}

// NouveauRapport crée un rapport vide.
func NouveauRapport(racine string) *Rapport {
	return &Rapport{Racine: racine, index: map[string]*Famille{}}
}

// F rend la famille de ce nom, créée au besoin.
func (r *Rapport) F(nom string) *Famille {
	if f, ok := r.index[nom]; ok {
		return f
	}
	f := &Famille{Nom: nom, casVus: map[string]bool{}}
	r.index[nom] = f
	r.Familles = append(r.Familles, f)
	return f
}

func (f *Famille) vu(cas string) {
	if !f.casVus[cas] {
		f.casVus[cas] = true
		f.Cas++
	}
}

// Comparer confronte une valeur recalculée à l'attendu.
func (f *Famille) Comparer(cas, valeur, attendu, recalcule, regle string) bool {
	f.vu(cas)
	f.Recalculees++
	if attendu == recalcule {
		f.Concordantes++
		f.Concordances = append(f.Concordances, fmt.Sprintf("%s : %s = %s", cas, valeur, abreger(recalcule)))
		return true
	}
	f.Discordantes++
	f.Discordances = append(f.Discordances, Discordance{f.Nom, cas, valeur, attendu, recalcule, Phrase(regle)})
	return false
}

// Vrai confronte une propriété qui doit être vraie (attendu « vrai »).
func (f *Famille) Vrai(cas, valeur string, ok bool, detail, regle string) bool {
	rec := "vrai"
	if !ok {
		rec = "faux"
		if detail != "" {
			rec += " (" + detail + ")"
		}
	}
	return f.Comparer(cas, valeur, "vrai", rec, regle)
}

// Hors consigne une valeur hors périmètre.
func (f *Famille) Hors(cas, valeur, raison string) {
	f.vu(cas)
	f.NbHors++
	f.ListeHors = append(f.ListeHors, HorsPerimetre{f.Nom, cas, valeur, raison})
}

// Erreur consigne une impossibilité de recalcul (fichier illisible…) comme
// une discordance.
func (f *Famille) Erreur(cas, valeur string, err error, regle string) {
	f.Comparer(cas, valeur, "lisible", "erreur : "+err.Error(), regle)
}

func abreger(s string) string {
	if len(s) > 90 {
		return s[:60] + "…" + s[len(s)-20:]
	}
	return s
}

// ToutConcorde dit si aucune discordance n'a été trouvée.
func (r *Rapport) ToutConcorde() bool {
	for _, f := range r.Familles {
		if f.Discordantes > 0 {
			return false
		}
	}
	return true
}

// Totaux rend les totaux du rapport.
func (r *Rapport) Totaux() (rec, conc, disc, hors, cas int) {
	for _, f := range r.Familles {
		rec += f.Recalculees
		conc += f.Concordantes
		disc += f.Discordantes
		hors += f.NbHors
		cas += f.Cas
	}
	return
}

// EcrireTexte écrit le rapport lisible.
func (r *Rapport) EcrireTexte(w io.Writer, verbeux bool) {
	fmt.Fprintf(w, "Vérificateur indépendant CT-4 (Go) : vecteurs de %s\n\n", r.Racine)
	fmt.Fprintf(w, "%-14s %6s %11s %12s %12s %13s\n", "famille", "cas", "recalculées", "concordantes", "discordantes", "hors périmètre")
	for _, f := range r.Familles {
		fmt.Fprintf(w, "%-14s %6d %11d %12d %12d %13d\n", f.Nom, f.Cas, f.Recalculees, f.Concordantes, f.Discordantes, f.NbHors)
	}
	rec, conc, disc, hors, cas := r.Totaux()
	fmt.Fprintf(w, "%-14s %6d %11d %12d %12d %13d\n\n", "total", cas, rec, conc, disc, hors)
	if verbeux {
		for _, f := range r.Familles {
			for _, c := range f.Concordances {
				fmt.Fprintf(w, "  [%s] concorde : %s\n", f.Nom, c)
			}
		}
		fmt.Fprintln(w)
	}
	if hors > 0 {
		fmt.Fprintln(w, "Hors périmètre (non comptées) :")
		raisons := map[string]int{}
		var ordre []string
		for _, f := range r.Familles {
			for _, h := range f.ListeHors {
				cle := f.Nom + " : " + h.Raison
				if raisons[cle] == 0 {
					ordre = append(ordre, cle)
				}
				raisons[cle]++
				if verbeux {
					fmt.Fprintf(w, "  [%s] %s, %s : %s\n", f.Nom, h.Cas, h.Valeur, h.Raison)
				}
			}
		}
		if !verbeux {
			for _, c := range ordre {
				fmt.Fprintf(w, "  %d × %s\n", raisons[c], c)
			}
		}
		fmt.Fprintln(w)
	}
	if r.ToutConcorde() {
		fmt.Fprintln(w, "Résultat : tout concorde.")
		return
	}
	fmt.Fprintf(w, "Résultat : %d discordance(s).\n", disc)
	for _, f := range r.Familles {
		for _, d := range f.Discordances {
			fmt.Fprintf(w, "\n- [%s] cas %s, %s\n    attendu   : %s\n    recalculé : %s\n    règle     : %s\n",
				d.Famille, d.Cas, d.Valeur, d.Attendu, d.Recalcule, d.Regle)
		}
	}
}

// EcrireJSON écrit le rapport en JSON.
func (r *Rapport) EcrireJSON(w io.Writer) error {
	rec, conc, disc, hors, cas := r.Totaux()
	sortie := struct {
		Version  int        `json:"version"`
		Racine   string     `json:"root"`
		Familles []*Famille `json:"families"`
		Total    any        `json:"total"`
		Resultat string     `json:"result"`
	}{0, r.Racine, r.Familles, map[string]int{"cases": cas, "recomputed": rec, "matching": conc, "mismatching": disc, "out_of_scope": hors}, "tout_concorde"}
	if !r.ToutConcorde() {
		sortie.Resultat = "discordances"
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(sortie)
}

// Phrase rend, pour un identifiant de règle, la règle suivie d'une
// citation de la spécification ; un texte libre est rendu tel quel.
func Phrase(regle string) string {
	if p, ok := phrases[regle]; ok {
		return regle + " : « " + p + " »"
	}
	if i := strings.Index(regle, " "); i > 0 {
		if p, ok := phrases[regle[:i]]; ok {
			return regle + " ; " + regle[:i] + " : « " + p + " »"
		}
	}
	return regle
}
