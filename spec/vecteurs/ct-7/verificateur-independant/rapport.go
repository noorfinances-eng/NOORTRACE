// Rapport de confrontation : chaque valeur attendue trouvée dans les
// vecteurs donne une comparaison (recalculée, concordante ou discordante) ;
// une valeur que ce module ne recalcule pas est rapportée « hors
// périmètre », avec sa raison, et ne compte ni comme concordante ni comme
// discordante.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Comparaison est la confrontation d'une valeur.
type Comparaison struct {
	Famille       string `json:"famille"`
	Vecteur       string `json:"vecteur"`
	Grandeur      string `json:"grandeur"`
	Attendu       string `json:"attendu"`
	Obtenu        string `json:"obtenu"`
	Concorde      bool   `json:"concorde"`
	HorsPerimetre bool   `json:"hors_perimetre,omitempty"`
}

// Rapport rassemble les comparaisons, les erreurs et les notes.
type Rapport struct {
	Racine       string        `json:"racine"`
	Comparaisons []Comparaison `json:"comparaisons"`
	Erreurs      []string      `json:"erreurs"`
	Notes        []string      `json:"notes"`
}

// NouveauRapport crée un rapport vide.
func NouveauRapport(racine string) *Rapport {
	return &Rapport{Racine: racine, Comparaisons: []Comparaison{}, Erreurs: []string{}, Notes: []string{}}
}

// Comparer consigne une valeur recalculée et la dit concordante si elle
// égale l'attendu.
func (r *Rapport) Comparer(famille, vecteur, grandeur, attendu, obtenu string) bool {
	c := Comparaison{famille, vecteur, grandeur, attendu, obtenu, attendu == obtenu, false}
	r.Comparaisons = append(r.Comparaisons, c)
	return c.Concorde
}

// Constater consigne une propriété recalculée (vrai attendu).
func (r *Rapport) Constater(famille, vecteur, grandeur string, ok bool, detail string) bool {
	obtenu := "oui"
	if !ok {
		obtenu = "non : " + detail
	}
	return r.Comparer(famille, vecteur, grandeur, "oui", obtenu)
}

// HorsPerimetre consigne une valeur que ce module ne recalcule pas.
func (r *Rapport) HorsPerimetre(famille, vecteur, grandeur, attendu, raison string) {
	r.Comparaisons = append(r.Comparaisons, Comparaison{famille, vecteur, grandeur, attendu, raison, false, true})
}

// Erreur consigne une erreur (fichier illisible, disposition inattendue).
func (r *Rapport) Erreur(format string, args ...any) {
	r.Erreurs = append(r.Erreurs, fmt.Sprintf(format, args...))
}

// Note consigne une remarque.
func (r *Rapport) Note(format string, args ...any) {
	r.Notes = append(r.Notes, fmt.Sprintf(format, args...))
}

// Comptes rend (recalculées, concordantes, discordantes, hors périmètre).
func (r *Rapport) Comptes() (int, int, int, int) {
	var t, c, d, h int
	for _, x := range r.Comparaisons {
		switch {
		case x.HorsPerimetre:
			h++
		case x.Concorde:
			t++
			c++
		default:
			t++
			d++
		}
	}
	return t, c, d, h
}

// ToutConcorde dit si aucune discordance ni erreur n'a été relevée.
func (r *Rapport) ToutConcorde() bool {
	_, _, d, _ := r.Comptes()
	return d == 0 && len(r.Erreurs) == 0
}

// EcrireTexte imprime le rapport lisible.
func (r *Rapport) EcrireTexte(w io.Writer, verbeux bool) {
	fmt.Fprintf(w, "Vérificateur indépendant CT-7 (Go, salle blanche) — racine des vecteurs : %s\n\n", r.Racine)
	familles := map[string][4]int{}
	var ordre []string
	for _, x := range r.Comparaisons {
		f, ok := familles[x.Famille]
		if !ok {
			ordre = append(ordre, x.Famille)
		}
		switch {
		case x.HorsPerimetre:
			f[3]++
		case x.Concorde:
			f[0]++
			f[1]++
		default:
			f[0]++
			f[2]++
		}
		familles[x.Famille] = f
	}
	fmt.Fprintf(w, "%-28s %10s %12s %12s %15s\n", "Famille", "recalculées", "concordantes", "discordantes", "hors périmètre")
	for _, f := range ordre {
		v := familles[f]
		fmt.Fprintf(w, "%-28s %10d %12d %12d %15d\n", f, v[0], v[1], v[2], v[3])
	}
	fmt.Fprintln(w)
	var disc []Comparaison
	for _, x := range r.Comparaisons {
		if !x.Concorde && !x.HorsPerimetre {
			disc = append(disc, x)
		}
	}
	if len(disc) > 0 {
		fmt.Fprintln(w, "Discordances :")
		for _, x := range disc {
			fmt.Fprintf(w, "  ✗ %s/%s · %s\n      attendu : %s\n      obtenu  : %s\n", x.Famille, x.Vecteur, x.Grandeur, x.Attendu, x.Obtenu)
		}
		fmt.Fprintln(w)
	}
	if verbeux {
		fmt.Fprintln(w, "Valeurs concordantes et hors périmètre :")
		for _, x := range r.Comparaisons {
			switch {
			case x.HorsPerimetre:
				fmt.Fprintf(w, "  ~ %s/%s · %s : %s (%s)\n", x.Famille, x.Vecteur, x.Grandeur, x.Attendu, x.Obtenu)
			case x.Concorde:
				fmt.Fprintf(w, "  ✓ %s/%s · %s = %s\n", x.Famille, x.Vecteur, x.Grandeur, abreger(x.Obtenu))
			}
		}
		fmt.Fprintln(w)
	}
	if len(r.Erreurs) > 0 {
		fmt.Fprintln(w, "Erreurs :")
		for _, e := range r.Erreurs {
			fmt.Fprintf(w, "  - %s\n", e)
		}
		fmt.Fprintln(w)
	}
	if len(r.Notes) > 0 {
		notes := append([]string(nil), r.Notes...)
		sort.Strings(notes)
		fmt.Fprintln(w, "Notes :")
		for _, n := range notes {
			fmt.Fprintf(w, "  - %s\n", n)
		}
		fmt.Fprintln(w)
	}
	t, c, d, h := r.Comptes()
	fmt.Fprintf(w, "Total : %d valeur(s) recalculée(s), %d concordante(s), %d discordante(s), %d hors périmètre, %d erreur(s)\n", t, c, d, h, len(r.Erreurs))
	if r.ToutConcorde() {
		fmt.Fprintln(w, "Résultat : tout concorde.")
		if h > 0 {
			fmt.Fprintln(w, "Les valeurs hors périmètre (vérifications que CT-7 EX-A.23 laisse au vérificateur de renvois, dérivations que le texte de CT-7 ne fixe pas : voir leur raison avec -v) ne sont pas recalculées par ce module.")
		}
	} else {
		fmt.Fprintln(w, "Résultat : DISCORDANCE ou erreur.")
	}
}

func abreger(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len([]rune(s)) > 100 {
		return string([]rune(s)[:97]) + "…"
	}
	return s
}

// EcrireJSON imprime le rapport en JSON.
func (r *Rapport) EcrireJSON(w io.Writer) error {
	t, c, d, h := r.Comptes()
	sortie := struct {
		*Rapport
		Total         int  `json:"recalculees"`
		Concordantes  int  `json:"concordantes"`
		Discordantes  int  `json:"discordantes"`
		HorsPerimetre int  `json:"hors_perimetre"`
		ToutConcorde  bool `json:"tout_concorde"`
	}{r, t, c, d, h, r.ToutConcorde()}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(sortie)
}

// Liste rend une liste de chaînes sous une forme comparable.
func Liste(xs []string) string {
	if len(xs) == 0 {
		return "[]"
	}
	return "[" + strings.Join(xs, ", ") + "]"
}
