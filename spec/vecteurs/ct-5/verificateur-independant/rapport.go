// Rapport de confrontation : chaque valeur attendue trouvée dans les vecteurs
// donne une comparaison (recalculée, concordante ou discordante). Même forme
// que le rapport du vérificateur de CT-1.

package main

import (
	"encoding/json"
	"fmt"
	"io"
)

// Comparaison est une valeur attendue confrontée à une valeur recalculée.
// HorsPerimetre marque une valeur que ce vérificateur ne recalcule pas (le
// verdict d'un outil tiers, confrontation/) : ni concordante ni discordante.
type Comparaison struct {
	Famille       string `json:"famille"`
	Vecteur       string `json:"vecteur"`
	Grandeur      string `json:"grandeur"`
	Attendu       string `json:"attendu"`
	Obtenu        string `json:"obtenu"`
	Concorde      bool   `json:"concorde"`
	HorsPerimetre bool   `json:"hors_perimetre,omitempty"`
	Note          string `json:"note,omitempty"`
}

// Rapport accumule les comparaisons, les erreurs (fichiers illisibles,
// dispositions non reconnues) et les notes.
type Rapport struct {
	Racine       string        `json:"racine"`
	Comparaisons []Comparaison `json:"comparaisons"`
	Erreurs      []string      `json:"erreurs"`
	Notes        []string      `json:"notes"`
	Details      []string      `json:"details"`
}

// Comparer enregistre une comparaison et rend sa concordance.
func (r *Rapport) Comparer(famille, vecteur, grandeur, attendu, obtenu string) bool {
	c := Comparaison{Famille: famille, Vecteur: vecteur, Grandeur: grandeur, Attendu: attendu, Obtenu: obtenu, Concorde: attendu == obtenu}
	r.Comparaisons = append(r.Comparaisons, c)
	return c.Concorde
}

// ComparerValeurs confronte deux valeurs JSON par leur rendu compact trié.
func (r *Rapport) ComparerValeurs(famille, vecteur, grandeur string, attendu, obtenu *Value) bool {
	return r.Comparer(famille, vecteur, grandeur, Rendu(attendu), Rendu(obtenu))
}

// HorsPerimetre enregistre une valeur attendue que ce vérificateur ne
// recalcule pas.
func (r *Rapport) HorsPerimetre(famille, vecteur, grandeur, attendu, note string) {
	r.Comparaisons = append(r.Comparaisons, Comparaison{Famille: famille, Vecteur: vecteur, Grandeur: grandeur, Attendu: attendu, Obtenu: "(non recalculé)", HorsPerimetre: true, Note: note})
}

// Erreur consigne une erreur qui rend le résultat non concluant.
func (r *Rapport) Erreur(format string, args ...any) {
	r.Erreurs = append(r.Erreurs, fmt.Sprintf(format, args...))
}

// Note consigne une information sans effet sur le code de retour.
func (r *Rapport) Note(format string, args ...any) {
	r.Notes = append(r.Notes, fmt.Sprintf(format, args...))
}

// Detail consigne une ligne de détail.
func (r *Rapport) Detail(format string, args ...any) {
	r.Details = append(r.Details, fmt.Sprintf(format, args...))
}

// Comptes rend (recalculées, concordantes, discordantes, hors périmètre).
func (r *Rapport) Comptes() (int, int, int, int) {
	c, hp := 0, 0
	for _, x := range r.Comparaisons {
		switch {
		case x.HorsPerimetre:
			hp++
		case x.Concorde:
			c++
		}
	}
	return len(r.Comparaisons), c, len(r.Comparaisons) - c - hp, hp
}

// ToutConcorde dit si le code de retour doit être 0 : aucune discordance et
// aucune erreur.
func (r *Rapport) ToutConcorde() bool {
	_, _, d, _ := r.Comptes()
	return d == 0 && len(r.Erreurs) == 0
}

// EcrireTexte imprime le rapport en français.
func (r *Rapport) EcrireTexte(w io.Writer, verbeux bool) {
	fmt.Fprintf(w, "Vérificateur indépendant CT-5 (Go, salle blanche) — racine des vecteurs : %s\n\n", r.Racine)
	familles := map[string][]Comparaison{}
	var ordre []string
	for _, c := range r.Comparaisons {
		if _, ok := familles[c.Famille]; !ok {
			ordre = append(ordre, c.Famille)
		}
		familles[c.Famille] = append(familles[c.Famille], c)
	}
	for _, f := range ordre {
		cs := familles[f]
		ok, hp := 0, 0
		for _, c := range cs {
			switch {
			case c.HorsPerimetre:
				hp++
			case c.Concorde:
				ok++
			}
		}
		fmt.Fprintf(w, "Famille %s : %d valeur(s) recalculée(s), %d concordante(s), %d discordante(s)", f, len(cs), ok, len(cs)-ok-hp)
		if hp > 0 {
			fmt.Fprintf(w, ", %d hors périmètre", hp)
		}
		fmt.Fprintln(w)
		for _, c := range cs {
			if (c.Concorde || c.HorsPerimetre) && !verbeux {
				continue
			}
			marque := "  ✓"
			if c.HorsPerimetre {
				marque = "  ~"
			} else if !c.Concorde {
				marque = "  ✗"
			}
			fmt.Fprintf(w, "%s %s · %s\n", marque, c.Vecteur, c.Grandeur)
			if !c.Concorde || verbeux {
				fmt.Fprintf(w, "      attendu : %s\n      obtenu  : %s\n", c.Attendu, c.Obtenu)
			}
			if c.Note != "" {
				fmt.Fprintf(w, "      note    : %s\n", c.Note)
			}
		}
	}
	if len(r.Details) > 0 && verbeux {
		fmt.Fprintln(w, "\nDétails :")
		for _, d := range r.Details {
			fmt.Fprintln(w, d)
		}
	}
	if len(r.Notes) > 0 {
		fmt.Fprintln(w, "\nNotes :")
		for _, n := range r.Notes {
			fmt.Fprintf(w, "  - %s\n", n)
		}
	}
	if len(r.Erreurs) > 0 {
		fmt.Fprintln(w, "\nErreurs :")
		for _, e := range r.Erreurs {
			fmt.Fprintf(w, "  ! %s\n", e)
		}
	}
	t, c, d, hp := r.Comptes()
	fmt.Fprintf(w, "\nTotal : %d valeur(s) recalculée(s), %d concordante(s), %d discordante(s), %d hors périmètre, %d erreur(s)\n", t, c, d, hp, len(r.Erreurs))
	if r.ToutConcorde() {
		fmt.Fprintln(w, "Résultat : tout concorde.")
		if hp > 0 {
			fmt.Fprintln(w, "Les valeurs hors périmètre (verdicts d'outils tiers) ne sont pas recalculées par ce vérificateur : elles relèvent de confrontation/.")
		}
	} else {
		fmt.Fprintln(w, "Résultat : DISCORDANCE ou erreur.")
	}
}

// EcrireJSON imprime le rapport en JSON (sortie de rapport, pas une forme
// canonique : encoding/json convient ici).
func (r *Rapport) EcrireJSON(w io.Writer) error {
	t, c, d, hp := r.Comptes()
	sortie := struct {
		*Rapport
		Recalculees   int  `json:"recalculees"`
		Concordantes  int  `json:"concordantes"`
		Discordantes  int  `json:"discordantes"`
		HorsPerimetre int  `json:"hors_perimetre"`
		ToutConcorde  bool `json:"tout_concorde"`
	}{r, t, c, d, hp, r.ToutConcorde()}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sortie)
}
