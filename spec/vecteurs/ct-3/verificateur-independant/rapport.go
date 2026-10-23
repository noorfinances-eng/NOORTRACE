// Rapport de confrontation : chaque valeur attendue des vecteurs est
// confrontée à la valeur recalculée (concordante ou discordante) ; une
// valeur que ce vérificateur ne recalcule pas est comptée « hors
// périmètre », avec sa raison.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Comparaison est une valeur attendue confrontée à une valeur recalculée.
type Comparaison struct {
	Famille       string `json:"famille"`
	Vecteur       string `json:"vecteur"`
	Grandeur      string `json:"grandeur"`
	Attendu       string `json:"attendu"`
	Obtenu        string `json:"obtenu"`
	Concorde      bool   `json:"concorde"`
	HorsPerimetre bool   `json:"hors_perimetre,omitempty"`
	Fondement     string `json:"fondement,omitempty"`
}

// Rapport accumule comparaisons, erreurs et notes.
type Rapport struct {
	Racine       string        `json:"racine"`
	Familles     []string      `json:"familles"`
	Comparaisons []Comparaison `json:"comparaisons"`
	Erreurs      []string      `json:"erreurs"`
	Notes        []string      `json:"notes"`
}

// NouveauRapport crée un rapport dont les familles sont imprimées dans
// l'ordre donné.
func NouveauRapport(racine string, familles ...string) *Rapport {
	return &Rapport{Racine: racine, Familles: familles, Comparaisons: []Comparaison{}, Erreurs: []string{}, Notes: []string{}}
}

// Comparer enregistre une comparaison de deux écritures et rend sa
// concordance. fondement cite la règle de la spécification qui fonde le
// calcul (rapportée avec une discordance).
func (r *Rapport) Comparer(famille, vecteur, grandeur, attendu, obtenu, fondement string) bool {
	c := Comparaison{Famille: famille, Vecteur: vecteur, Grandeur: grandeur, Attendu: attendu, Obtenu: obtenu, Concorde: attendu == obtenu, Fondement: fondement}
	r.Comparaisons = append(r.Comparaisons, c)
	return c.Concorde
}

// ComparerJSON confronte deux valeurs JSON (ordre des membres indifférent).
func (r *Rapport) ComparerJSON(famille, vecteur, grandeur string, attendu, obtenu *Value, fondement string) bool {
	c := Comparaison{Famille: famille, Vecteur: vecteur, Grandeur: grandeur, Attendu: Compact(attendu), Obtenu: Compact(obtenu), Concorde: EgalJSON(attendu, obtenu), Fondement: fondement}
	r.Comparaisons = append(r.Comparaisons, c)
	return c.Concorde
}

// Exiger enregistre une propriété que la spécification impose (attendu :
// l'énoncé de la propriété ; obtenu : le constat).
func (r *Rapport) Exiger(famille, vecteur, grandeur string, ok bool, constat, fondement string) bool {
	att := "vrai"
	obt := "vrai"
	if !ok {
		obt = "faux : " + constat
	}
	c := Comparaison{Famille: famille, Vecteur: vecteur, Grandeur: grandeur, Attendu: att, Obtenu: obt, Concorde: ok, Fondement: fondement}
	r.Comparaisons = append(r.Comparaisons, c)
	return ok
}

// HorsPerimetre enregistre une valeur non recalculée, avec sa raison.
func (r *Rapport) HorsPerimetre(famille, vecteur, grandeur, raison string) {
	r.Comparaisons = append(r.Comparaisons, Comparaison{Famille: famille, Vecteur: vecteur, Grandeur: grandeur, HorsPerimetre: true, Obtenu: raison})
}

// Erreur consigne une erreur (fichier absent ou illisible) : le résultat
// n'est pas concluant.
func (r *Rapport) Erreur(format string, args ...any) {
	r.Erreurs = append(r.Erreurs, fmt.Sprintf(format, args...))
}

// Note consigne une information sans effet sur le code de retour.
func (r *Rapport) Note(format string, args ...any) {
	r.Notes = append(r.Notes, fmt.Sprintf(format, args...))
}

// Comptes rend, pour une famille (« » : toutes), (recalculées,
// concordantes, discordantes, hors périmètre).
func (r *Rapport) Comptes(famille string) (int, int, int, int) {
	rec, con, dis, hp := 0, 0, 0, 0
	for _, c := range r.Comparaisons {
		if famille != "" && c.Famille != famille {
			continue
		}
		switch {
		case c.HorsPerimetre:
			hp++
		case c.Concorde:
			rec++
			con++
		default:
			rec++
			dis++
		}
	}
	return rec, con, dis, hp
}

// ToutConcorde dit si aucune discordance ni erreur n'a été relevée.
func (r *Rapport) ToutConcorde() bool {
	_, _, d, _ := r.Comptes("")
	return d == 0 && len(r.Erreurs) == 0
}

// EcrireTexte imprime le rapport.
func (r *Rapport) EcrireTexte(w io.Writer, verbeux bool) {
	fmt.Fprintf(w, "Vérificateur indépendant CT-3 (Go) — vecteurs : %s\n\n", r.Racine)
	fmt.Fprintf(w, "%-22s %11s %12s %12s %15s\n", "Famille", "recalculées", "concordantes", "discordantes", "hors périmètre")
	for _, f := range r.Familles {
		rec, con, dis, hp := r.Comptes(f)
		fmt.Fprintf(w, "%-22s %11d %12d %12d %15d\n", f, rec, con, dis, hp)
	}
	rec, con, dis, hp := r.Comptes("")
	fmt.Fprintf(w, "%-22s %11d %12d %12d %15d\n", "total", rec, con, dis, hp)
	if verbeux {
		fmt.Fprintln(w, "\nValeurs concordantes :")
		for _, c := range r.Comparaisons {
			if c.Concorde && !c.HorsPerimetre {
				fmt.Fprintf(w, "  [%s] %s — %s : %s\n", c.Famille, c.Vecteur, c.Grandeur, tronquer(c.Obtenu, 160))
			}
		}
	}
	premiere := true
	for _, c := range r.Comparaisons {
		if c.HorsPerimetre {
			if premiere {
				fmt.Fprintln(w, "\nHors périmètre (non recalculé) :")
				premiere = false
			}
			if verbeux {
				fmt.Fprintf(w, "  [%s] %s — %s : %s\n", c.Famille, c.Vecteur, c.Grandeur, c.Obtenu)
			}
		}
	}
	if !premiere && !verbeux {
		raisons := map[string]int{}
		exemple := map[string]string{}
		ordre := []string{}
		for _, c := range r.Comparaisons {
			if c.HorsPerimetre {
				cle := "[" + c.Famille + "] " + c.Grandeur + " : " + c.Obtenu
				if raisons[cle] == 0 {
					ordre = append(ordre, cle)
					exemple[cle] = c.Vecteur
				}
				raisons[cle]++
			}
		}
		for _, k := range ordre {
			if raisons[k] == 1 {
				fmt.Fprintf(w, "  %s (%s)\n", k, exemple[k])
			} else {
				fmt.Fprintf(w, "  %s (%d valeurs)\n", k, raisons[k])
			}
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
			fmt.Fprintf(w, "  - %s\n", e)
		}
	}
	if dis > 0 {
		fmt.Fprintln(w, "\nDiscordances :")
		for _, c := range r.Comparaisons {
			if !c.Concorde && !c.HorsPerimetre {
				fmt.Fprintf(w, "  [%s] %s — %s\n      attendu    : %s\n      recalculé  : %s\n", c.Famille, c.Vecteur, c.Grandeur, c.Attendu, c.Obtenu)
				if c.Fondement != "" {
					fmt.Fprintf(w, "      fondement  : %s\n", c.Fondement)
				}
			}
		}
	}
	if r.ToutConcorde() {
		fmt.Fprintln(w, "\nRésultat : tout concorde.")
	} else {
		fmt.Fprintf(w, "\nRésultat : %d discordance(s), %d erreur(s).\n", dis, len(r.Erreurs))
	}
}

// EcrireJSON écrit le rapport en JSON.
func (r *Rapport) EcrireJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func tronquer(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

// listeChaines écrit une liste de chaînes pour un rapport.
func listeChaines(ss []string) string { return "[" + strings.Join(ss, ", ") + "]" }
