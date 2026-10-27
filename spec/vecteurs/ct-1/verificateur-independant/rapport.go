// Rapport de confrontation : chaque valeur attendue trouvée dans les vecteurs
// donne une comparaison (recalculée, concordante ou discordante).

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Comparaison est une valeur attendue confrontée à une valeur recalculée.
// HorsPerimetre marque une valeur que ce vérificateur ne peut pas recalculer
// (contrôle E-9, signatures EIP-191 ; notions de CT-6 et de CT-7 portées
// par les attendus de la révision 0.4) : ni concordante ni discordante.
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

// ComparerAvecNote enregistre une comparaison dont la concordance est décidée
// par l'appelant (verdicts à ensembles de contrôles).
func (r *Rapport) ComparerAvecNote(famille, vecteur, grandeur, attendu, obtenu string, concorde bool, note string) bool {
	r.Comparaisons = append(r.Comparaisons, Comparaison{Famille: famille, Vecteur: vecteur, Grandeur: grandeur, Attendu: attendu, Obtenu: obtenu, Concorde: concorde, Note: note})
	return concorde
}

// Erreur consigne une erreur qui rend le résultat non concluant.
func (r *Rapport) Erreur(format string, args ...any) {
	r.Erreurs = append(r.Erreurs, fmt.Sprintf(format, args...))
}

// Note consigne une information sans effet sur le code de retour.
func (r *Rapport) Note(format string, args ...any) {
	r.Notes = append(r.Notes, fmt.Sprintf(format, args...))
}

// Detail consigne une ligne de détail (contrôles d'un dossier, bornes).
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
// aucune erreur. Les valeurs hors périmètre sont énoncées, pas comptées
// comme discordantes.
func (r *Rapport) ToutConcorde() bool {
	_, _, d, _ := r.Comptes()
	return d == 0 && len(r.Erreurs) == 0
}

// EcrireTexte imprime le rapport en français.
func (r *Rapport) EcrireTexte(w io.Writer, verbeux bool) {
	fmt.Fprintf(w, "Vérificateur indépendant CT-1 (Go, salle blanche) — racine des vecteurs : %s\n\n", r.Racine)
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
			if c.Concorde && !verbeux {
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
			fmt.Fprintln(w, "Les valeurs hors périmètre (signatures EIP-191 des approbateurs, contrôle 7 / E-9 ; vérification visée, attestation retenue et avertissements AV-AT- des dossiers de la révision 0.4, définis par CT-6 et CT-7) ne sont pas vérifiées par ce vérificateur et restent à confronter par l'implémentation de référence.")
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

// verdictTexte rend « valide » ou la liste triée des contrôles en échec.
func verdictTexte(echecs []string) string {
	if len(echecs) == 0 {
		return "valide"
	}
	ids := append([]string{}, echecs...)
	TrierControles(ids)
	return strings.Join(ids, ",")
}

// comparerVerdict confronte le verdict recalculé (ensemble des contrôles en
// échec) à l'attendu. Attendu « valide » : aucun échec. Attendu une liste de
// contrôles : chacun doit être en échec ; en mode strict, aucun autre. Les
// échecs supplémentaires hors mode strict sont rapportés en note, car la
// spécification admet les cascades (§11.5 : « E-7, puis C-2 sur next »). Un
// contrôle attendu que ce vérificateur déclare hors périmètre (E-9) rend la
// comparaison « hors périmètre », ni concordante ni discordante.
func comparerVerdict(rap *Rapport, famille, vecteur string, attenduValide bool, attendus []string, res *Resultats, strict bool) bool {
	echecs := res.Echecs()
	obtenu := verdictTexte(echecs)
	if attenduValide {
		return rap.ComparerAvecNote(famille, vecteur, "verdict", "valide", obtenu, len(echecs) == 0, "")
	}
	ids := append([]string{}, attendus...)
	TrierControles(ids)
	attendu := strings.Join(ids, ",")
	manquants := []string{}
	horsPerimetre := []string{}
	for _, a := range ids {
		if !dansEnum(a, echecs) {
			if c := res.parID[a]; (c != nil && c.Etat == EtatHorsPerimetre) || a == "E-9" {
				horsPerimetre = append(horsPerimetre, a)
				continue
			}
			manquants = append(manquants, a)
		}
	}
	if len(manquants) == 0 && len(horsPerimetre) > 0 {
		rap.Comparaisons = append(rap.Comparaisons, Comparaison{Famille: famille, Vecteur: vecteur, Grandeur: "verdict", Attendu: attendu, Obtenu: obtenu,
			HorsPerimetre: true, Note: "contrôle(s) hors périmètre de ce vérificateur (signatures EIP-191) : " + strings.Join(horsPerimetre, ",") + " ; non vérifiable ici"})
		return false
	}
	supplementaires := []string{}
	for _, e := range echecs {
		if !dansEnum(e, ids) {
			supplementaires = append(supplementaires, e)
		}
	}
	sort.Strings(supplementaires)
	concorde := len(manquants) == 0 && (!strict || len(supplementaires) == 0)
	note := ""
	if len(supplementaires) > 0 && len(manquants) == 0 && !strict {
		note = "échecs supplémentaires (cascade admise hors mode strict) : " + strings.Join(supplementaires, ",")
	}
	return rap.ComparerAvecNote(famille, vecteur, "verdict", attendu, obtenu, concorde, note)
}
