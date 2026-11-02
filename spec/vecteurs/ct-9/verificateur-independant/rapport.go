package main

// Rapport du vérificateur : chaque valeur recalculée est un contrôle, dont
// le statut est « concordant », « discordant » ou « hors_perimetre » (avec
// sa raison). Le code de retour ne dépend que des discordances.

import (
	"encoding/json"
	"fmt"
	"io"
)

// Statuts d'un contrôle (valeurs énumérées, français sans accent).
const (
	Concordant    = "concordant"
	Discordant    = "discordant"
	HorsPerimetre = "hors_perimetre"
)

// Controle est une valeur recalculée et le résultat de sa confrontation.
type Controle struct {
	Statut string `json:"status"`
	Regle  string `json:"rule"`
	Objet  string `json:"object"`
	Detail string `json:"detail"`
}

// Comptes récapitule les nombres recalculés qui résument la couverture.
type Comptes struct {
	Entrees           int `json:"entries"`
	Identifiants      int `json:"identifiers"`
	CouvertsParEntree int `json:"covered_by_tests"`
	CouvertsParNC     int `json:"covered_by_nc"`
	NonCouverts       int `json:"uncovered"`
	Menaces           int `json:"threats"`
	MenacesAvecTA     int `json:"threats_with_ta"`
	Occurrences       int `json:"occurrences"`
	LignesTC          int `json:"traceability_rows"`
	Executables       int `json:"executable"`
	TitresCites       int `json:"titles_checked"`
	TablesComparees   int `json:"text_tables_compared"`
}

// Resume est le décompte des contrôles par statut.
type Resume struct {
	Total         int `json:"total"`
	Concordants   int `json:"consistent"`
	Discordants   int `json:"discordant"`
	HorsPerimetre int `json:"out_of_scope"`
}

// Rapport est la sortie du vérificateur.
type Rapport struct {
	Racine    string     `json:"root"`
	Comptes   Comptes    `json:"counts"`
	Resume    Resume     `json:"summary"`
	Controles []Controle `json:"checks"`
}

func (r *Rapport) ajouter(statut, regle, objet, format string, args ...any) {
	r.Controles = append(r.Controles, Controle{statut, regle, objet, fmt.Sprintf(format, args...)})
}

// Concorde enregistre une valeur recalculée égale à la valeur publiée.
func (r *Rapport) Concorde(regle, objet, format string, args ...any) {
	r.ajouter(Concordant, regle, objet, format, args...)
}

// Discorde enregistre une valeur recalculée différente de la valeur publiée.
func (r *Rapport) Discorde(regle, objet, format string, args ...any) {
	r.ajouter(Discordant, regle, objet, format, args...)
}

// HorsPerimetre enregistre une valeur publiée que le texte seul ne permet
// pas de recalculer, avec sa raison.
func (r *Rapport) HorsPerimetre(regle, objet, format string, args ...any) {
	r.ajouter(HorsPerimetre, regle, objet, format, args...)
}

// Verdict enregistre concordant ou discordant selon ok.
func (r *Rapport) Verdict(ok bool, regle, objet, format string, args ...any) {
	if ok {
		r.Concorde(regle, objet, format, args...)
	} else {
		r.Discorde(regle, objet, format, args...)
	}
}

// Discordances rend les contrôles discordants.
func (r *Rapport) Discordances() []Controle {
	var out []Controle
	for _, c := range r.Controles {
		if c.Statut == Discordant {
			out = append(out, c)
		}
	}
	return out
}

// Clore calcule le résumé.
func (r *Rapport) Clore() {
	r.Resume = Resume{Total: len(r.Controles)}
	for _, c := range r.Controles {
		switch c.Statut {
		case Concordant:
			r.Resume.Concordants++
		case Discordant:
			r.Resume.Discordants++
		default:
			r.Resume.HorsPerimetre++
		}
	}
}

func etiquette(statut string) string {
	switch statut {
	case Concordant:
		return "[OK]"
	case Discordant:
		return "[DISCORDANCE]"
	default:
		return "[HORS PÉRIMÈTRE]"
	}
}

// EcrireTexte imprime le rapport lisible ; en mode verbeux, chaque contrôle
// est imprimé, raison des hors périmètre comprise.
func (r *Rapport) EcrireTexte(w io.Writer, verbeux bool) {
	c := r.Comptes
	fmt.Fprintf(w, "Vérificateur indépendant CT-9 : %s\n", r.Racine)
	fmt.Fprintf(w, "- catalogue : %d entrées ; %d tables du texte comparées\n", c.Entrees, c.TablesComparees)
	fmt.Fprintf(w, "- règle (a) : %d identifiants définis par CT-1 à CT-8, %d couverts par une entrée, %d par un NC-, %d non couvert(s)\n", c.Identifiants, c.CouvertsParEntree, c.CouvertsParNC, c.NonCouverts)
	fmt.Fprintf(w, "- règle (b) : %d menaces sur %d avec un TA-\n", c.MenacesAvecTA, c.Menaces)
	fmt.Fprintf(w, "- règle (c) : %d occurrences de « CT-9 », %d lignes TC-\n", c.Occurrences, c.LignesTC)
	fmt.Fprintf(w, "- règle (d) : %d entrées exécutables, %d titres ou étapes cités\n", c.Executables, c.TitresCites)
	for _, x := range r.Controles {
		if verbeux || x.Statut == Discordant {
			fmt.Fprintf(w, "  %s %s | %s : %s\n", etiquette(x.Statut), x.Regle, x.Objet, x.Detail)
		}
	}
	s := r.Resume
	fmt.Fprintf(w, "%d valeurs recalculées : %d concordantes, %d discordantes, %d hors périmètre\n", s.Total, s.Concordants, s.Discordants, s.HorsPerimetre)
	// EX-A.17 : « 0 discordance » et le code 0, ou la liste des écarts et le code 1.
	code := 0
	if s.Discordants > 0 {
		code = 1
	}
	fmt.Fprintf(w, "Verdict : %d discordance(s), code %d\n", s.Discordants, code)
}

// EcrireJSON imprime le rapport en JSON.
func (r *Rapport) EcrireJSON(w io.Writer) error {
	if r.Controles == nil {
		r.Controles = []Controle{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}
