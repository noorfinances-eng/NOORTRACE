// Lecture du texte de CT-7 (spec/CT-7-securite-et-conformite.md) : sections
// par titre, blocs de code annotés, tables. Le vérificateur en tire les
// exemples et les valeurs que le texte imprime (5.10, 7.1, 7.2, 7.5), les
// tables qu'il confronte aux fichiers (3.2 à 3.5, A.4, A.6, annexe B,
// annexe C), et rien d'autre.

package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Texte est une spécification découpée en lignes.
type Texte struct {
	Nom    string
	Lignes []string
}

// LireTexte lit une spécification Markdown.
func LireTexte(chemin string) (*Texte, error) {
	b, err := os.ReadFile(chemin)
	if err != nil {
		return nil, err
	}
	return &Texte{Nom: chemin, Lignes: strings.Split(string(b), "\n")}, nil
}

var reTitre = regexp.MustCompile(`^(#{2,4}) (.*)$`)

// Section rend les lignes d'une section dont le titre commence par prefixe
// (« ### 5.10 », « ## Annexe B »), jusqu'au titre suivant de niveau égal ou
// supérieur.
func (t *Texte) Section(prefixe string) ([]string, error) {
	niveau := strings.Index(prefixe, " ")
	for i, l := range t.Lignes {
		if !strings.HasPrefix(l, prefixe) {
			continue
		}
		var out []string
		for _, m := range t.Lignes[i+1:] {
			if mm := reTitre.FindStringSubmatch(m); mm != nil && len(mm[1]) <= niveau {
				break
			}
			out = append(out, m)
		}
		return out, nil
	}
	return nil, fmt.Errorf("%s : section « %s » introuvable", t.Nom, prefixe)
}

// Titres rend les titres de niveau donné (« ### ») d'un ensemble de lignes.
func Titres(lignes []string, diese string) []string {
	var out []string
	for _, l := range lignes {
		if strings.HasPrefix(l, diese+" ") {
			out = append(out, strings.TrimPrefix(l, diese+" "))
		}
	}
	return out
}

// BlocApres rend le contenu du premier bloc de code qui suit la première
// ligne contenant repere, dans les lignes données.
func BlocApres(lignes []string, repere string) (string, error) {
	for i, l := range lignes {
		if !strings.Contains(l, repere) {
			continue
		}
		for j := i + 1; j < len(lignes); j++ {
			if strings.HasPrefix(lignes[j], "```") {
				var sb strings.Builder
				for k := j + 1; k < len(lignes); k++ {
					if strings.HasPrefix(lignes[k], "```") {
						return sb.String(), nil
					}
					sb.WriteString(lignes[k])
					sb.WriteByte('\n')
				}
				return "", fmt.Errorf("bloc après %q non fermé", repere)
			}
		}
	}
	return "", fmt.Errorf("aucun bloc après %q", repere)
}

// Table est une table Markdown : en-tête et lignes de cellules.
type Table struct {
	Entete []string
	Lignes [][]string
}

// CelluleTable découpe une ligne de table : séparateurs « | » non échappés,
// « \| » rendu par « | », espaces de bord retirés (RV-5, MX-8).
func CellulesTable(l string) []string {
	l = strings.TrimSpace(l)
	l = strings.TrimPrefix(l, "|")
	l = strings.TrimSuffix(l, "|")
	var out []string
	var sb strings.Builder
	for i := 0; i < len(l); i++ {
		if l[i] == '\\' && i+1 < len(l) && l[i+1] == '|' {
			sb.WriteByte('|')
			i++
			continue
		}
		if l[i] == '|' {
			out = append(out, strings.TrimSpace(sb.String()))
			sb.Reset()
			continue
		}
		sb.WriteByte(l[i])
	}
	return append(out, strings.TrimSpace(sb.String()))
}

// Tables rend les tables d'un ensemble de lignes, dans l'ordre.
func Tables(lignes []string) []Table {
	var out []Table
	for i := 0; i+1 < len(lignes); i++ {
		if !strings.HasPrefix(lignes[i], "|") || !strings.HasPrefix(lignes[i+1], "|---") {
			continue
		}
		t := Table{Entete: CellulesTable(lignes[i])}
		j := i + 2
		for ; j < len(lignes) && strings.HasPrefix(lignes[j], "|"); j++ {
			t.Lignes = append(t.Lignes, CellulesTable(lignes[j]))
		}
		out = append(out, t)
		i = j
	}
	return out
}

// TableEntete rend la première table dont la première colonne d'en-tête
// vaut premiere (et la deuxième deuxieme si non vide).
func TableEntete(lignes []string, premiere, deuxieme string) (Table, error) {
	for _, t := range Tables(lignes) {
		if len(t.Entete) > 1 && t.Entete[0] == premiere && (deuxieme == "" || t.Entete[1] == deuxieme) {
			return t, nil
		}
	}
	return Table{}, fmt.Errorf("table « %s | %s » introuvable", premiere, deuxieme)
}

// SansCode retire les accents graves d'une cellule (`x` → x).
func SansCode(s string) string { return strings.ReplaceAll(s, "`", "") }
