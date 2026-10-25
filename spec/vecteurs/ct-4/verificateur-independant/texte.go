// Lecture du texte de CT-4 : exemples annotés « <!-- schema: … --> »,
// tables et valeurs imprimées, que la famille « texte » recalcule et
// confronte aux vecteurs.

package main

import (
	"regexp"
	"strings"
)

// Exemple est un bloc JSON annoté du texte.
type Exemple struct {
	Schema string
	Ligne  int
	Brut   string
	Valeur *Value
	Err    error
}

var reAnnotation = regexp.MustCompile(`^<!-- schema: ([a-z0-9/_-]+) -->$`)

// ExemplesAnnotes rend les blocs JSON précédés d'une annotation de schéma.
func ExemplesAnnotes(texte string) []Exemple {
	lignes := strings.Split(texte, "\n")
	var out []Exemple
	for i := 0; i < len(lignes); i++ {
		m := reAnnotation.FindStringSubmatch(strings.TrimSpace(lignes[i]))
		if m == nil {
			continue
		}
		j := i + 1
		for j < len(lignes) && strings.TrimSpace(lignes[j]) == "" {
			j++
		}
		if j >= len(lignes) || strings.TrimSpace(lignes[j]) != "```json" {
			out = append(out, Exemple{Schema: m[1], Ligne: i + 1, Err: errFormat("bloc ```json attendu après l'annotation")})
			continue
		}
		k := j + 1
		var corps []string
		for k < len(lignes) && strings.TrimSpace(lignes[k]) != "```" {
			corps = append(corps, lignes[k])
			k++
		}
		brut := strings.Join(corps, "\n")
		v, err := ParseJSON([]byte(brut))
		out = append(out, Exemple{Schema: m[1], Ligne: i + 1, Brut: brut, Valeur: v, Err: err})
		i = k
	}
	return out
}

type errFormat string

func (e errFormat) Error() string { return string(e) }

// SchemaDeAnnotation traduit le nom d'une annotation en référence de schéma.
func SchemaDeAnnotation(nom string) string {
	base, def, _ := strings.Cut(nom, "/")
	ref := base + "-v0.schema.json"
	if def != "" {
		ref += "#/$defs/" + def
	}
	return ref
}

// Section rend le texte d'une section, de son titre au titre suivant de même
// niveau ou supérieur.
func Section(texte, titre string) string {
	i := strings.Index(texte, "\n"+titre+"\n")
	if i < 0 {
		return ""
	}
	niveau := strings.IndexByte(titre, ' ')
	reste := texte[i+1+len(titre):]
	lignes := strings.Split(reste, "\n")
	var out []string
	for _, l := range lignes {
		if strings.HasPrefix(l, "#") {
			n := strings.IndexByte(l, ' ')
			if n > 0 && n <= niveau && strings.Trim(l[:n], "#") == "" {
				break
			}
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// LignesTable rend les lignes d'une table markdown (hors en-tête et
// séparateur), chaque ligne découpée en cellules.
func LignesTable(sec string) [][]string {
	var out [][]string
	enTete := true
	for _, l := range strings.Split(sec, "\n") {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "|") {
			if len(out) > 0 {
				break
			}
			enTete = true
			continue
		}
		if strings.HasPrefix(l, "|---") {
			enTete = false
			continue
		}
		if enTete {
			continue
		}
		cs := strings.Split(strings.Trim(l, "|"), "|")
		for i := range cs {
			cs[i] = strings.TrimSpace(cs[i])
		}
		out = append(out, cs)
	}
	return out
}

var reCode = regexp.MustCompile("`([^`]+)`")

// Codes rend les fragments entre accents graves d'une cellule.
func Codes(cellule string) []string {
	var out []string
	for _, m := range reCode.FindAllStringSubmatch(cellule, -1) {
		out = append(out, m[1])
	}
	return out
}
