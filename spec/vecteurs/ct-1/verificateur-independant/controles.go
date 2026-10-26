// Résultats de contrôles numérotés (CT-1 §11.4). Un contrôle est passé,
// échoué, non exécuté (pièce absente ou donnée non vérifiable, avec raison)
// ou hors périmètre de ce vérificateur (E-9, signatures EIP-191).

package main

import (
	"fmt"
	"sort"
	"strings"
)

// Etat d'un contrôle.
type Etat int

// Les quatre états possibles.
const (
	EtatPasse Etat = iota
	EtatEchoue
	EtatNonExecute
	EtatHorsPerimetre
)

func (e Etat) String() string {
	switch e {
	case EtatPasse:
		return "passé"
	case EtatEchoue:
		return "ÉCHOUÉ"
	case EtatNonExecute:
		return "non exécuté"
	case EtatHorsPerimetre:
		return "hors périmètre"
	}
	return "?"
}

// Controle est l'état d'un contrôle identifié (D-1, E-7, C-2, M-2, P-5, A-3…).
type Controle struct {
	ID      string
	Etat    Etat
	Details []string
}

// Resultats accumule les contrôles dans l'ordre de leur première mention.
type Resultats struct {
	ordre []string
	parID map[string]*Controle
}

// NouveauxResultats crée un accumulateur vide.
func NouveauxResultats() *Resultats {
	return &Resultats{parID: map[string]*Controle{}}
}

func (r *Resultats) controle(id string) *Controle {
	c, ok := r.parID[id]
	if !ok {
		c = &Controle{ID: id, Etat: EtatPasse}
		r.parID[id] = c
		r.ordre = append(r.ordre, id)
	}
	return c
}

// Echec marque le contrôle échoué et consigne le détail.
func (r *Resultats) Echec(id, format string, args ...any) {
	c := r.controle(id)
	c.Etat = EtatEchoue
	c.Details = append(c.Details, fmt.Sprintf(format, args...))
}

// Passe mentionne le contrôle comme passé s'il n'a pas déjà un autre état.
func (r *Resultats) Passe(id string) { r.controle(id) }

// NonExecute marque le contrôle non exécuté, sauf s'il a déjà échoué.
func (r *Resultats) NonExecute(id, raison string) {
	c := r.controle(id)
	if c.Etat == EtatEchoue {
		return
	}
	c.Etat = EtatNonExecute
	c.Details = append(c.Details, raison)
}

// HorsPerimetre marque le contrôle hors périmètre de ce vérificateur.
func (r *Resultats) HorsPerimetre(id, raison string) {
	c := r.controle(id)
	if c.Etat == EtatEchoue {
		return
	}
	c.Etat = EtatHorsPerimetre
	c.Details = append(c.Details, raison)
}

// Fusionner reporte les contrôles d'un autre accumulateur, en préfixant les
// détails d'une étiquette (par exemple le nom du voisin).
func (r *Resultats) Fusionner(autre *Resultats, etiquette string) {
	for _, id := range autre.ordre {
		src := autre.parID[id]
		c := r.controle(id)
		for _, d := range src.Details {
			if etiquette != "" {
				d = etiquette + " : " + d
			}
			c.Details = append(c.Details, d)
		}
		switch src.Etat {
		case EtatEchoue:
			c.Etat = EtatEchoue
		case EtatNonExecute, EtatHorsPerimetre:
			if c.Etat == EtatPasse {
				c.Etat = src.Etat
			}
		}
	}
}

// Echecs rend les identifiants des contrôles échoués, dans l'ordre canonique.
func (r *Resultats) Echecs() []string {
	var out []string
	for _, id := range r.ordre {
		if r.parID[id].Etat == EtatEchoue {
			out = append(out, id)
		}
	}
	TrierControles(out)
	return out
}

// Valide dit si aucun contrôle n'a échoué.
func (r *Resultats) Valide() bool { return len(r.Echecs()) == 0 }

// Liste rend tous les contrôles dans l'ordre canonique.
func (r *Resultats) Liste() []*Controle {
	ids := append([]string{}, r.ordre...)
	TrierControles(ids)
	out := make([]*Controle, 0, len(ids))
	for _, id := range ids {
		out = append(out, r.parID[id])
	}
	return out
}

// ordreFamilles est l'ordre des familles de contrôles dans la table 11.4.
var ordreFamilles = map[byte]int{'D': 0, 'E': 1, 'C': 2, 'M': 3, 'P': 4, 'A': 5, 'K': 6}

// TrierControles trie des identifiants de contrôle dans l'ordre de la table
// 11.4 (D, E, C, M, P, A, K puis numéro).
func TrierControles(ids []string) {
	sort.Slice(ids, func(i, j int) bool {
		fi, ni := decomposerID(ids[i])
		fj, nj := decomposerID(ids[j])
		if fi != fj {
			return fi < fj
		}
		if ni != nj {
			return ni < nj
		}
		return ids[i] < ids[j]
	})
}

func decomposerID(id string) (int, int) {
	if len(id) < 3 || id[1] != '-' {
		return 99, 0
	}
	f, ok := ordreFamilles[id[0]]
	if !ok {
		f = 98
	}
	n := 0
	fmt.Sscanf(id[2:], "%d", &n)
	return f, n
}

// Resume rend une ligne par contrôle.
func (r *Resultats) Resume(indent string) string {
	var sb strings.Builder
	for _, c := range r.Liste() {
		fmt.Fprintf(&sb, "%s%-4s %s", indent, c.ID, c.Etat)
		if len(c.Details) > 0 {
			fmt.Fprintf(&sb, " — %s", strings.Join(c.Details, " ; "))
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}
