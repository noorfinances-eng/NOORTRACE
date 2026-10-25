// Lecture des fichiers de famille (A.3, A.4) et confrontation des verdicts.

package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Cas est un cas d'un fichier de famille.
type Cas struct {
	ID       string
	Checks   []string
	Input    *Value
	Expected *Value
	Refusal  *Value
}

// lireFamille lit un fichier de famille, vérifie sa conformité à
// fichier_vecteurs (EX-A.3) et rend ses cas.
func (c *Ctx) lireFamille(f *Famille, chemin, famille string) []Cas {
	v, _, err := LireJSON(filepath.Join(c.Racine, chemin))
	if err != nil {
		f.Erreur(chemin, "lecture", err, "EX-A.3")
		return nil
	}
	errs := c.Schemas.Valider("operations-registre-v0.schema.json#/$defs/fichier_vecteurs", v)
	f.Vrai(chemin, "conforme à fichier_vecteurs", len(errs) == 0, strings.Join(errs, " ; "), "EX-A.3")
	f.Comparer(chemin, "family", famille, v.Get("family").S(), "EX-A.3")
	var out []Cas
	for _, k := range v.Get("cases").Arr {
		cs := Cas{ID: k.Get("id").S(), Input: k.Get("input"), Expected: k.Get("expected"), Refusal: k.Get("refusal")}
		for _, x := range k.Get("checks").Arr {
			cs.Checks = append(cs.Checks, x.S())
		}
		out = append(out, cs)
		c.couverture(famille, cs)
	}
	return out
}

// refusAttendu rend (check, code) du refus déclaré, ou ("", "") s'il est
// nul.
func refusAttendu(cs Cas) (string, string) {
	if cs.Refusal == nil || cs.Refusal.IsNull() {
		return "", ""
	}
	return cs.Refusal.Get("check").S(), cs.Refusal.Get("code").S()
}

const raisonMotifRG = "motif d'échec d'une RG- : la spécification ne fixe que reussi ou echoue (6.9) ; les motifs des vecteurs viennent de l'implémentation de référence (INDEX.md)"

// confronterIssue confronte l'issue recalculée d'un cas (e nul : réussite)
// au refus déclaré. Rend vrai si le cas réussit selon le recalcul et selon
// l'attendu (les valeurs attendues sont alors à confronter).
func (c *Ctx) confronterIssue(f *Famille, cs Cas, e *Echec) bool {
	chk, code := refusAttendu(cs)
	if e == nil {
		if chk == "" {
			f.Comparer(cs.ID, "issue", "reussi", "reussi", firstCheck(cs))
			c.issue(cs, "", "")
			return true
		}
		f.Comparer(cs.ID, "issue", "echoue "+chk+" "+code, "reussi", chk)
		return false
	}
	c.issue(cs, e.Check, e.Raison)
	if chk == "" {
		f.Comparer(cs.ID, "issue", "reussi", "echoue "+e.Check+" ("+e.Raison+")", e.Check)
		return false
	}
	f.Comparer(cs.ID, "refusal.check", chk, e.Check, e.Check)
	switch {
	case strings.HasPrefix(chk, "RG-"):
		f.Hors(cs.ID, "refusal.code "+code, raisonMotifRG)
	case e.Fixe:
		f.Comparer(cs.ID, "refusal.code", code, e.Code, e.Check)
	default:
		raison := "code d'erreur non fixé par la spécification pour ce cas (" + e.Raison + ")"
		if e.Code != "" {
			raison += " ; lecture du vérificateur : " + e.Code
		}
		f.Hors(cs.ID, "refusal.code "+code, raison)
	}
	return false
}

func firstCheck(cs Cas) string {
	if len(cs.Checks) > 0 {
		return cs.Checks[0]
	}
	return ""
}

// ------------------------------------------------------------ couverture

type issueCas struct {
	reussis map[string]bool
	echoues map[string]bool
}

func (c *Ctx) issue(cs Cas, check, raison string) {
	if c.issues == nil {
		c.issues = map[string]*issueCas{}
	}
	_ = raison
	for _, k := range cs.Checks {
		ic := c.issues[k]
		if ic == nil {
			ic = &issueCas{map[string]bool{}, map[string]bool{}}
			c.issues[k] = ic
		}
		if check == "" {
			ic.reussis[cs.ID] = true
		}
	}
	if check != "" {
		ic := c.issues[check]
		if ic == nil {
			ic = &issueCas{map[string]bool{}, map[string]bool{}}
			c.issues[check] = ic
		}
		ic.echoues[cs.ID] = true
	}
}

// issueVerdicts consigne, pour une famille à verdicts par vérification
// (manifestes, capture), les vérifications réussies et échouées d'un cas.
func (c *Ctx) issueVerdicts(cs Cas, verdicts map[string]bool, premier string) {
	if c.issues == nil {
		c.issues = map[string]*issueCas{}
	}
	for k, ok := range verdicts {
		ic := c.issues[k]
		if ic == nil {
			ic = &issueCas{map[string]bool{}, map[string]bool{}}
			c.issues[k] = ic
		}
		if ok {
			ic.reussis[cs.ID] = true
		} else if k == premier {
			ic.echoues[cs.ID] = true
		}
	}
}

func (c *Ctx) couverture(famille string, cs Cas) {
	if c.casParFamille == nil {
		c.casParFamille = map[string][]string{}
	}
	c.casParFamille[famille] = append(c.casParFamille[famille], cs.ID)
}

// FamilleCouverture vérifie EX-A.3 : chaque RG-1 à RG-20, OP-4, OP-6, OP-7,
// CP-2 à CP-6 a au moins un cas qui réussit et un cas qui échoue sur elle,
// selon les issues recalculées.
func (c *Ctx) FamilleCouverture() {
	f := c.R.F("couverture")
	var ids []string
	for i := 1; i <= 20; i++ {
		ids = append(ids, fmt.Sprintf("RG-%d", i))
	}
	ids = append(ids, "OP-4", "OP-6", "OP-7", "CP-2", "CP-3", "CP-4", "CP-5", "CP-6")
	for _, id := range ids {
		ic := c.issues[id]
		nr, ne := 0, 0
		if ic != nil {
			nr, ne = len(ic.reussis), len(ic.echoues)
		}
		f.Vrai(id, "au moins un cas qui réussit", nr > 0, fmt.Sprintf("%d cas", nr), "EX-A.3")
		f.Vrai(id, "au moins un cas qui échoue sur elle", ne > 0, fmt.Sprintf("%d cas", ne), "EX-A.3")
	}
}
