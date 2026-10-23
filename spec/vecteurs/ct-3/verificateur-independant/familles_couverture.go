// Forme des fichiers (EX-A.1) et couverture que l'annexe A exige des
// familles : chaque vérification AP- a au moins un cas (A.4), les traces
// servent les vérifications TK- (7.12), les remises valides exigées par
// EX-A.8.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// FamFormat est la famille de la forme des fichiers.
const FamFormat = "format"

func familleFormat(c *Contexte) {
	const f = FamFormat
	var fics []string
	filepath.WalkDir(c.Racine, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && d.Name() == "verificateur-independant" {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(p, ".json") {
			r, _ := filepath.Rel(c.Racine, p)
			fics = append(fics, filepath.ToSlash(r))
		}
		return nil
	})
	for _, fic := range fics {
		src, err := os.ReadFile(filepath.Join(c.Racine, fic))
		if err != nil {
			c.R.Erreur("%s : %v", fic, err)
			continue
		}
		v, err := ParseJSON(src)
		if err != nil {
			c.R.Erreur("%s : %v", fic, err)
			continue
		}
		txt, err := Stringify2(v)
		if err != nil {
			c.R.Erreur("%s : %v", fic, err)
			continue
		}
		ok := string(src) == txt+"\n"
		constat := ""
		if !ok {
			constat = premiereDifference(string(src), txt+"\n")
		}
		c.R.Exiger(f, fic, "octets = JSON.stringify(valeur, null, 2) + saut de ligne", ok, constat, "CT-3 EX-A.1 : « Les fichiers JSON sont écrits par JSON.stringify(objet, null, 2) suivi d'un saut de ligne »")
	}
	c.R.HorsPerimetre(f, "INDEX.md", "contenu", "résumé généré des cas, sans valeur attendue propre (EX-A.2) ; non recalculé")
}

func premiereDifference(a, b string) string {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			d := i - 20
			if d < 0 {
				d = 0
			}
			fa, fb := i+20, i+20
			if fa > len(a) {
				fa = len(a)
			}
			if fb > len(b) {
				fb = len(b)
			}
			return fmt.Sprintf("octet %d : fichier %q, attendu %q", i, a[d:fa], b[d:fb])
		}
	}
	return fmt.Sprintf("longueurs %d et %d", len(a), len(b))
}

var reAP = regexp.MustCompile(`^AP-([0-9]+)$`)
var reTK = regexp.MustCompile(`^TK-([0-9]+)$`)

func couvertureAP(c *Contexte) {
	vus := map[string]bool{}
	ajouter := func(v *Value) {
		for _, x := range v.Arr {
			vus[x.S()] = true
		}
	}
	if att, ok := c.lire("politiques-invalides/attendu.json"); ok {
		for _, cas := range att.Get("cases").Arr {
			ajouter(cas.Get("checks"))
		}
	}
	for _, motif := range []string{"evaluation/*.json", "candidats/*.json"} {
		for _, fic := range c.fichiers(motif) {
			if d, ok := c.lire(fic); ok {
				for _, cas := range d.Get("cases").Arr {
					ajouter(cas.Get("checks"))
				}
			}
		}
	}
	for i := 1; i <= 17; i++ {
		id := fmt.Sprintf("AP-%d", i)
		c.R.Exiger(FamEvaluation, "vecteurs AP- (politiques-invalides, evaluation, candidats)", id+" a au moins un cas", vus[id], "aucun cas", "CT-3 A.4 : « chaque vérification AP- ayant au moins un cas »")
	}
	for id := range vus {
		if m := reAP.FindStringSubmatch(id); m == nil || len(m[1]) > 2 || m[1] == "0" || (len(m[1]) == 2 && m[1] > "17") {
			c.R.Exiger(FamEvaluation, "vecteurs AP-", "identifiant "+id+" défini en 4.15", false, "inconnu", "CT-3 4.15 (AP-1 à AP-17)")
		}
	}
}

func couvertureTK(c *Contexte) {
	vus := map[string]bool{}
	for _, fic := range c.fichiers("tickets/*.json") {
		tr, ok := c.lire(fic)
		if !ok {
			continue
		}
		for _, x := range tr.Get("checks").Arr {
			vus[x.S()] = true
		}
		// 10.3 : étapes d'escalade à after_ms strictement croissants et
		// inférieurs à E.
		e, _ := EntierJSON(tr.Get("expire_after_ms"))
		prec := int64(0)
		okEsc := true
		for _, et := range tr.Get("service").Get("escalation").Arr {
			a, _ := EntierJSON(et.Get("after_ms"))
			if a <= prec || a >= e {
				okEsc = false
			}
			prec = a
		}
		c.R.Exiger(FamTickets, fic, "escalade : after_ms strictement croissants et inférieurs à E", okEsc, Compact(tr.Get("service").Get("escalation")), "CT-3 10.3 : « after_ms strictement croissants et inférieurs à E »")
		// EX-8.2, point 2 : un jeu statique n'est jamais chargé en production.
		if tr.Get("approver_set").Get("source").S() == "statique" {
			c.R.Exiger(FamTickets, fic, "jeu statique hors production", tr.Get("environment").S() != "production", "environment production", "CT-3 EX-8.2, point 2")
		}
	}
	for i := 1; i <= 13; i++ {
		id := fmt.Sprintf("TK-%d", i)
		c.R.Exiger(FamTickets, "vecteurs tickets/", id+" servie par au moins une trace", vus[id], "aucune trace", "CT-3 7.12 : « Vérifications du cycle de vie, servies par les vecteurs tickets/ »")
	}
	for id := range vus {
		m := reTK.FindStringSubmatch(id)
		ok := m != nil
		if ok {
			var n int
			fmt.Sscanf(m[1], "%d", &n)
			ok = n >= 1 && n <= 13
		}
		if !ok {
			c.R.Exiger(FamTickets, "vecteurs tickets/", "identifiant "+id+" défini en 7.12", false, "inconnu", "CT-3 7.12 (TK-1 à TK-13)")
		}
	}
}

// couvertureRemisesValides vérifie la liste d'EX-A.8 pour decisions/valides/.
func couvertureRemisesValides(c *Contexte) {
	k := c.Consts
	var a23, r23, exp, stat, ct1, permise bool
	for _, fic := range c.fichiers("decisions/valides/*.json") {
		cas, ok := c.lire(fic)
		if !ok {
			continue
		}
		rem := cas.Get("remise")
		// approbation signée par une adresse du demandeur sous
		// self_approval « permise » (SG-7 ne s'applique pas)
		if ctx, err := LireContexteNoyau(cas.Get("context")); err == nil && ctx.Separation != nil && ctx.Separation.AutoApprobation == "permise" {
			if r := retenueDeLaDemande(ctx, rem); r != nil {
				for _, id := range ctx.Separation.Identites {
					if id.LaunchedBy != r.LaunchedBy {
						continue
					}
					for _, x := range chaines(rem.Get("approval").Get("approvers")) {
						if contient(id.Adresses, x) && rem.Get("approval").Get("decision").S() == "approuve" {
							permise = true
						}
					}
				}
			}
		}
		ap := rem.Get("approval")
		dec := ap.Get("decision").S()
		appr := chaines(ap.Get("approvers"))
		rq, _ := EntierJSON(ap.Get("threshold").Get("required"))
		sz, _ := EntierJSON(ap.Get("threshold").Get("size"))
		src := rem.Get("approver_set").Get("source").S()
		deuxSurTrois := rq == 2 && sz == 3
		comptes12 := len(appr) == 2 && contient(appr, k.Comptes[1]) && contient(appr, k.Comptes[2])
		switch {
		case strings.HasSuffix(fic, "ct1-apr-2201.json"):
			ct1 = ap.Get("ticket").S() == "apr-2201"
		case strings.HasPrefix(src, "jeu statique de la politique ") && dec == "approuve":
			stat = true
		case dec == "approuve" && deuxSurTrois && comptes12:
			a23 = true
		case dec == "refuse" && deuxSurTrois && len(appr) == 2:
			r23 = true
		case dec == "expire" && len(appr) == 0:
			exp = true
		}
	}
	fond := "CT-3 EX-A.8 : decisions/valides/ contient au moins …"
	c.R.Exiger(FamDecisions, "decisions/valides", "une approbation 2 sur 3 des comptes 1 et 2", a23, "absente", fond)
	c.R.Exiger(FamDecisions, "decisions/valides", "un refus 2 sur 3", r23, "absent", fond)
	c.R.Exiger(FamDecisions, "decisions/valides", "une expiration sans signature", exp, "absente", fond)
	c.R.Exiger(FamDecisions, "decisions/valides", "une approbation sur un jeu statique", stat, "absente", fond)
	c.R.Exiger(FamDecisions, "decisions/valides", "la décision du ticket apr-2201 de CT-1", ct1, "absente", fond)
	c.R.Exiger(FamDecisions, "decisions/valides", "une approbation signée par une adresse du demandeur sous self_approval « permise » (SG-7 ne s'applique pas)", permise, "absente",
		"CT-3 EX-A.8 : « une approbation signée par une adresse du demandeur sous self_approval: \"interdite\" (auto_approbation, SG-7 […]), la même sous permise restant dans valides/ »")
}
