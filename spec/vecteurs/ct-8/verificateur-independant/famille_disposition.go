// Familles « disposition » (A.1, A.6 : ce qui est présent sous
// spec/vecteurs/ct-8) et « coefficients » (9.2 et A.5 : mesures des
// coefficients b_pt, b_man, b_tsr_sup et b_cap, rejouées sur les vecteurs
// de ct-1, ct-5 et ct-6).

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// FamilleDisposition confronte le contenu de spec/vecteurs/ct-8 à la
// disposition d'A.1. Une famille que la disposition annonce et que les
// vecteurs n'ont pas encore est rapportée hors périmètre (A.1 : la famille
// supervision/ est « à produire, lot suivant »).
func FamilleDisposition(c *Contexte) {
	const f = "disposition"
	sec, err := c.Texte.Section("### A.1 ")
	if err != nil {
		c.Rap.Erreur("%v", err)
		return
	}
	bloc, err := BlocApres(sec, "Disposition d'ensemble")
	if err != nil {
		c.Rap.Erreur("A.1 : %v", err)
		return
	}
	annonces := map[string]bool{}
	for _, l := range strings.Split(bloc, "\n") {
		if !strings.HasPrefix(l, "  ") || strings.HasPrefix(l, "   ") {
			continue
		}
		nom := strings.TrimSuffix(strings.Fields(l)[0], "/")
		annonces[nom] = true
		_, err := os.Stat(c.Chemin(nom))
		if err == nil {
			c.Rap.Constater(f, nom, "présent (A.1)", true, "")
		} else {
			c.Rap.HorsPerimetre(f, nom, "présent (A.1)", "présent", "absent des vecteurs de ce lot (A.1 : à produire) : rien à recalculer")
		}
	}
	es, _ := os.ReadDir(c.Racine)
	var imprevus []string
	for _, e := range es {
		if !annonces[e.Name()] {
			imprevus = append(imprevus, e.Name())
		}
	}
	c.Rap.Comparer(f, "ct-8", "entrées hors de la disposition d'A.1", "[]", Liste(imprevus))
}

func taille(chemin string) (int64, error) {
	i, err := os.Stat(chemin)
	if err != nil {
		return 0, err
	}
	return i.Size(), nil
}

// FamilleCoefficients rejoue les mesures de 9.2 (commandes d'A.5) et les
// confronte à la table de 9.2 et aux valeurs que le texte imprime.
func FamilleCoefficients(c *Contexte) {
	const f = "coefficients"
	coef, err := LireCoefficients(c.Texte)
	if err != nil {
		c.Rap.Erreur("%v", err)
		return
	}
	vec := filepath.Join(c.Spec, "vecteurs")
	val := func(n string) string { return NombreES6(coef[n]) }

	// b_pt : ligne JCS v0 plus \n des points de ct-1 (9.2 : « 183 points,
	// 681 à 682 octets »).
	n, min, max := 0, int64(-1), int64(0)
	for _, p := range []string{"periode-1", "periode-2", "periode-3"} {
		v, _, ok := c.LireJSON(filepath.Join(vec, "ct-1", "points-de-controle", p+".json"))
		if !ok {
			return
		}
		for _, x := range v.Arr {
			b, err := Canonique(x)
			if err != nil {
				c.Rap.Erreur("ct-1 %s : %v", p, err)
				return
			}
			l := int64(len(b) + 1)
			n++
			if min < 0 || l < min {
				min = l
			}
			if l > max {
				max = l
			}
		}
	}
	c.Rap.Comparer(f, "b_pt", "valeur de la table de 9.2 = mesure", val("b_pt"), strconv.FormatInt(max, 10))
	c.Rap.Comparer(f, "b_pt", "points mesurés et étendue (9.2)", "183 points, 681 à 682 octets", fmt.Sprintf("%d points, %d à %d octets", n, min, max))

	// b_man : manifeste et signature les plus grands des trois périodes.
	var mj, ms int64
	var tj []string
	for _, p := range []string{"periode-1", "periode-2", "periode-3"} {
		a, err1 := taille(filepath.Join(vec, "ct-1", "manifestes", p+".json"))
		b, err2 := taille(filepath.Join(vec, "ct-1", "manifestes", p+".sig"))
		if err1 != nil || err2 != nil {
			c.Rap.Erreur("ct-1 manifestes %s illisibles", p)
			return
		}
		tj = append(tj, fmt.Sprintf("%s.json %d, .sig %d", p, a, b))
		if a > mj {
			mj = a
		}
		if b > ms {
			ms = b
		}
	}
	c.Rap.Comparer(f, "b_man", "valeur de la table de 9.2 = mesure", val("b_man"), strconv.FormatInt(mj+ms, 10))
	c.Rap.Comparer(f, "b_man", "plus grands (9.2 : periode-2.json 631, periode-2.sig 285)", "631 + 285", fmt.Sprintf("%d + %d", mj, ms))
	c.Rap.Note("b_man : %s", strings.Join(tj, " ; "))

	// b_tsr_sup : .tsr moins .der sur les paires de ct-5/reponses.
	rep := filepath.Join(vec, "ct-5", "reponses")
	ecarts := map[int64]bool{}
	paires := 0
	for _, d := range Fichiers(rep, ".der") {
		a, err1 := taille(filepath.Join(rep, d))
		b, err2 := taille(filepath.Join(rep, strings.TrimSuffix(d, ".der")+".tsr"))
		if err1 != nil || err2 != nil {
			continue
		}
		paires++
		ecarts[b-a] = true
	}
	var lst []string
	for e := range ecarts {
		lst = append(lst, strconv.FormatInt(e, 10))
	}
	c.Rap.Comparer(f, "b_tsr_sup", "écarts .tsr − .der (9.2 : 9 octets dans chaque cas)", "["+val("b_tsr_sup")+"]", Liste(lst))
	c.Rap.Comparer(f, "b_tsr_sup", "paires mesurées (9.2)", "16", strconv.Itoa(paires))

	// b_cap : en-tête de bloc, certificat de commit et reçu les plus grands
	// de ct-6/registre/capture (A.5 : « 1 498 ; 6 818 à 7 782 ; 1 107 à
	// 1 816 »).
	cap := filepath.Join(vec, "ct-6", "registre", "capture")
	etendue := func(prefixe string) (int64, int64) {
		lo, hi := int64(-1), int64(0)
		for _, x := range Fichiers(cap, ".json") {
			if !strings.HasPrefix(x, prefixe) {
				continue
			}
			t, err := taille(filepath.Join(cap, x))
			if err != nil {
				continue
			}
			if lo < 0 || t < lo {
				lo = t
			}
			if t > hi {
				hi = t
			}
		}
		return lo, hi
	}
	bl, bh := etendue("bloc-")
	cl, ch := etendue("certificat-")
	rl, rh := etendue("recu-")
	c.Rap.Comparer(f, "b_cap", "valeur de la table de 9.2 = mesure", val("b_cap"), strconv.FormatInt(bh+ch+rh, 10))
	c.Rap.Comparer(f, "b_cap", "étendues (A.5)", "1498 à 1498 ; 6818 à 7782 ; 1107 à 1816",
		fmt.Sprintf("%d à %d ; %d à %d ; %d à %d", bl, bh, cl, ch, rl, rh))
}
