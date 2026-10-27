// Modèle de menace (CT-7 section 3, §3.8, annexe A.10) : menaces.json
// contre son schéma modele-menace-v0 (RV-1) et contre le texte de CT-7, dans
// ce que le texte seul permet : RV-2 (réponse écrite, préfixe du test,
// numérotation des MN- et RA-), RV-4 (renvois extraits par l'expression du
// texte), RV-5 (tables 3.2, 3.4 et 3.5 égales au fichier, cellule par
// cellule), RV-8 (risques acceptés) et la consolidation de 3.3 (table des
// tables sources et rattachement ligne par ligne). L'existence des renvois
// dans les spécifications citées (RV-3), celle des lignes sources (RV-6),
// les occurrences de « CT-7 » (RV-7) et les clés de test (RV-9, recalculées
// à part par ce module) relèvent du vérificateur de renvois.

package main

import (
	"fmt"
	"regexp"
	"strings"
)

// PrefixeTest est le préfixe fixe de la colonne « Test de CT-9 » (3.4, 3.8).
const PrefixeTest = "Le test échoue si la réponse est retirée : "

// reRenvoi est l'expression de RV-4.
var reRenvoi = regexp.MustCompile(`CT-([1-9]) (EX-[0-9A-Z]+\.[0-9]+|§[0-9A-Z]+(\.[0-9]+)*|[A-Z]{1,2}-[0-9]+)`)

var (
	reEXNu    = regexp.MustCompile(`EX-[0-9A-Z]+\.[0-9]+`)
	reCTAvant = regexp.MustCompile(`CT-[1-9] $`)
)

// porteurs traduit la colonne « Porté par » de 3.5 dans l'énumération
// owner du schéma (valeurs en français sans accent, CT-7 §0.1).
var porteurs = map[string]string{
	"client":                  "client",
	"exploitant NOORTRACE":    "exploitant_noortrace",
	"réviseur":                "reviseur",
	"opérateur de validateur": "operateur_validateur",
}

// Renvois rend les renvois d'un texte, dans l'ordre de leur première
// occurrence, sans doublon (RV-4).
func Renvois(t string) []string {
	out := []string{}
	vus := map[string]bool{}
	for _, m := range reRenvoi.FindAllString(t, -1) {
		if !vus[m] {
			vus[m] = true
			out = append(out, m)
		}
	}
	return out
}

// exNus rend les EX-s.k d'un texte qui ne sont pas précédés de « CT-n ».
func exNus(t string) []string {
	var out []string
	for _, loc := range reEXNu.FindAllStringIndex(t, -1) {
		if !reCTAvant.MatchString(t[:loc[0]]) {
			out = append(out, t[loc[0]:loc[1]])
		}
	}
	return out
}

func valeursChaines(v *Value) []string {
	out := []string{}
	for _, x := range v.Arr {
		out = append(out, x.Chaine())
	}
	return out
}

// VerifierMenaces confronte menaces.json à son schéma et au texte ; chaque
// comparaison est consignée dans le rapport.
func VerifierMenaces(rap *Rapport, m *Value, sch *Schema, t *Texte) {
	const fam = "menaces"
	manq := sch.Valider(m)
	rap.Comparer(fam, "menaces.json", "RV-1 : conformité à modele-menace-v0", "[]", Liste(manq))

	menaces := m.Get("threats").Arr
	composants := map[string]string{}
	for _, c := range m.Get("components").Arr {
		composants[c.Get("id").Chaine()] = c.Get("name").Chaine()
	}

	// RV-2.
	var idsMN, idsRA []string
	vusRA := map[string]*Value{}
	for _, x := range menaces {
		id := x.Get("id").Chaine()
		idsMN = append(idsMN, id)
		ar := x.Chemin("residual", "accepted_risk")
		if len(x.Chemin("response", "refs").Arr) == 0 && ar.EstNull() {
			rap.Comparer(fam, id, "RV-2 : réponse écrite (renvoi ou risque accepté)", "oui", "non")
		}
		if !strings.HasPrefix(x.Get("test").Chaine(), PrefixeTest) {
			rap.Comparer(fam, id, "RV-2 : préfixe du test", PrefixeTest, x.Get("test").Chaine())
		}
		if !ar.EstNull() {
			ra := ar.Get("id").Chaine()
			if autre, ok := vusRA[ra]; ok && !Egales(autre, ar) {
				rap.Comparer(fam, id, "RV-8 : "+ra+" identique partout", "oui", "non")
			}
			if _, ok := vusRA[ra]; !ok {
				idsRA = append(idsRA, ra)
			}
			vusRA[ra] = ar
		}
	}
	errMN, errRA := numerosSansTrou(idsMN, "MN-"), numerosSansTrou(idsRA, "RA-")
	rap.Comparer(fam, "menaces.json", "RV-2 : MN- uniques et sans trou", "", texteErreur(errMN))
	rap.Comparer(fam, "menaces.json", "RV-2 : RA- uniques et sans trou", "", texteErreur(errRA))

	// RV-4 : renvois recalculés depuis le texte de chaque cellule.
	for _, x := range menaces {
		id := x.Get("id").Chaine()
		for _, champ := range []string{"response", "detection"} {
			txt := x.Chemin(champ, "text").Chaine()
			rap.Comparer(fam, id, "RV-4 : "+champ+".refs", Liste(valeursChaines(x.Chemin(champ, "refs"))), Liste(Renvois(txt)))
			if nus := exNus(txt); len(nus) > 0 {
				rap.Comparer(fam, id, "RV-4 : EX- sans « CT-n » dans "+champ, "[]", Liste(nus))
			}
		}
	}

	// RV-5 : table 3.2.
	s32, err := t.Section("### 3.2")
	if err != nil {
		rap.Erreur("%v", err)
		return
	}
	t32, err := TableEntete(s32, "Id", "Composant")
	if err != nil {
		rap.Erreur("3.2 : %v", err)
		return
	}
	var lignes []string
	for _, c := range m.Get("components").Arr {
		lignes = append(lignes, strings.Join([]string{"`" + c.Get("id").Chaine() + "`", c.Get("name").Chaine(), c.Get("holds").Chaine(), c.Get("trust").Chaine()}, " | "))
	}
	comparerTable(rap, fam, "RV-5 : table 3.2", t32, lignes)

	// RV-5 : table 3.4.
	s34, err := t.Section("### 3.4")
	if err != nil {
		rap.Erreur("%v", err)
		return
	}
	t34, err := TableEntete(s34, "Id", "Composant")
	if err != nil {
		rap.Erreur("3.4 : %v", err)
		return
	}
	lignes = nil
	for _, x := range menaces {
		var stride []string
		for _, s := range valeursChaines(x.Get("stride")) {
			stride = append(stride, "`"+s+"`")
		}
		residuel := x.Chemin("residual", "text").Chaine()
		if ar := x.Chemin("residual", "accepted_risk"); !ar.EstNull() {
			residuel += " Risque accepté " + ar.Get("id").Chaine() + "."
		}
		lignes = append(lignes, strings.Join([]string{
			x.Get("id").Chaine(), composants[x.Get("component").Chaine()], strings.Join(stride, ", "),
			x.Get("actor").Chaine(), x.Get("asset").Chaine(), x.Get("effect").Chaine(),
			x.Chemin("response", "text").Chaine(), x.Chemin("detection", "text").Chaine(),
			residuel, strings.TrimPrefix(x.Get("test").Chaine(), PrefixeTest),
		}, " | "))
	}
	comparerTable(rap, fam, "RV-5 : table 3.4", t34, lignes)

	// RV-5 et RV-8 : table 3.5.
	s35, err := t.Section("### 3.5")
	if err != nil {
		rap.Erreur("%v", err)
		return
	}
	t35, err := TableEntete(s35, "Id", "Risque")
	if err != nil {
		rap.Erreur("3.5 : %v", err)
		return
	}
	parRA := map[string][]string{}
	for _, x := range menaces {
		if ar := x.Chemin("residual", "accepted_risk"); !ar.EstNull() {
			parRA[ar.Get("id").Chaine()] = append(parRA[ar.Get("id").Chaine()], x.Get("id").Chaine())
		}
	}
	inverse := map[string]string{}
	for k, v := range porteurs {
		inverse[v] = k
	}
	lignes = nil
	for _, ra := range idsRA {
		ar := vusRA[ra]
		lignes = append(lignes, strings.Join([]string{ra, ar.Get("name").Chaine(), ar.Get("bound").Chaine(), inverse[ar.Get("owner").Chaine()], strings.Join(parRA[ra], ", ")}, " | "))
	}
	ordonnerSelonTable(lignes, t35)
	comparerTable(rap, fam, "RV-5 et RV-8 : table 3.5", t35, lignes)

	// Consolidation de 3.3 : table des tables sources et rattachement.
	s33, err := t.Section("### 3.3")
	if err != nil {
		rap.Erreur("%v", err)
		return
	}
	tSources, err := TableEntete(s33, "Spécification", "Section")
	if err != nil {
		rap.Erreur("3.3 : %v", err)
		return
	}
	lignes = nil
	attendues := Table{Entete: tSources.Entete}
	for _, l := range tSources.Lignes {
		attendues.Lignes = append(attendues.Lignes, []string{l[0], l[1], l[3]})
	}
	for _, s := range m.Get("source_tables").Arr {
		n, _ := s.Get("rows").Entier()
		lignes = append(lignes, strings.Join([]string{s.Get("spec").Chaine(), s.Get("section").Chaine(), fmt.Sprint(n)}, " | "))
	}
	comparerTable(rap, fam, "3.3 : source_tables (spécification, section, lignes)", attendues, lignes)

	var tRatt Table
	for _, tb := range Tables(s33) {
		if len(tb.Entete) == 4 && tb.Entete[3] == "Menaces de CT-7" {
			tRatt = tb
		}
	}
	if tRatt.Entete == nil {
		rap.Erreur("3.3 : table de rattachement introuvable")
		return
	}
	for _, x := range menaces {
		id := x.Get("id").Chaine()
		var attendu []string
		for _, l := range tRatt.Lignes {
			for _, mn := range strings.Split(l[3], ", ") {
				if mn == id {
					attendu = append(attendu, l[0]+" "+l[1]+" "+l[2])
				}
			}
		}
		var obtenu []string
		for _, s := range x.Get("sources").Arr {
			obtenu = append(obtenu, s.Get("spec").Chaine()+" "+s.Get("section").Chaine()+" "+s.Get("row").Chaine())
		}
		rap.Comparer(fam, id, "3.3 : sources dans l'ordre du rattachement", Liste(attendu), Liste(obtenu))
	}
}

func texteErreur(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// comparerTable confronte les lignes d'une table du texte (cellules jointes
// par « | ») aux lignes reconstruites depuis le fichier.
func comparerTable(rap *Rapport, fam, grandeur string, tb Table, lignes []string) {
	rap.Comparer(fam, "texte de CT-7", grandeur+" : nombre de lignes", fmt.Sprint(len(tb.Lignes)), fmt.Sprint(len(lignes)))
	for i, l := range tb.Lignes {
		attendu := strings.Join(l, " | ")
		obtenu := ""
		if i < len(lignes) {
			obtenu = lignes[i]
		}
		rap.Comparer(fam, "texte de CT-7", fmt.Sprintf("%s, ligne %s", grandeur, l[0]), attendu, obtenu)
	}
}

// ordonnerSelonTable range des lignes « id | … » dans l'ordre des
// identifiants de la table (la table 3.5 suit l'ordre des RA-).
func ordonnerSelonTable(lignes []string, tb Table) {
	rang := map[string]int{}
	for i, l := range tb.Lignes {
		rang[l[0]] = i
	}
	for i := 1; i < len(lignes); i++ {
		for j := i; j > 0; j-- {
			a := strings.SplitN(lignes[j-1], " | ", 2)[0]
			b := strings.SplitN(lignes[j], " | ", 2)[0]
			if rang[a] > rang[b] {
				lignes[j-1], lignes[j] = lignes[j], lignes[j-1]
			}
		}
	}
}
