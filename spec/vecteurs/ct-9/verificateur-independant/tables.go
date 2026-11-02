package main

// Tables du texte de CT-9 imprimées depuis le catalogue (EX-4.4, EX-A.4) et
// comparées, cellule par cellule, aux blocs du texte publiés sous chaque
// marqueur « <!-- table X --> ». La règle d'impression d'une ligne est fixe
// par table ; elle est celle que les tables publiées du texte montrent.

import (
	"fmt"
	"regexp"
	"strings"
)

// Tables est l'ordre des marqueurs du texte.
var Tables = []string{"TC", "niveaux", "etapes", "NC", "stats", "TU", "TV", "TI", "TE", "TA", "scenarios", "RA", "TM", "TR", "TQ"}

var reMarqueur = regexp.MustCompile(`^<!-- table ([A-Za-z]+) -->$`)

func esc(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ") }

func uniq(l []string) []string {
	vu := map[string]bool{}
	var out []string
	for _, x := range l {
		if !vu[x] {
			vu[x] = true
			out = append(out, x)
		}
	}
	return out
}

func joinOuTiret(l []string, sep string) string {
	if len(l) == 0 {
		return "—"
	}
	return strings.Join(l, sep)
}

// EtatImprime : « à écrire (étape n) », « exécutable : `fichier`, … », avec
// « ; complément à écrire (étape n) ».
func EtatImprime(t *Test) string {
	s := t.Status
	if s.State != "executable" {
		return fmt.Sprintf("à écrire (étape %d)", *s.Phase2Step)
	}
	var sources []string
	for _, x := range s.Tests {
		sources = append(sources, "`"+x.File+"`")
	}
	for range s.CISteps {
		sources = append(sources, "étape de `ci.yml`")
	}
	out := "exécutable : " + strings.Join(uniq(sources), ", ")
	if s.Complement != nil {
		out += fmt.Sprintf(" ; complément à écrire (étape %d)", s.Complement.Phase2Step)
	}
	return out
}

func etatTA(t *Test) string {
	if t.Status.State != "executable" {
		return fmt.Sprintf("à écrire (étape %d)", *t.Status.Phase2Step)
	}
	if t.Status.Complement != nil {
		return fmt.Sprintf("exécutable ; complément à écrire (étape %d)", t.Status.Complement.Phase2Step)
	}
	return "exécutable"
}

// ResumeCouverts : « CT-6 T- (11) », par famille, dans l'ordre de première
// apparition ; les sections « CT-n §s » ne comptent pas.
func ResumeCouverts(ids []string) string {
	comptes := map[string]int{}
	var ordre []string
	for _, id := range ids {
		if strings.Contains(id, "§") {
			continue
		}
		parts := strings.SplitN(id, " ", 2)
		k := parts[0] + " " + reFinNum.ReplaceAllString(parts[1], "-")
		if comptes[k] == 0 {
			ordre = append(ordre, k)
		}
		comptes[k]++
	}
	var out []string
	for _, k := range ordre {
		out = append(out, fmt.Sprintf("%s (%d)", k, comptes[k]))
	}
	return strings.Join(out, ", ")
}

// CibleTM imprime la cible d'une mesure : « — », « p50 ≤ 5, p99 ≤ 50 ms »,
// « 450 min », ou le texte de la cible.
func CibleTM(m *Mesure) (string, error) {
	if EstNull(m.Target) {
		return "—", nil
	}
	s := string(m.Target)
	switch {
	case strings.HasPrefix(s, "{"):
		paires, err := ClesOrdonnees(m.Target)
		if err != nil {
			return "", err
		}
		var parts []string
		for _, p := range paires {
			parts = append(parts, fmt.Sprintf("%s ≤ %s", p[0], p[1]))
		}
		return strings.Join(parts, ", ") + " " + m.Unit, nil
	case strings.HasPrefix(s, "\""):
		var t string
		if err := jsonUnmarshal(m.Target, &t); err != nil {
			return "", err
		}
		return t, nil
	default:
		var f float64
		if err := jsonUnmarshal(m.Target, &f); err != nil {
			return "", err
		}
		return NombreJS(f) + " " + m.Unit, nil
	}
}

// Statistiques : comptes par niveau, dans l'ordre d'apparition des niveaux.
type Statistique struct{ N, Exe, AE, C int }

func Statistiques(c *Catalogue) ([]string, map[string]*Statistique) {
	st := map[string]*Statistique{}
	var ordre []string
	for i := range c.Tests {
		t := &c.Tests[i]
		if st[t.Level] == nil {
			st[t.Level] = &Statistique{}
			ordre = append(ordre, t.Level)
		}
		s := st[t.Level]
		s.N++
		if t.Status.State == "executable" {
			s.Exe++
		} else {
			s.AE++
		}
		if t.Status.Complement != nil {
			s.C++
		}
	}
	return ordre, st
}

// ImprimerTables rend les tables du texte depuis le catalogue : nom → lignes
// (en-tête, séparateur, puis une ligne par entrée).
func ImprimerTables(c *Catalogue) (map[string][]string, error) {
	blocs := map[string][]string{}
	parNiveau := func(n string) []*Test {
		var out []*Test
		for i := range c.Tests {
			if c.Tests[i].Level == n {
				out = append(out, &c.Tests[i])
			}
		}
		return out
	}
	tc := []string{"| Id | Spécification, section (ligne) | Ce qui est délégué à CT-9 | Réponse de CT-9 |", "|---|---|---|---|"}
	for _, r := range c.Traceability {
		tc = append(tc, fmt.Sprintf("| %s | %s (l. %d) | %s | %s |", r.ID, esc(r.Key), r.Line, esc(r.Delegated), esc(r.Response)))
	}
	blocs["TC"] = tc
	niv := []string{"| Niveau | Nom | Objet | Oracle | Section |", "|---|---|---|---|---|"}
	for _, l := range c.Levels {
		niv = append(niv, fmt.Sprintf("| %s- | %s | %s | %s | %s |", l.ID, esc(l.Name), esc(l.Object), esc(l.Oracle), l.Section))
	}
	blocs["niveaux"] = niv
	et := []string{"| Étape | Composant livré | Livré quand |", "|---|---|---|"}
	for _, e := range c.Phase2Steps {
		et = append(et, fmt.Sprintf("| %d | %s | %s |", e.Step, esc(e.Component), esc(e.DeliveredWhen)))
	}
	blocs["etapes"] = et
	nc := []string{"| Id | Catégorie | Identifiants | Justification |", "|---|---|---|---|"}
	for _, n := range c.NonTests {
		nc = append(nc, fmt.Sprintf("| %s | `%s` | %s | %s |", n.ID, n.Category, esc(ResumeCouverts(n.Covers)), esc(n.Justification)))
	}
	blocs["NC"] = nc
	ordre, st := Statistiques(c)
	stats := []string{"| Niveau | Entrées | Exécutables | dont avec complément à écrire | À écrire |", "|---|---|---|---|---|"}
	var somExe, somC, somAE int
	for _, k := range ordre {
		s := st[k]
		stats = append(stats, fmt.Sprintf("| %s- | %d | %d | %d | %d |", k, s.N, s.Exe, s.C, s.AE))
		somExe += s.Exe
		somC += s.C
		somAE += s.AE
	}
	stats = append(stats, fmt.Sprintf("| Total | %d | %d | %d | %d |", len(c.Tests), somExe, somC, somAE))
	blocs["stats"] = stats
	for _, niveau := range []string{"TU", "TV", "TI", "TE", "TQ"} {
		l := []string{"| Id | Objet | Identifiants couverts (famille : nombre) | Menaces | État |", "|---|---|---|---|---|"}
		for _, t := range parNiveau(niveau) {
			l = append(l, fmt.Sprintf("| %s | %s | %s | %s | %s |", t.ID, esc(t.Title), esc(ResumeCouverts(t.Covers)), joinOuTiret(t.Threats, ", "), esc(EtatImprime(t))))
		}
		blocs[niveau] = l
	}
	ta := []string{"| TA | MN | Composant | État | Réponse retirée (où) | Tests |", "|---|---|---|---|---|---|"}
	sc := []string{"| Scénario | Titre | Menaces | Tests composés | État |", "|---|---|---|---|---|"}
	for _, t := range parNiveau("TA") {
		if t.Adversarial == nil {
			return nil, fmt.Errorf("%s : bloc adversarial absent", t.ID)
		}
		if t.Adversarial.Threat != nil {
			var fichiers []string
			for _, x := range t.Status.Tests {
				fichiers = append(fichiers, "`"+x.File+"`")
			}
			composant := ""
			if t.Adversarial.Component != nil {
				composant = *t.Adversarial.Component
			}
			ta = append(ta, fmt.Sprintf("| %s | %s | `%s` | %s | %s | %s |", t.ID, *t.Adversarial.Threat, composant, etatTA(t), esc(t.Adversarial.ResponseRemoved.Where), joinOuTiret(uniq(fichiers), ", ")))
		} else {
			sc = append(sc, fmt.Sprintf("| %s | %s | %s | %s | %s |", t.ID, esc(t.Title), strings.Join(t.Threats, ", "), strings.Join(t.Adversarial.Composition, ", "), etatTA(t)))
		}
	}
	blocs["TA"] = ta
	blocs["scenarios"] = sc
	ra := []string{"| RA | Risque | Test | État | Non testé par CT-9 |", "|---|---|---|---|---|"}
	for _, r := range c.AcceptedRisks {
		ra = append(ra, fmt.Sprintf("| %s | %s | %s | %s | %s |", r.ID, esc(r.Name), r.Test, r.TestState, esc(r.NotTested)))
	}
	blocs["RA"] = ra
	tm := []string{"| Id | Grandeur | Cible | Comparaison | Source | Seuil d'échec | Méthode | État | Mesure |", "|---|---|---|---|---|---|---|---|---|"}
	for _, t := range parNiveau("TM") {
		if t.Measure == nil {
			return nil, fmt.Errorf("%s : bloc measure absent", t.ID)
		}
		m := t.Measure
		cible, err := CibleTM(m)
		if err != nil {
			return nil, fmt.Errorf("%s : cible illisible (%v)", t.ID, err)
		}
		tm = append(tm, fmt.Sprintf("| %s | %s | %s | `%s` | %s | %s | `%s` | %s | — |", t.ID, esc(m.Quantity), esc(cible), m.Comparison, esc(m.Source), esc(m.FailureThreshold), m.Method, esc(EtatImprime(t))))
	}
	blocs["TM"] = tm
	tr := []string{"| Id | Épreuve | Participant | Matériel remis | Sections interdites | Grille | Verdict | État |", "|---|---|---|---|---|---|---|---|"}
	for _, t := range parNiveau("TR") {
		if t.Replay == nil {
			return nil, fmt.Errorf("%s : bloc replay absent", t.ID)
		}
		r := t.Replay
		grille := "verdict d'outil"
		if r.Grid != nil {
			grille = "`" + *r.Grid + "`"
		}
		tr = append(tr, fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s | %s |", t.ID, esc(t.Title), esc(r.Participant), esc(strings.Join(r.Material, " ; ")), esc(strings.Join(r.ForbiddenSections, " ; ")), grille, esc(r.VerdictRule), esc(EtatImprime(t))))
	}
	blocs["TR"] = tr
	return blocs, nil
}

// TablesDuTexte lit, sous chaque marqueur, les lignes contiguës qui
// commencent par « | ».
func TablesDuTexte(texte string) map[string][]string {
	lignes := strings.Split(texte, "\n")
	out := map[string][]string{}
	for i, l := range lignes {
		m := reMarqueur.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		var bloc []string
		for j := i + 1; j < len(lignes) && strings.HasPrefix(lignes[j], "|"); j++ {
			bloc = append(bloc, lignes[j])
		}
		out[m[1]] = bloc
	}
	return out
}

// cellules découpe une ligne de table sur les « | » non échappés et retire
// les blancs de chaque cellule.
func cellules(l string) []string {
	var out []string
	var b strings.Builder
	for i := 0; i < len(l); i++ {
		if l[i] == '\\' && i+1 < len(l) {
			b.WriteByte(l[i])
			b.WriteByte(l[i+1])
			i++
			continue
		}
		if l[i] == '|' {
			out = append(out, strings.TrimSpace(b.String()))
			b.Reset()
			continue
		}
		b.WriteByte(l[i])
	}
	out = append(out, strings.TrimSpace(b.String()))
	if len(out) >= 2 {
		return out[1 : len(out)-1]
	}
	return out
}

// ComparerTables compare les tables imprimées aux blocs du texte ; rend le
// nombre de tables comparées et les différences.
func ComparerTables(attendu map[string][]string, texte string) (int, []string) {
	lu := TablesDuTexte(texte)
	var diff []string
	compared := 0
	for _, nom := range Tables {
		lignes := attendu[nom]
		t, ok := lu[nom]
		if !ok {
			diff = append(diff, fmt.Sprintf("table %s : marqueur absent du texte", nom))
			continue
		}
		compared++
		if len(t) != len(lignes) {
			diff = append(diff, fmt.Sprintf("table %s : %d lignes dans le texte, %d dans le catalogue", nom, len(t), len(lignes)))
		}
		n := len(t)
		if len(lignes) < n {
			n = len(lignes)
		}
		for i := 0; i < n; i++ {
			if t[i] == lignes[i] {
				continue
			}
			a, b := cellules(t[i]), cellules(lignes[i])
			if len(a) != len(b) {
				diff = append(diff, fmt.Sprintf("table %s, ligne %d : %d cellules dans le texte, %d dans le catalogue", nom, i+1, len(a), len(b)))
				continue
			}
			for j := range a {
				if a[j] != b[j] {
					diff = append(diff, fmt.Sprintf("table %s, ligne %d, cellule %d : texte « %s », catalogue « %s »", nom, i+1, j+1, a[j], b[j]))
				}
			}
		}
	}
	for nom := range lu {
		if _, ok := attendu[nom]; !ok {
			diff = append(diff, fmt.Sprintf("table %s : marqueur du texte sans table du catalogue", nom))
		}
	}
	return compared, diff
}
