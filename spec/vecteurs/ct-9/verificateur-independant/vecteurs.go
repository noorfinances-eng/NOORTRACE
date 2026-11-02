package main

// Familles de spec/vecteurs/ct-9 recalculées depuis le texte de CT-9 et le
// schéma : verdicts des cas (EX-A.3, EX-A.14, EX-A.15), validité des
// fichiers publiés, rapports de mesure (EX-11.11, EX-11.13), gabarit de
// consignation (EX-A.15), grilles (EX-12.7, EX-15.2, EX-A.16), extraits et
// SHA256SUMS (EX-12.2, EX-A.16), INDEX.md (EX-A.2) et chiffres de la prose.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// validerFichier valide un fichier contre une définition du schéma et rend
// ses violations.
func (d *Depot) validerFichier(chemin, def string) ([]Violation, error) {
	doc, err := LireDocument(filepath.Join(d.Racine, filepath.FromSlash(chemin)))
	if err != nil {
		return nil, err
	}
	return d.Schema.Valider(def, doc)
}

// verifierSchemas : chaque fichier publié valide contre sa définition
// (EX-4.3, EX-A.3, EX-A.9, EX-A.16).
func (d *Depot) verifierSchemas(rap *Rapport) error {
	fichiers := [][2]string{
		{"spec/vecteurs/ct-9/catalogue.json", "racine"},
		{"spec/vecteurs/ct-9/couverture.json", "rapport_couverture"},
		{"spec/vecteurs/ct-9/consignations/gabarit-TR-10.json", "consignation_rejeu"},
		{"spec/vecteurs/ct-9/acceptation-ancrage-attendu.json", "grille_acceptation"},
		{"spec/vecteurs/ct-9/acceptation-verdict-point-attendu.json", "grille_acceptation"},
		{"spec/vecteurs/ct-9/acceptation-porte-2-attendu.json", "grille_acceptation"},
	}
	rapports, _ := filepath.Glob(filepath.Join(d.Vecteurs, "mesures", "rapport-*.json"))
	sort.Strings(rapports)
	for _, r := range rapports {
		fichiers = append(fichiers, [2]string{"spec/vecteurs/ct-9/mesures/" + filepath.Base(r), "rapport_mesure"})
	}
	consignations, _ := filepath.Glob(filepath.Join(d.Vecteurs, "consignations", "TR-*.json"))
	sort.Strings(consignations)
	for _, c := range consignations {
		fichiers = append(fichiers, [2]string{"spec/vecteurs/ct-9/consignations/" + filepath.Base(c), "consignation_rejeu"})
	}
	for _, f := range fichiers {
		v, err := d.validerFichier(f[0], f[1])
		if err != nil {
			return err
		}
		rap.Verdict(len(v) == 0, "schéma", f[0], "valide contre #/$defs/%s ; violations : %s", f[1], resumerViolations(v))
	}
	return nil
}

func resumerViolations(v []Violation) string {
	if len(v) == 0 {
		return "aucune"
	}
	var out []string
	for i, x := range v {
		if i == 4 {
			out = append(out, fmt.Sprintf("… (%d en tout)", len(v)))
			break
		}
		out = append(out, fmt.Sprintf("%s@%s", x.MotCle, x.Chemin))
	}
	return strings.Join(out, ", ")
}

// verifierCas : verdict de chaque cas de cas/, mesures/cas/ et
// consignations/cas/ recalculé contre le schéma ; pour cas/, le mot-clé
// fautif attendu figure parmi les mots-clés violés.
func (d *Depot) verifierCas(rap *Rapport) error {
	familles := []struct{ liste, dossier, defaut string }{
		{"cas/attendu.json", "cas", "racine"},
		{"mesures/cas/cas.json", "mesures/cas", "rapport_mesure"},
		{"consignations/cas/cas.json", "consignations/cas", "consignation_rejeu"},
	}
	for _, f := range familles {
		var liste ListeCas
		if err := LireJSON(filepath.Join(d.Vecteurs, f.liste), &liste); err != nil {
			return err
		}
		fichiers, _ := os.ReadDir(filepath.Join(d.Vecteurs, f.dossier))
		var presents []string
		for _, e := range fichiers {
			if strings.HasSuffix(e.Name(), ".json") && e.Name() != "attendu.json" && e.Name() != "cas.json" {
				presents = append(presents, e.Name())
			}
		}
		var listes []string
		for _, c := range liste.Cases {
			listes = append(listes, c.File)
		}
		rap.Verdict(egalesTriees(presents, listes), "EX-A.3", f.dossier+"/", "%d cas listés, %d fichiers présents", len(listes), len(presents))
		for _, c := range liste.Cases {
			def := c.Def
			if def == "" {
				def = f.defaut
			}
			v, err := d.validerFichier("spec/vecteurs/ct-9/"+f.dossier+"/"+c.File, def)
			if err != nil {
				return err
			}
			valide := len(v) == 0
			attenduValide := c.Expected == "valide" || c.Expected == "valid"
			mots := MotsCles(v)
			ok := valide == attenduValide
			detail := fmt.Sprintf("attendu %s, recalculé %s", c.Expected, map[bool]string{true: "valide", false: "invalide"}[valide])
			if c.Keyword != nil {
				ok = ok && contient(mots, *c.Keyword)
				detail += fmt.Sprintf(" ; mot-clé attendu %s, violés %v", *c.Keyword, mots)
			} else if !valide {
				detail += fmt.Sprintf(" ; violés %v", mots)
			}
			rap.Verdict(ok, "EX-A.3", f.dossier+"/"+c.File, "%s", detail)
		}
	}
	return nil
}

// verifierRapportsMesure : EX-11.11 (chaque ligne a son TM- et son nom),
// EX-11.13 (rapport vide : cibles du catalogue, null ailleurs ; rapport sur
// les vecteurs : tailles de ligne du segment recalculées, bloc JSON de 11.3).
func (d *Depot) verifierRapportsMesure(rap *Rapport) error {
	tm := map[string]*Test{}
	for i := range d.Cat.Tests {
		if d.Cat.Tests[i].Level == "TM" && d.Cat.Tests[i].Measure != nil {
			tm[d.Cat.Tests[i].ID] = &d.Cat.Tests[i]
		}
	}
	// Lignes nommées par la table de 11.3 : « | `nom` | TM-n | … ».
	nommees := map[string]string{}
	for _, m := range regexp.MustCompile("(?m)^\\| `([a-z0-9_]+)` \\| (TM-[0-9]+) \\|").FindAllStringSubmatch(SectionTexte(d.CT9.Texte, "11.3"), -1) {
		nommees[m[1]] = m[2]
	}
	rapports, _ := filepath.Glob(filepath.Join(d.Vecteurs, "mesures", "rapport-*.json"))
	sort.Strings(rapports)
	for _, f := range rapports {
		var r RapportMesure
		if err := LireJSON(f, &r); err != nil {
			return err
		}
		nom := "mesures/" + filepath.Base(f)
		vide := strings.HasSuffix(f, "-vide.json")
		for _, l := range r.Results {
			t := tm[l.TestID]
			var pb []string
			if t == nil {
				pb = append(pb, l.TestID+" n'est pas un TM- du catalogue")
			} else {
				if l.Name != t.Measure.ResultName && nommees[l.Name] != l.TestID {
					pb = append(pb, fmt.Sprintf("nom %s : ni result_name de %s (%s) ni ligne nommée par la table de 11.3", l.Name, t.ID, t.Measure.ResultName))
				}
				if l.Unit != t.Measure.Unit {
					pb = append(pb, fmt.Sprintf("unité %s, %s dans le catalogue", l.Unit, t.Measure.Unit))
				}
				if vide {
					if !EgalBrut(l.Target, t.Measure.Target) {
						pb = append(pb, fmt.Sprintf("cible %s, %s dans le catalogue", l.Target, t.Measure.Target))
					}
					for k, v := range map[string]json.RawMessage{"n": l.N, "value": l.Value, "p50": l.P50, "p95": l.P95, "p99": l.P99, "min": l.Min, "max": l.Max, "mean": l.Mean, "text_value": l.TextValue, "met": l.Met, "excluded_reason": l.ExcludedReason, "samples": l.Samples} {
						if !EstNull(v) {
							pb = append(pb, k+" non nul dans le rapport vide")
						}
					}
				}
			}
			rap.Verdict(len(pb) == 0, "EX-11.11", nom+" "+l.Name, "ligne de %s ; %s", l.TestID, strings.Join(append(pb, "conforme"), " ; "))
		}
		if vide {
			rap.Verdict(r.CountsForTargets && r.System.Reference, "EX-11.13", nom, "counts_for_targets %v, system.reference %v (vrai attendus), %d lignes", r.CountsForTargets, r.System.Reference, len(r.Results))
		}
		if strings.HasSuffix(f, "-vecteurs.json") {
			if err := d.verifierRapportVecteurs(rap, nom, &r, f); err != nil {
				return err
			}
		}
	}
	return nil
}

// TaillesLignes rend la taille de chaque ligne d'un fichier, saut de ligne
// compris, et le SHA-256 du fichier (EX-A.14, table de 11.3).
func TaillesLignes(octets []byte) ([]int, string) {
	lignes := strings.Split(string(octets), "\n")
	if len(lignes) > 0 && lignes[len(lignes)-1] == "" {
		lignes = lignes[:len(lignes)-1]
	}
	var out []int
	for _, l := range lignes {
		out = append(out, len(l)+1)
	}
	h := sha256.Sum256(octets)
	return out, hex.EncodeToString(h[:])
}

func (d *Depot) verifierRapportVecteurs(rap *Rapport, nom string, r *RapportMesure, chemin string) error {
	rap.Verdict(!r.CountsForTargets && !r.System.Reference, "EX-11.13", nom, "counts_for_targets %v, system.reference %v (faux attendus)", r.CountsForTargets, r.System.Reference)
	segment, err := os.ReadFile(filepath.Join(d.Racine, "spec", "vecteurs", "ct-2", "evenements", "journal-demo", "segment.ndjson"))
	if err != nil {
		return err
	}
	tailles, h := TaillesLignes(segment)
	somme, min, max := 0, 0, 0
	for i, t := range tailles {
		somme += t
		if i == 0 || t < min {
			min = t
		}
		if t > max {
			max = t
		}
	}
	moyenne := float64(int(float64(somme)/float64(len(tailles))*100+0.5)) / 100
	var ligne *ResultatMesure
	for i := range r.Results {
		if r.Results[i].Name == "octets_par_evenement" {
			ligne = &r.Results[i]
		}
	}
	if ligne == nil {
		rap.Discorde("EX-A.14", nom+" octets_par_evenement", "ligne absente")
	} else {
		var samples []int
		_ = jsonUnmarshal(ligne.Samples, &samples)
		attendu := fmt.Sprintf("n %d, samples %v, min %d, max %d, mean %s, SHA-256 %s", len(tailles), tailles, min, max, NombreJS(moyenne), h)
		lu := fmt.Sprintf("n %s, samples %v, min %s, max %s, mean %s", ligne.N, samples, ligne.Min, ligne.Max, ligne.Mean)
		ok := string(ligne.N) == fmt.Sprint(len(tailles)) && fmt.Sprint(samples) == fmt.Sprint(tailles) && string(ligne.Min) == fmt.Sprint(min) && string(ligne.Max) == fmt.Sprint(max) && string(ligne.Mean) == NombreJS(moyenne)
		sha := false
		for _, c := range ligne.Conditions {
			if strings.Contains(c, h) {
				sha = true
			}
		}
		rap.Verdict(ok && sha, "EX-A.14", nom+" octets_par_evenement", "recalculé depuis segment.ndjson : %s ; lu : %s, SHA-256 dans conditions : %v", attendu, lu, sha)
	}
	// Table de 11.3 : « 9 lignes, 14 293 octets, moyenne 1 588,11, min 413, max 2 530 ».
	s := Normaliser(SectionTexte(d.CT9.Texte, "11.3"))
	m := regexp.MustCompile(`([0-9]+) lignes, ([0-9 ]+) octets, moyenne ([0-9 ]+,[0-9]+), min ([0-9 ]+), max ([0-9 ]+) \(saut de ligne compris\)`).FindStringSubmatch(s)
	if m == nil {
		rap.Discorde("EX-11.13", "11.3 octets_par_evenement", "ligne de la table non lue")
	} else {
		n, _ := EntierFrancais(m[1])
		tot, _ := EntierFrancais(m[2])
		moy, _ := EntierFrancais(m[3])
		mn, _ := EntierFrancais(m[4])
		mx, _ := EntierFrancais(m[5])
		rap.Verdict(int(n) == len(tailles) && int(tot) == somme && moy == moyenne && int(mn) == min && int(mx) == max, "EX-11.13", "11.3 octets_par_evenement", "texte : %s lignes, %s octets, moyenne %s, min %s, max %s ; recalculé : %d, %d, %s, %d, %d", m[1], m[2], m[3], m[4], m[5], len(tailles), somme, NombreJS(moyenne), min, max)
	}
	// Bloc JSON de 11.3 : le rapport imprimé sans ses membres samples.
	bloc := regexp.MustCompile("(?s)sans ses membres\\s+`samples`.*?```json\\n(.*?)\\n```").FindStringSubmatch(SectionTexte(d.CT9.Texte, "11.3"))
	if bloc == nil {
		rap.Discorde("EX-11.13", "11.3 bloc JSON", "bloc du rapport sur les vecteurs non lu")
		return nil
	}
	imprime, err := DecoderJSON([]byte(bloc[1]))
	if err != nil {
		rap.Discorde("EX-11.13", "11.3 bloc JSON", "JSON illisible : %v", err)
		return nil
	}
	fichier, err := LireDocument(chemin)
	if err != nil {
		return err
	}
	oi, _ := imprime.(map[string]any)
	of, _ := fichier.(map[string]any)
	var diff []string
	for k, v := range oi {
		if k == "results" {
			continue
		}
		if !EgalJSON(v, of[k]) {
			diff = append(diff, k)
		}
	}
	ri, _ := oi["results"].([]any)
	rf, _ := of["results"].([]any)
	for i := range ri {
		li, _ := ri[i].(map[string]any)
		if i >= len(rf) {
			diff = append(diff, fmt.Sprintf("results[%d] absent du fichier", i))
			continue
		}
		lf, _ := rf[i].(map[string]any)
		for k, v := range li {
			if k == "samples" {
				continue
			}
			if !EgalJSON(v, lf[k]) {
				diff = append(diff, fmt.Sprintf("results[%d].%s", i, k))
			}
		}
	}
	rap.Verdict(len(diff) == 0, "EX-11.13", "11.3 bloc JSON", "%d membres de premier niveau et %d ligne(s) de résultat comparés au fichier, samples exclus ; écarts %v", len(oi)-1, len(ri), diff)
	return nil
}

// verifierConsignations : EX-A.15, gabarit de TR-10.
func (d *Depot) verifierConsignations(rap *Rapport) {
	var c Consignation
	if err := LireJSON(filepath.Join(d.Vecteurs, "consignations", "gabarit-TR-10.json"), &c); err != nil {
		rap.Discorde("EX-A.15", "consignations/gabarit-TR-10.json", "illisible : %v", err)
		return
	}
	t := d.ParID[c.TestID]
	var pb []string
	if c.TestID != "TR-10" || t == nil || t.Replay == nil {
		pb = append(pb, "test_id "+c.TestID+" n'est pas l'entrée TR-10")
	} else {
		if (c.Grid == nil) != (t.Replay.Grid == nil) || (c.Grid != nil && *c.Grid != *t.Replay.Grid) {
			pb = append(pb, "grille différente de celle de TR-10")
		}
		if strings.Join(c.ForbiddenSections, " ; ") != strings.Join(t.Replay.ForbiddenSections, " ; ") {
			pb = append(pb, "sections interdites différentes de celles de TR-10")
		}
	}
	if !EstNull(c.DurationS) {
		pb = append(pb, "duration_s non nul")
	}
	zero := strings.Repeat("0", 64)
	for _, m := range c.Material {
		if m.SHA256 != nil && *m.SHA256 != zero {
			pb = append(pb, "SHA-256 de matériel non nul : "+m.Item)
		}
	}
	if !c.Judge.Independent || !strings.HasPrefix(c.Participant.Pseudonym, "P-") || !strings.HasPrefix(c.Judge.Pseudonym, "J-") {
		pb = append(pb, "juge non indépendant ou pseudonymes mal formés (EX-12.1, EX-12.5)")
	}
	if len(pb) > 0 {
		rap.Discorde("EX-A.15", "consignations/gabarit-TR-10.json", "%s", strings.Join(pb, " ; "))
	} else {
		rap.Concorde("EX-A.15", "consignations/gabarit-TR-10.json", "TR-10, grille et sections interdites égales au catalogue, SHA-256 à zéro, duration_s null, pseudonymes")
	}
}

// GrillePorte2 recalcule les questions de la grille de TR-14 depuis les deux
// tables de la section 14 (critères, entrées, verdict calculable), EX-14.2
// et la table des niveaux (EX-15.2) : q1, un élément par critère « continuer
// si » (« critère : verdict », règles « CT-9 §14 (entrées : …) » et « CT-9
// EX-14.1 ») ; q2, les points d'EX-14.2 (règle « CT-9 EX-14.2 ») ; q3, pour
// chaque niveau, les critères dont les entrées sont de sa famille.
func GrillePorte2(section14 string, niveaux []Niveau) [][]struct{ Element, Rules string } {
	type ligne struct{ critere, entrees, verdict string }
	lire := func(table string) []ligne {
		var out []ligne
		for _, l := range strings.Split(table, "\n") {
			if !strings.HasPrefix(l, "| ") || strings.HasPrefix(l, "| Critère") || strings.HasPrefix(l, "|---") {
				continue
			}
			c := cellules(l)
			if len(c) >= 3 {
				out = append(out, ligne{c[0], c[1], c[2]})
			}
		}
		return out
	}
	tables := regexp.MustCompile(`(?m)(?:^\|.*\n)+`).FindAllString(section14+"\n", -1)
	var cont, stop []ligne
	if len(tables) >= 2 {
		cont, stop = lire(tables[0]), lire(tables[1])
	}
	var q1, q2, q3 []struct{ Element, Rules string }
	for _, r := range cont {
		q1 = append(q1, struct{ Element, Rules string }{r.critere + " : " + r.verdict, "CT-9 §14 (entrées : " + r.entrees + ")\x00CT-9 EX-14.1"})
	}
	if m := regexp.MustCompile(`\*\*EX-14\.2\*\* Ce que la porte 2 ne mesure pas, et le dit : (.*?)\.(\s*\n\s*\n|\s*$)`).FindStringSubmatch(Normaliser(section14) + "\n\n"); m != nil {
		for _, x := range strings.Split(m[1], " ; ") {
			q2 = append(q2, struct{ Element, Rules string }{Normaliser(x), "CT-9 EX-14.2"})
		}
	}
	reFam := regexp.MustCompile(`\b(TU|TV|TI|TE|TA|TM|TR|TQ)-[0-9]`)
	for _, n := range niveaux {
		var co, st []string
		for _, r := range cont {
			for _, f := range reFam.FindAllStringSubmatch(r.entrees, -1) {
				if f[1] == n.ID && !contient(co, r.critere) {
					co = append(co, r.critere)
				}
			}
		}
		for _, r := range stop {
			for _, f := range reFam.FindAllStringSubmatch(r.entrees, -1) {
				if f[1] == n.ID && !contient(st, r.critere) {
					st = append(st, r.critere)
				}
			}
		}
		var parts []string
		if len(co) > 0 {
			parts = append(parts, "continuer si : "+strings.Join(co, " ; "))
		}
		if len(st) > 0 {
			parts = append(parts, "arrêter ou reprendre si : "+strings.Join(st, " ; "))
		}
		q3 = append(q3, struct{ Element, Rules string }{n.ID + "- (" + n.Name + ") : " + strings.Join(parts, " — "), "CT-9 §3.1\x00CT-9 §14"})
	}
	return [][]struct{ Element, Rules string }{q1, q2, q3}
}

// regleConnue dit si la règle d'un élément de grille désigne un identifiant
// ou une section d'une spécification (« CT-5 EX-3.3 », « CT-9 §14 (entrées :
// …) ») ou un fichier des vecteurs (« spec/vecteurs/ct-5/cout/cout.json »).
func (d *Depot) regleConnue(r string) bool {
	base := strings.SplitN(r, " (", 2)[0]
	if d.Connu(base) || d.SectionConnue(base) {
		return true
	}
	if strings.HasPrefix(r, "spec/") {
		_, err := os.Stat(filepath.Join(d.Racine, filepath.FromSlash(r)))
		return err == nil
	}
	return false
}

// verifierGrilles : EX-12.7, EX-15.2, EX-A.9, EX-A.16 pour les trois grilles
// que CT-9 dote lui-même (TR-4, TR-5, TR-14) et leurs consignes.
func (d *Depot) verifierGrilles(rap *Rapport) {
	grilles := []struct{ fichier, consigne, tr string }{
		{"acceptation-ancrage-attendu.json", "acceptation-ancrage/consigne.md", "TR-4"},
		{"acceptation-verdict-point-attendu.json", "acceptation-verdict-point/consigne.md", "TR-5"},
		{"acceptation-porte-2-attendu.json", "acceptation-porte-2/consigne.md", "TR-14"},
	}
	for _, g := range grilles {
		var grille Grille
		if err := LireJSON(filepath.Join(d.Vecteurs, g.fichier), &grille); err != nil {
			rap.Discorde("EX-A.16", g.fichier, "illisible : %v", err)
			continue
		}
		t := d.ParID[g.tr]
		var pb []string
		if grille.Kind != "grille-acceptation" || grille.TestID != g.tr {
			pb = append(pb, fmt.Sprintf("kind %q, test_id %q", grille.Kind, grille.TestID))
		}
		if t == nil || t.Replay == nil || t.Replay.Grid == nil || *t.Replay.Grid != "spec/vecteurs/ct-9/"+g.fichier {
			pb = append(pb, "le membre grid de "+g.tr+" ne désigne pas ce fichier")
		}
		nbElements := 0
		for _, q := range grille.Questions {
			for _, e := range q.Elements {
				nbElements++
				for _, r := range e.Rules {
					if !d.regleConnue(r) {
						pb = append(pb, "règle inconnue "+r)
					}
				}
			}
		}
		consigne, err := os.ReadFile(filepath.Join(d.Vecteurs, filepath.FromSlash(g.consigne)))
		if err != nil {
			pb = append(pb, "consigne illisible")
		} else {
			texte := Normaliser(string(consigne))
			for _, q := range grille.Questions {
				for _, e := range q.Elements {
					if strings.Contains(texte, Normaliser(e.Element)) {
						pb = append(pb, "la consigne contient l'élément « "+e.Element+" »")
					}
				}
			}
			if g.tr != "TR-14" {
				n := len(regexp.MustCompile(`(?m)^[0-9]+\. `).FindAllString(string(consigne), -1))
				if n != len(grille.Questions) {
					pb = append(pb, fmt.Sprintf("%d questions numérotées dans la consigne, %d dans la grille", n, len(grille.Questions)))
				}
			}
		}
		if len(pb) > 0 {
			rap.Discorde("EX-A.16", g.fichier, "%s", strings.Join(pb, " ; "))
		} else {
			rap.Concorde("EX-A.16", g.fichier, "grille de %s : %d questions, %d éléments, %d affirmation(s) disqualifiante(s) ; règles connues ; consigne %s sans aucun élément", g.tr, len(grille.Questions), nbElements, len(grille.Disqualifying), g.consigne)
		}
		if g.tr == "TR-14" {
			attendu := GrillePorte2(SectionTexte(d.CT9.Texte, "14"), d.Cat.Levels)
			var diff []string
			if len(grille.Questions) != len(attendu) {
				diff = append(diff, fmt.Sprintf("%d questions, %d attendues", len(grille.Questions), len(attendu)))
			}
			for i := 0; i < len(attendu) && i < len(grille.Questions); i++ {
				q := grille.Questions[i]
				if len(q.Elements) != len(attendu[i]) {
					diff = append(diff, fmt.Sprintf("%s : %d éléments, %d attendus", q.ID, len(q.Elements), len(attendu[i])))
					continue
				}
				for j, e := range q.Elements {
					if e.Element != attendu[i][j].Element || strings.Join(e.Rules, "\x00") != attendu[i][j].Rules {
						diff = append(diff, fmt.Sprintf("%s élément %d : « %s » (règles %v) au lieu de « %s »", q.ID, j+1, e.Element, e.Rules, attendu[i][j].Element))
					}
				}
			}
			rap.Verdict(len(diff) == 0, "EX-15.2", g.fichier, "q1 (%d critères « continuer si »), q2 (%d points d'EX-14.2), q3 (%d niveaux) recalculés depuis la section 14 et la table des niveaux ; écarts %v", len(attendu[0]), len(attendu[1]), len(attendu[2]), diff)
			rap.Verdict(len(grille.Disqualifying) == 3, "EX-15.2", g.fichier+" disqualifying", "%d affirmations (EX-15.2 en nomme trois : conformité à un texte, périmètre de capture, attaquant hors du modèle)", len(grille.Disqualifying))
		}
	}
	// TR-5 : la consigne nomme un rapport de vérification d'un dossier ct-6 qui existe (EX-A.16).
	if consigne, err := os.ReadFile(filepath.Join(d.Vecteurs, "acceptation-verdict-point", "consigne.md")); err == nil {
		chemins := regexp.MustCompile("(spec/vecteurs/ct-6/[^\\s`]+)").FindAllStringSubmatch(string(consigne), -1)
		var absents []string
		for _, c := range chemins {
			if _, err := os.Stat(filepath.Join(d.Racine, filepath.FromSlash(c[1]))); err != nil {
				absents = append(absents, c[1])
			}
		}
		rap.Verdict(len(chemins) > 0 && len(absents) == 0, "EX-A.16", "acceptation-verdict-point/consigne.md", "%d chemin(s) ct-6 cités, absents %v", len(chemins), absents)
	}
}

// Extraits : fichier, source, découpe (EX-12.2, EX-A.16, table 12.2).
var Extraits = []struct {
	Fichier, Source                string
	RetirerL2, RetirerL3, GarderL2 []string
}{
	{"CT-7-sans-9-A15.md", "CT-7", []string{"9"}, []string{"A.15"}, nil},
	{"CT-8-sans-14-A.md", "CT-8", []string{"14", "Annexe A"}, nil, nil},
	{"CT-8-13.md", "CT-8", nil, nil, []string{"13"}},
	{"CT-8-12.md", "CT-8", nil, nil, []string{"12"}},
	{"CT-7-7.md", "CT-7", nil, nil, []string{"7"}},
	{"CT-9-sans-15.md", "CT-9", []string{"15"}, nil, nil},
}

// verifierExtraits : chaque extrait égale la découpe de sa spécification ;
// SHA256SUMS égale les condensés recalculés.
func (d *Depot) verifierExtraits(rap *Rapport) error {
	sommes := map[string]string{}
	for _, e := range Extraits {
		src := d.ParSpec[e.Source]
		attendu := Couper(src.Texte, e.RetirerL2, e.RetirerL3, e.GarderL2)
		octets, err := os.ReadFile(filepath.Join(d.Vecteurs, "extraits", e.Fichier))
		if err != nil {
			rap.Discorde("EX-A.16", "extraits/"+e.Fichier, "illisible : %v", err)
			continue
		}
		h := sha256.Sum256(octets)
		sommes[e.Fichier] = hex.EncodeToString(h[:])
		rap.Verdict(string(octets) == attendu, "EX-12.2", "extraits/"+e.Fichier, "%s découpé (retirer %v, %v ; garder %v) : %d octets recalculés, %d publiés", e.Source, e.RetirerL2, e.RetirerL3, e.GarderL2, len(attendu), len(octets))
	}
	liste, err := os.ReadFile(filepath.Join(d.Vecteurs, "extraits", "SHA256SUMS"))
	if err != nil {
		return err
	}
	lus := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(liste)), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 {
			lus[f[1]] = f[0]
		}
	}
	for _, e := range Extraits {
		rap.Verdict(lus[e.Fichier] == sommes[e.Fichier], "EX-A.16", "extraits/SHA256SUMS "+e.Fichier, "%s recalculé, %s publié", sommes[e.Fichier], lus[e.Fichier])
	}
	rap.Verdict(len(lus) == len(Extraits), "EX-A.16", "extraits/SHA256SUMS", "%d lignes, %d extraits", len(lus), len(Extraits))
	return nil
}

// EtatIndex est l'état d'une entrée tel qu'INDEX.md l'imprime.
func EtatIndex(t *Test) string {
	s := t.Status
	if s.State == "a_ecrire" {
		return fmt.Sprintf("à écrire (étape %d)", *s.Phase2Step)
	}
	if s.Complement != nil {
		return "exécutable, complément à écrire"
	}
	return "exécutable"
}

// verifierIndexMD : EX-A.2, INDEX.md liste chaque entrée (identifiant,
// niveau, état, titre), chaque cas avec son attendu, et ses comptes.
func (d *Depot) verifierIndexMD(rap *Rapport) {
	octets, err := os.ReadFile(filepath.Join(d.Vecteurs, "INDEX.md"))
	if err != nil {
		rap.Discorde("EX-A.2", "INDEX.md", "illisible : %v", err)
		return
	}
	idx := string(octets)
	rap.Verdict(strings.Contains(idx, "ne pas\nl'éditer à la main") || strings.Contains(Normaliser(idx), "ne pas l'éditer à la main"), "EX-A.2", "INDEX.md en-tête", "dit qu'il est produit par le générateur et ne doit pas être édité")
	var absents []string
	for i := range d.Cat.Tests {
		t := &d.Cat.Tests[i]
		ligne := fmt.Sprintf("| %s | %s- | %s | %s |", t.ID, t.Level, EtatIndex(t), esc(t.Title))
		if !strings.Contains(idx, ligne) {
			absents = append(absents, t.ID)
		}
	}
	rap.Verdict(len(absents) == 0, "EX-A.2", "INDEX.md catalogue", "%d entrées (identifiant, niveau, état, titre) ; absentes %v", len(d.Cat.Tests), absents)
	n := Normaliser(idx)
	m := regexp.MustCompile(`([0-9]+) entrées, ([0-9]+) justifications NC-, ([0-9]+) risques acceptés, ([0-9]+) lignes TC-`).FindStringSubmatch(n)
	lus := "phrase non lue"
	if m != nil {
		lus = strings.Join(m[1:], ", ")
	}
	rap.Verdict(m != nil && m[1] == fmt.Sprint(len(d.Cat.Tests)) && m[2] == fmt.Sprint(len(d.Cat.NonTests)) && m[3] == fmt.Sprint(len(d.Cat.AcceptedRisks)) && m[4] == fmt.Sprint(len(d.Cat.Traceability)), "EX-A.2", "INDEX.md comptes du catalogue", "entrées, NC-, RA-, TC- : texte %s ; recalculé %d, %d, %d, %d", lus, len(d.Cat.Tests), len(d.Cat.NonTests), len(d.Cat.AcceptedRisks), len(d.Cat.Traceability))
	r := &d.Resultats.Mien
	attendu := fmt.Sprintf("%d identifiants définis par CT-1 à CT-8, %d couverts par une entrée, %d par une justification NC-, %d non couvert(s) ; %d menaces sur %d avec un TA- ; %d occurrences de « CT-9 » et %d lignes TC- ; %d entrées exécutables citant %d titres ou étapes, %d absent(s) ; %d tables du texte comparées, %d différence(s)", r.Identifiers.Total, r.Identifiers.CoveredByTests, r.Identifiers.CoveredByNC, r.Identifiers.Uncovered, r.Threats.WithTA, r.Threats.Total, r.Traceability.Occurrences, r.Traceability.Rows, r.Executable.Total, r.Executable.TitlesChecked, len(r.Executable.TitlesMissing), r.TextTables.Compared, len(r.TextTables.Differences))
	rap.Verdict(strings.Contains(n, attendu), "EX-A.2", "INDEX.md couverture.json", "résumé recalculé « %s »", attendu)
	// Cas de cas/, mesures/cas/, consignations/cas/.
	type fam struct{ liste, prefixe string }
	for _, f := range []fam{{"cas/attendu.json", "cas"}, {"mesures/cas/cas.json", "mesures/cas"}, {"consignations/cas/cas.json", "consignations/cas"}} {
		var liste ListeCas
		if err := LireJSON(filepath.Join(d.Vecteurs, f.liste), &liste); err != nil {
			continue
		}
		var abs []string
		for _, c := range liste.Cases {
			var ligne string
			if f.prefixe == "cas" {
				mot := "—"
				if c.Keyword != nil {
					mot = "`" + *c.Keyword + "`"
				}
				ligne = fmt.Sprintf("| `cas/%s` | %s | %s |", c.File, c.Expected, mot)
			} else {
				ligne = fmt.Sprintf("| `%s/%s` | %s | %s |", f.prefixe, c.File, c.Expected, c.Reason)
			}
			if !strings.Contains(idx, ligne) {
				abs = append(abs, c.File)
			}
		}
		rap.Verdict(len(abs) == 0, "EX-A.2", "INDEX.md "+f.prefixe+"/", "%d cas avec leur attendu ; absents %v", len(liste.Cases), abs)
	}
	for _, g := range []struct{ fichier, tr string }{{"acceptation-ancrage-attendu.json", "TR-4"}, {"acceptation-verdict-point-attendu.json", "TR-5"}, {"acceptation-porte-2-attendu.json", "TR-14"}} {
		var grille Grille
		if err := LireJSON(filepath.Join(d.Vecteurs, g.fichier), &grille); err != nil {
			continue
		}
		nb := 0
		for _, q := range grille.Questions {
			nb += len(q.Elements)
		}
		ligne := fmt.Sprintf("| `%s` | %s | grille : %d questions, %d éléments, %d affirmation(s) disqualifiante(s) |", g.fichier, g.tr, len(grille.Questions), nb, len(grille.Disqualifying))
		rap.Verdict(strings.Contains(idx, ligne), "EX-A.2", "INDEX.md "+g.fichier, "%s", ligne)
	}
}

// verifierProse : chiffres et identifiants que la prose de CT-9 énonce sans
// ambiguïté (sections 6, 7, 12.2, 13, 16), recalculés depuis le catalogue.
func (d *Depot) verifierProse(rap *Rapport) {
	parEtat := func(niveau, etat string) []string {
		var out []string
		for i := range d.Cat.Tests {
			t := &d.Cat.Tests[i]
			if t.Level == niveau && t.Status.State == etat {
				out = append(out, t.ID)
			}
		}
		return out
	}
	rap.Verdict(len(parEtat("TU", "a_ecrire")) == 0, "6", "TU- à écrire", "%v (texte : les trente-neuf exécutables, TU-12 depuis l'étape 1)", parEtat("TU", "a_ecrire"))
	s7 := Normaliser(SectionTexte(d.CT9.Texte, "7"))
	m := regexp.MustCompile(`(TV-[0-9]+) \(vérificateur Go de CT-6\) l'est depuis l'étape 2, et (TV-[0-9]+) \(famille .supervision/., étape 7\) est à écrire`).FindStringSubmatch(s7)
	tvAE := parEtat("TV", "a_ecrire")
	if m == nil {
		rap.Discorde("7", "TV- à écrire", "phrase « TV-n (vérificateur Go de CT-6) l'est depuis l'étape 2, et TV-m … est à écrire » non lue")
	} else {
		rap.Verdict(strings.Join(tvAE, ",") == m[2], "7", "TV- à écrire", "texte : %s ; catalogue : %v", m[2], tvAE)
		for id, etat := range map[string]string{m[1]: "executable", m[2]: "a_ecrire"} {
			t := d.ParID[id]
			titre := ""
			if t != nil {
				titre = t.Title
			}
			attendu := map[string]string{m[1]: "CT-6", m[2]: "supervision"}[id]
			rap.Verdict(t != nil && t.Status.State == etat && strings.Contains(titre, attendu), "7", id, "texte : %s, objet « %s » ; catalogue : état %s, titre « %s »", etat, attendu, etatDe(t), titre)
		}
	}
	rap.Verdict(len(parEtat("TR", "executable")) == 0 && len(parEtat("TR", "a_ecrire")) == 15, "12.2", "TR- à écrire", "%d à écrire, %d exécutables (texte : quinze épreuves, toutes à écrire)", len(parEtat("TR", "a_ecrire")), len(parEtat("TR", "executable")))
	tq := parEtat("TQ", "a_ecrire")
	etapes := map[string]int{}
	for _, id := range tq {
		etapes[id] = *d.ParID[id].Status.Phase2Step
	}
	ok := len(tq) == 8 && len(parEtat("TQ", "executable")) == 0 && etapes["TQ-8"] == 7
	for id, e := range etapes {
		if id != "TQ-8" && e != 8 {
			ok = false
		}
	}
	rap.Verdict(ok, "13", "TQ- à écrire", "%d entrées, étapes %v (texte : huit, toutes à écrire, étape 8, étape 7 pour la chaîne de construction)", len(tq), etapes)
	s16 := Normaliser(SectionTexte(d.CT9.Texte, "16"))
	var aEcrire, compl, compl4, tmAE int
	for i := range d.Cat.Tests {
		t := &d.Cat.Tests[i]
		if t.Status.State == "a_ecrire" {
			aEcrire++
			if t.Level == "TM" {
				tmAE++
			}
		}
		if t.Status.Complement != nil {
			// Section 16 : « les compléments des n TA- exécutables » ;
			// le complément de TV-55 (publication, étape 7) est nommé à part.
			if t.Level == "TA" {
				compl++
			}
			if t.Status.Complement.Phase2Step == 4 {
				compl4++
			}
		}
	}
	lire := func(re *regexp.Regexp, objet string, attendu int) {
		x := re.FindStringSubmatch(s16)
		if x == nil {
			rap.Discorde("16", objet, "non lu dans le texte")
			return
		}
		n, okN := EntierFrancais(x[1])
		rap.Verdict(okN && int(n) == attendu, "16", objet, "texte %s, recalculé %d", x[1], attendu)
	}
	lire(regexp.MustCompile(`: ([0-9]+) entrées du catalogue \(table de 5\.5\)`), "entrées à écrire", aEcrire)
	lire(regexp.MustCompile(`les compléments des ([a-z]+) TA- exécutables`), "TA- avec complément", compl)
	lire(regexp.MustCompile(`les compléments des ([a-z]+) entrées de l'étape 4`), "compléments de l'étape 4", compl4)
	lire(regexp.MustCompile(`les ([0-9]+) entrées TM- « à écrire »`), "TM- à écrire", tmAE)
	if x := regexp.MustCompile(`\(binaire de CT-6 §14\) : (TV-[0-9]+) à écrire`).FindStringSubmatch(s16); x != nil {
		t := d.ParID[x[1]]
		rap.Verdict(t != nil && t.Status.State == "a_ecrire" && strings.Contains(t.Title, "CT-6"), "16", x[1], "texte : vérificateur Go de CT-6 à écrire ; catalogue : état %s, titre « %s »", etatDe(t), titreDe(t))
	}
}

func etatDe(t *Test) string {
	if t == nil {
		return "absent"
	}
	return t.Status.State
}

func titreDe(t *Test) string {
	if t == nil {
		return ""
	}
	return t.Title
}

// horsPerimetre nomme les valeurs publiées que le texte seul ne permet pas
// de recalculer, avec leur raison.
func (d *Depot) horsPerimetre(rap *Rapport) {
	rap.HorsPerimetre("EX-A.7", "couverture.json date, tool.command", "date et commande d'une exécution de l'outil JavaScript, exclues de la comparaison par EX-A.7 ; lues : %s, %q", d.Publie.Date, d.Publie.Tool.Command)
	rap.HorsPerimetre("EX-5.9", "couverture.json errors (texte des écarts)", "le libellé des écarts est celui de l'outil JavaScript ; seul le nombre (%d) est comparé au verdict recalculé", len(d.Publie.Errors))
	rap.HorsPerimetre("EX-A.3", "cas/attendu.json mot-clé fautif (ordre)", "l'ordre des erreurs d'un validateur tiers n'est pas fixé par le texte ; le mot-clé attendu est confronté à l'ensemble des mots-clés violés, pas au premier")
	rap.HorsPerimetre("EX-3.11", "comptes de npx hardhat test (cas réussis, en attente)", "résultat d'exécution de npx hardhat test ; le vérificateur n'exécute aucun test")
	rap.HorsPerimetre("10.8", "« N passing », mutants tués", "résultat d'exécution de test/adversarial.test.js ; le nombre de mutants vit dans le code du test, que le vérificateur ne lit pas")
	rap.HorsPerimetre("EX-11.13", "mesures/rapport-2026-11-01-vecteurs.json octets_ligne_annexe_a (2465), p1_cadence_vecteurs", "valeurs rendues par test/enregistreur.test.js et recalculées par le générateur depuis ct-1 (délais aux points) ; seule la ligne octets_par_evenement se recalcule ici depuis le segment")
	rap.HorsPerimetre("EX-11.13", "mesures/rapport-*.json commit, measured_at, system", "commit éprouvé, instant et machine d'une exécution ; le bloc de 11.3 les reprend et c'est cette égalité qui est contrôlée")
	rap.HorsPerimetre("EX-A.16", "acceptation-ancrage-attendu.json, acceptation-verdict-point-attendu.json éléments", "paraphrases des étapes de TR-4 et TR-5 et des sections de CT-5 et CT-6 citées ; non recalculables mot pour mot (règles, consigne et comptes contrôlés)")
	rap.HorsPerimetre("EX-15.2", "grilles disqualifying (libellés)", "paraphrases d'EX-15.2, de CT-5 EX-3.2 et de CT-6 §7.9 ; seul le nombre de la grille de TR-14 est contrôlé")
	rap.HorsPerimetre("EX-A.15", "consignations/gabarit-TR-10.json verdict.elements", "éléments d'exemple tirés de CT-8 EX-14.8 ; aucune règle de CT-9 n'en fixe le texte")
	rap.HorsPerimetre("EX-11.14", "TM- failure_threshold (texte)", "seuil d'échec écrit en toutes lettres ; seule la réserve de TM-22 (480 min) est contrôlée")
	rap.HorsPerimetre("EX-5.7", "NC- : « ne couvre jamais un EX- en DOIT dont le sujet est un composant »", "jugement sur le sujet de chaque EX- ; non mécanisable")
	rap.HorsPerimetre("16", "« 18 entrées TA- » de phase 2", "définition du compte ambiguë : %d TA- à menace à écrire d'exécution phase_2 (dont TA-95, épreuve de procédure), %d d'exécution vecteurs_et_depot, 5 scénarios", compteTA(d, "phase_2"), compteTA(d, "vecteurs_et_depot"))
	rap.HorsPerimetre("EX-A.18", "confrontation/sorties/recompte.txt", "sortie d'un programme Python ; la comparaison à couverture.json est celle de test/plan-de-tests.test.js et de la CI")
	rap.HorsPerimetre("EX-A.1", "déterminisme du générateur (deux générations identiques)", "propriété d'une exécution du générateur, que le vérificateur ne lance pas")
}

func compteTA(d *Depot, execution string) int {
	n := 0
	for i := range d.Cat.Tests {
		t := &d.Cat.Tests[i]
		if t.Level == "TA" && t.Adversarial != nil && t.Adversarial.Threat != nil && t.Status.State == "a_ecrire" && t.Adversarial.Execution == execution {
			n++
		}
	}
	return n
}
