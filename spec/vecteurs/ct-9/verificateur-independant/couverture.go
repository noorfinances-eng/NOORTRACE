package main

// Recomptage de la couverture (CT-9 §5.1, règles (a) à (d), EX-5.5 ;
// §10.1, EX-10.1, EX-10.2 ; §10.5 ; §10.6 ; EX-A.13) et des règles
// propres aux niveaux TA-, TM- et TR- (EX-A.17), puis comparaison membre
// par membre au rapport publié couverture.json.

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

func jsonUnmarshal(r json.RawMessage, v any) error { return json.Unmarshal(r, v) }

func sha256Fichier(chemin string) (string, error) {
	octets, err := os.ReadFile(chemin)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(octets)
	return hex.EncodeToString(h[:]), nil
}

var reIDNiveau = regexp.MustCompile(`^(TU|TV|TI|TE|TA|TM|TR|TQ)-([1-9][0-9]*)$`)

// Depot rassemble ce que le vérificateur lit, pour les contrôles.
type Depot struct {
	Racine    string
	Vecteurs  string
	Specs     []*Specification
	ParSpec   map[string]*Specification
	CT9       *Specification
	Cat       Catalogue
	ParID     map[string]*Test
	Publie    RapportCouverture
	Menaces   Menaces
	TexteCI   string
	Titres    map[string]TitresFichier
	Fichiers  []string // test/*.test.js
	Schema    *Schema
	Occ       []Occurrence
	Resultats Resultats
}

// Resultats sont les nombres recalculés, repris par plusieurs contrôles.
type Resultats struct {
	Mien          RapportCouverture
	Inconnus      []string
	SansTA        []string
	TitresAbsents []TitreAbsent
	Tables        map[string][]string
	Compared      int
	Differences   []string
}

// Connu dit si « CT-n X » est un identifiant défini par CT-n (5.2).
func (d *Depot) Connu(id string) bool {
	m := reIDCatalog.FindStringSubmatch(id)
	return m != nil && d.ParSpec[m[1]] != nil && d.ParSpec[m[1]].IDs[m[2]]
}

// SectionConnue dit si « CT-n §s » est une section de CT-n.
func (d *Depot) SectionConnue(id string) bool {
	m := reSectionCat.FindStringSubmatch(id)
	return m != nil && d.ParSpec[m[1]] != nil && d.ParSpec[m[1]].Sections[m[2]]
}

// Verifier relit le dépôt et rend le rapport du vérificateur.
func Verifier(racine string) (*Rapport, error) {
	rap := &Rapport{Racine: racine}
	d := &Depot{Racine: racine, Vecteurs: filepath.Join(racine, "spec", "vecteurs", "ct-9"), ParSpec: map[string]*Specification{}, ParID: map[string]*Test{}}
	var err error
	if d.Specs, err = LireSpecifications(racine); err != nil {
		return nil, err
	}
	for _, s := range d.Specs {
		d.ParSpec[s.ID] = s
	}
	if d.CT9, err = LireSpecification(racine, "CT-9-plan-de-tests.md"); err != nil {
		return nil, err
	}
	d.ParSpec["CT-9"] = d.CT9
	if err := LireJSON(filepath.Join(d.Vecteurs, "catalogue.json"), &d.Cat); err != nil {
		return nil, err
	}
	for i := range d.Cat.Tests {
		d.ParID[d.Cat.Tests[i].ID] = &d.Cat.Tests[i]
	}
	if err := LireJSON(filepath.Join(d.Vecteurs, "couverture.json"), &d.Publie); err != nil {
		return nil, err
	}
	if err := LireJSON(filepath.Join(racine, "spec", "vecteurs", "ct-7", "menaces.json"), &d.Menaces); err != nil {
		return nil, err
	}
	ci, err := os.ReadFile(filepath.Join(racine, ".github", "workflows", "ci.yml"))
	if err != nil {
		return nil, err
	}
	d.TexteCI = string(ci)
	if d.Titres, d.Fichiers, err = IndexTitres(racine); err != nil {
		return nil, err
	}
	if d.Schema, err = ChargerSchema(filepath.Join(racine, "spec", "schemas", "plan-de-tests-v0.schema.json")); err != nil {
		return nil, err
	}
	if d.Occ, err = OccurrencesCT9(racine, d.Specs); err != nil {
		return nil, err
	}

	d.verifierRacine(rap)
	d.verifierIdentifiants(rap)
	d.verifierCouvertureA(rap)
	d.verifierMenaces(rap)
	d.verifierIndex(rap)
	d.verifierTraceabilite(rap)
	d.verifierTitres(rap)
	if err := d.verifierTables(rap); err != nil {
		return nil, err
	}
	d.verifierMesuresEtRejeux(rap)
	d.comparerPublie(rap)
	if err := d.verifierCondenses(rap); err != nil {
		return nil, err
	}
	if err := d.verifierSchemas(rap); err != nil {
		return nil, err
	}
	if err := d.verifierCas(rap); err != nil {
		return nil, err
	}
	if err := d.verifierRapportsMesure(rap); err != nil {
		return nil, err
	}
	d.verifierConsignations(rap)
	d.verifierGrilles(rap)
	if err := d.verifierExtraits(rap); err != nil {
		return nil, err
	}
	d.verifierIndexMD(rap)
	d.verifierProse(rap)
	d.horsPerimetre(rap)

	m := &d.Resultats.Mien
	rap.Comptes = Comptes{Entrees: len(d.Cat.Tests), Identifiants: m.Identifiers.Total, CouvertsParEntree: m.Identifiers.CoveredByTests, CouvertsParNC: m.Identifiers.CoveredByNC, NonCouverts: m.Identifiers.Uncovered, Menaces: m.Threats.Total, MenacesAvecTA: m.Threats.WithTA, Occurrences: m.Traceability.Occurrences, LignesTC: m.Traceability.Rows, Executables: m.Executable.Total, TitresCites: m.Executable.TitlesChecked, TablesComparees: m.TextTables.Compared}
	rap.Clore()
	return rap, nil
}

// verifierRacine : membres de la racine du catalogue et en-tête du texte.
func (d *Depot) verifierRacine(rap *Rapport) {
	c := &d.Cat
	rap.Verdict(c.Version == 0 && c.Kind == "plan-de-tests" && c.Spec == "CT-9", "EX-4.3", "catalogue.json racine", "version %d, kind %q, spec %q", c.Version, c.Kind, c.Spec)
	rap.Verdict(c.SpecVersion == d.CT9.Version, "EX-4.3", "catalogue.json spec_version", "%q dans le catalogue, « Version %s » dans l'en-tête de CT-9", c.SpecVersion, d.CT9.Version)
	date := regexp.MustCompile(`(?m)^Version [0-9.]+, ([0-9]{4}-[0-9]{2}-[0-9]{2})`).FindStringSubmatch(d.CT9.Texte)
	enTete := "non lue"
	if date != nil {
		enTete = date[1]
	}
	rap.Verdict(date != nil && c.Date == date[1], "EX-4.3", "catalogue.json date", "%q dans le catalogue, %s dans l'en-tête de CT-9", c.Date, enTete)
	rap.Verdict(len(c.Levels) == 8 && len(c.Phase2Steps) == 8, "EX-4.3", "catalogue.json levels, phase2_steps", "%d niveaux, %d étapes (huit attendus)", len(c.Levels), len(c.Phase2Steps))
	for _, l := range c.Levels {
		titre := regexp.MustCompile(`(?m)^## ` + regexp.QuoteMeta(l.Section) + `\. .*\(` + regexp.QuoteMeta(l.ID) + `-\)\s*$`)
		rap.Verdict(titre.MatchString(d.CT9.Texte), "3.1", l.ID+"- section", "la section %s du texte est le titre de niveau 2 « (%s-) »", l.Section, l.ID)
	}
	for i, e := range c.Phase2Steps {
		rap.Verdict(e.Step == i+1, "3.4", fmt.Sprintf("étape %d", e.Step), "numéro %d en position %d", e.Step, i+1)
	}
}

// verifierIdentifiants : EX-3.1 (unicité, forme, numéros qui se suivent),
// EX-3.10 (états), EX-4.1 (blocs propres), identifiants des TC-, NC-, RA-.
func (d *Depot) verifierIdentifiants(rap *Rapport) {
	compteurs := map[string]int{}
	vus := map[string]bool{}
	for i := range d.Cat.Tests {
		t := &d.Cat.Tests[i]
		var pb []string
		if vus[t.ID] {
			pb = append(pb, "identifiant en double")
		}
		vus[t.ID] = true
		m := reIDNiveau.FindStringSubmatch(t.ID)
		if m == nil || m[1] != t.Level {
			pb = append(pb, fmt.Sprintf("identifiant ou niveau mal formé (niveau %s)", t.Level))
		} else {
			compteurs[t.Level]++
			if fmt.Sprintf("%s-%d", t.Level, compteurs[t.Level]) != t.ID {
				pb = append(pb, fmt.Sprintf("attendu %s-%d (numéros qui se suivent dans l'ordre du catalogue)", t.Level, compteurs[t.Level]))
			}
		}
		s := t.Status
		switch s.State {
		case "executable":
			if s.Command == "" || (len(s.Tests) == 0 && len(s.CISteps) == 0) {
				pb = append(pb, "exécutable sans commande ou sans titre ni étape cités")
			}
		case "a_ecrire":
			if s.Phase2Step == nil || s.Blocking == "" || s.Complement != nil {
				pb = append(pb, "à écrire sans étape ou sans blocage, ou avec complément")
			}
		default:
			pb = append(pb, fmt.Sprintf("état inconnu %q", s.State))
		}
		blocs := map[string]bool{"adversarial": t.Adversarial != nil, "measure": t.Measure != nil, "replay": t.Replay != nil, "review": t.Review != nil}
		attendu := map[string]string{"TA": "adversarial", "TM": "measure", "TR": "replay", "TQ": "review"}[t.Level]
		for nom, present := range blocs {
			if present && nom != attendu {
				pb = append(pb, "bloc "+nom+" interdit à ce niveau")
			}
			if !present && nom == attendu {
				pb = append(pb, "bloc "+nom+" absent")
			}
		}
		if len(t.Preconditions) == 0 || len(t.Steps) == 0 || t.Oracle == "" || len(t.Specs) == 0 {
			pb = append(pb, "préconditions, étapes, oracle ou specs vides")
		}
		if len(pb) > 0 {
			rap.Discorde("EX-3.1", t.ID, "%s", strings.Join(pb, " ; "))
		} else {
			rap.Concorde("EX-3.1", t.ID, "identifiant unique de la famille %s, état %s conforme à EX-3.10, blocs d'EX-4.1 conformes", t.Level, s.State)
		}
	}
	for i, n := range d.Cat.Traceability {
		rap.Verdict(n.ID == fmt.Sprintf("TC-%d", i+1), "0.2", n.ID, "position %d", i+1)
	}
	for i, n := range d.Cat.NonTests {
		rap.Verdict(n.ID == fmt.Sprintf("NC-%d", i+1), "5.3", n.ID, "position %d", i+1)
	}
	for i, r := range d.Cat.AcceptedRisks {
		rap.Verdict(r.ID == fmt.Sprintf("RA-%d", i+1), "10.6", r.ID, "position %d", i+1)
	}
}

// verifierCouvertureA : règle (a) et EX-5.5, par spécification, avec la
// justification NC- de chaque identifiant qu'aucune entrée ne couvre.
func (d *Depot) verifierCouvertureA(rap *Rapport) {
	couvertParTest := map[string][]string{}
	couvertParNC := map[string][]string{}
	var inconnus []string
	menaceConnue := map[string]bool{}
	for _, m := range d.Menaces.Threats {
		menaceConnue[m.ID] = true
	}
	for i := range d.Cat.Tests {
		t := &d.Cat.Tests[i]
		for _, id := range t.Covers {
			if strings.Contains(id, "§") {
				rap.Verdict(d.SectionConnue(id), "EX-4.1", t.ID+" covers "+id, "section citée pour situer l'objet, non comptée")
				continue
			}
			if !d.Connu(id) {
				inconnus = append(inconnus, t.ID+" : "+id)
			}
			couvertParTest[id] = append(couvertParTest[id], t.ID)
		}
		for _, mn := range t.Threats {
			if t.Level == "TA" {
				id := "CT-7 " + mn
				if !d.Connu(id) || !menaceConnue[mn] {
					inconnus = append(inconnus, t.ID+" : "+id)
				}
				couvertParTest[id] = append(couvertParTest[id], t.ID)
			} else if !menaceConnue[mn] {
				rap.Discorde("EX-4.1", t.ID, "menace citée inconnue %s", mn)
			}
		}
	}
	categories := map[string]bool{"definition": true, "convention": true, "texte_descriptif": true, "delegue": true, "hors_version_0": true, "renvoi": true, "proposition": true, "ligne_de_modele": true, "non_verifie": true}
	for _, nc := range d.Cat.NonTests {
		ok := categories[nc.Category] && len(nc.Justification) > 0 && len(nc.Covers) > 0 && (nc.Category != "delegue" || nc.DelegatedTo != "")
		rap.Verdict(ok, "EX-5.7", nc.ID, "catégorie %s, %d identifiants, justification de %d caractères", nc.Category, len(nc.Covers), len(nc.Justification))
		for _, id := range nc.Covers {
			if !d.Connu(id) {
				inconnus = append(inconnus, nc.ID+" : "+id)
			}
			couvertParNC[id] = append(couvertParNC[id], nc.ID)
		}
	}
	sort.Strings(inconnus)
	rap.Verdict(len(inconnus) == 0, "EX-5.5", "identifiants cités inconnus", "%d : %s", len(inconnus), strings.Join(inconnus, ", "))
	var perSpec []ParSpec
	var total, cbt, cbn, unc int
	for _, s := range d.Specs {
		p := ParSpec{Spec: s.ID, Families: map[string]int{}, UncoveredIDs: []string{}}
		var ids []string
		for x := range s.IDs {
			ids = append(ids, x)
		}
		sort.Strings(ids)
		for _, x := range ids {
			id := s.ID + " " + x
			p.Total++
			p.Families[Famille(x)]++
			switch {
			case len(couvertParTest[id]) > 0:
				p.CoveredByTests++
			case len(couvertParNC[id]) > 0:
				p.CoveredByNC++
				ncs := couvertParNC[id]
				var cats []string
				for _, n := range ncs {
					for _, nc := range d.Cat.NonTests {
						if nc.ID == n {
							cats = append(cats, nc.Category)
						}
					}
				}
				rap.Concorde("EX-5.1", id, "couvert par aucune entrée ; justifié par %s (%s)", strings.Join(ncs, ", "), strings.Join(cats, ", "))
			default:
				p.UncoveredIDs = append(p.UncoveredIDs, id)
				rap.Discorde("EX-5.1", id, "couvert par aucune entrée ni aucune justification NC-")
			}
		}
		p.Uncovered = len(p.UncoveredIDs)
		rap.Verdict(p.Uncovered == 0, "EX-5.1", s.ID, "%d identifiants définis (%d EX-), %d couverts par une entrée, %d par un NC-, %d non couverts", p.Total, comptePrefixe(s.IDs, "EX-"), p.CoveredByTests, p.CoveredByNC, p.Uncovered)
		perSpec = append(perSpec, p)
		total += p.Total
		cbt += p.CoveredByTests
		cbn += p.CoveredByNC
		unc += p.Uncovered
	}
	rap.Verdict(unc == 0, "EX-5.1", "total", "%d identifiants définis par CT-1 à CT-8 : %d couverts par une entrée, %d par un NC-, %d non couverts", total, cbt, cbn, unc)
	m := &d.Resultats.Mien
	m.Identifiers.Total, m.Identifiers.CoveredByTests, m.Identifiers.CoveredByNC, m.Identifiers.Uncovered = total, cbt, cbn, unc
	m.Identifiers.UnknownCited = inconnus
	m.Identifiers.PerSpec = perSpec
	d.Resultats.Inconnus = inconnus
}

func comptePrefixe(ids map[string]bool, prefixe string) int {
	n := 0
	for x := range ids {
		if strings.HasPrefix(x, prefixe) {
			n++
		}
	}
	return n
}

// verifierMenaces : règle (b), EX-10.1 à EX-10.4, EX-10.7, scénarios
// (10.5), risques acceptés (10.6).
func (d *Depot) verifierMenaces(rap *Rapport) {
	menaceConnue := map[string]*Menace{}
	for i := range d.Menaces.Threats {
		menaceConnue[d.Menaces.Threats[i].ID] = &d.Menaces.Threats[i]
	}
	avecTA := map[string]bool{}
	var TA []*Test
	for i := range d.Cat.Tests {
		if d.Cat.Tests[i].Level == "TA" {
			TA = append(TA, &d.Cat.Tests[i])
			for _, mn := range d.Cat.Tests[i].Threats {
				avecTA[mn] = true
			}
		}
	}
	var sansTA []string
	for _, m := range d.Menaces.Threats {
		if !avecTA[m.ID] {
			sansTA = append(sansTA, m.ID)
		}
		var ta []*Test
		for _, t := range TA {
			if t.Adversarial != nil && t.Adversarial.Threat != nil && *t.Adversarial.Threat == m.ID {
				ta = append(ta, t)
			}
		}
		if len(ta) != 1 {
			rap.Discorde("EX-10.1", m.ID, "%d TA- de menace (un attendu)", len(ta))
			continue
		}
		t := ta[0]
		a := t.Adversarial
		var pb []string
		if t.ID != "TA-"+strings.TrimPrefix(m.ID, "MN-") {
			pb = append(pb, fmt.Sprintf("%s au lieu de TA-%s", t.ID, strings.TrimPrefix(m.ID, "MN-")))
		}
		if len(t.Threats) != 1 || t.Threats[0] != m.ID {
			pb = append(pb, "threats diffère de ["+m.ID+"]")
		}
		if a.ThreatTestText == nil || *a.ThreatTestText != m.Test {
			pb = append(pb, "threat_test_text diffère du membre test de menaces.json")
		}
		if !strings.HasPrefix(m.Test, "Le test échoue si la réponse est retirée : ") {
			pb = append(pb, "texte de test sans le préfixe fixe")
		}
		if strings.Join(t.Covers, "\x00") != strings.Join(m.Response.Refs, "\x00") {
			pb = append(pb, "covers diffère de response.refs")
		}
		if a.Component == nil || *a.Component != m.Component {
			pb = append(pb, "component diffère de menaces.json")
		}
		var raAttendu *string
		if m.Residual != nil && m.Residual.AcceptedRisk != nil {
			id := m.Residual.AcceptedRisk.ID
			raAttendu = &id
		}
		if (a.AcceptedRisk == nil) != (raAttendu == nil) || (a.AcceptedRisk != nil && *a.AcceptedRisk != *raAttendu) {
			pb = append(pb, "accepted_risk diffère de menaces.json")
		}
		if a.Execution != "vecteurs_et_depot" && a.Execution != "phase_2" {
			pb = append(pb, fmt.Sprintf("execution %q inconnue", a.Execution))
		}
		if a.ResponseRemoved.What == "" || a.ResponseRemoved.How == "" || a.ResponseRemoved.Where == "" || a.Attack == "" {
			pb = append(pb, "réponse retirée ou attaque vide")
		}
		// EX-10.7 : un it de test/adversarial.test.js nomme un mutant tué, sauf
		// les deux oracles sur un vecteur d'EX-10.4 (TA-23, TA-72), dont le
		// mutant est la régénération et l'observation le git diff de la CI.
		if t.Status.State == "executable" && t.ID != "TA-23" && t.ID != "TA-72" {
			for _, x := range t.Status.Tests {
				if x.File == "test/adversarial.test.js" && x.It != nil {
					if lu, ok := LireTitreTA(*x.It); !ok || !lu.Tue {
						pb = append(pb, "le titre cité dans test/adversarial.test.js n'a pas la forme d'EX-10.7 (TA-, menace, « (tué) »)")
					} else if !contient(lu.TAs, t.ID) {
						pb = append(pb, fmt.Sprintf("cite dans test/adversarial.test.js un it dont le titre nomme %v et non %s (EX-10.7)", lu.TAs, t.ID))
					}
				}
			}
		}
		if len(pb) > 0 {
			rap.Discorde("EX-10.1", m.ID, "%s", strings.Join(pb, " ; "))
		} else {
			rap.Concorde("EX-10.1", m.ID, "%s : threats, threat_test_text, covers (%d), component %s, accepted_risk égaux à menaces.json ; execution %s", t.ID, len(t.Covers), m.Component, a.Execution)
		}
	}
	for _, id := range []string{"TA-23", "TA-72"} {
		t := d.ParID[id]
		where := ""
		if t != nil && t.Adversarial != nil {
			where = t.Adversarial.ResponseRemoved.Where
		}
		rap.Verdict(t != nil && t.Status.State == "executable" && (strings.Contains(strings.ToLower(where), "génér") || strings.Contains(strings.ToLower(where), "generer")), "EX-10.4", id, "exécutable, réponse retirée dans un générateur : « %s »", where)
	}
	for _, t := range TA {
		if t.Adversarial == nil || t.Adversarial.Threat != nil {
			continue
		}
		a := t.Adversarial
		var pb []string
		if len(a.Composition) < 2 {
			pb = append(pb, "scénario sans composition")
		}
		var covers, threats []string
		vuC, vuT := map[string]bool{}, map[string]bool{}
		for _, id := range a.Composition {
			c := d.ParID[id]
			if c == nil || c.Adversarial == nil || c.Adversarial.Threat == nil {
				pb = append(pb, "compose "+id+", qui n'est pas un TA- à menace")
				continue
			}
			for _, x := range c.Covers {
				if !vuC[x] {
					vuC[x] = true
					covers = append(covers, x)
				}
			}
			for _, x := range c.Threats {
				if !vuT[x] {
					vuT[x] = true
					threats = append(threats, x)
				}
			}
		}
		if strings.Join(covers, "\x00") != strings.Join(t.Covers, "\x00") {
			pb = append(pb, "covers n'est pas l'union ordonnée des covers composés")
		}
		if strings.Join(threats, "\x00") != strings.Join(t.Threats, "\x00") {
			pb = append(pb, "threats n'est pas l'union des menaces composées")
		}
		if a.Component != nil || a.AcceptedRisk != nil || a.ThreatTestText != nil {
			pb = append(pb, "component, accepted_risk ou threat_test_text non nuls")
		}
		if t.Status.State != "a_ecrire" || t.Status.Phase2Step == nil || *t.Status.Phase2Step != 8 || a.Execution != "phase_2" {
			pb = append(pb, "scénario qui n'est pas à écrire à l'étape 8 en phase 2")
		}
		if !strings.HasSuffix(t.Title, "("+strings.Join(a.Composition, ", ")+")") {
			pb = append(pb, "titre sans la liste des tests composés")
		}
		if len(pb) > 0 {
			rap.Discorde("10.5", t.ID, "%s", strings.Join(pb, " ; "))
		} else {
			rap.Concorde("10.5", t.ID, "scénario de %d tests, %d menaces, covers = union des covers composés, à écrire (étape 8)", len(a.Composition), len(t.Threats))
		}
	}
	rap.Verdict(len(d.scenarios()) == 5, "10.5", "scénarios", "%d scénarios (cinq attendus : TA-103 à TA-107)", len(d.scenarios()))
	var raMenaces []Menace
	for _, m := range d.Menaces.Threats {
		if m.Residual != nil && m.Residual.AcceptedRisk != nil {
			raMenaces = append(raMenaces, m)
		}
	}
	rap.Verdict(len(d.Cat.AcceptedRisks) == len(raMenaces), "10.6", "accepted_risks", "%d dans le catalogue, %d risques acceptés dans menaces.json", len(d.Cat.AcceptedRisks), len(raMenaces))
	parRA := map[string]*Risque{}
	for i := range d.Cat.AcceptedRisks {
		parRA[d.Cat.AcceptedRisks[i].ID] = &d.Cat.AcceptedRisks[i]
	}
	for _, m := range raMenaces {
		a := m.Residual.AcceptedRisk
		r := parRA[a.ID]
		if r == nil {
			rap.Discorde("10.6", a.ID, "absent du catalogue")
			continue
		}
		var pb []string
		if r.Name != a.Name || r.Bound != a.Bound || r.Owner != a.Owner || r.Threat != m.ID {
			pb = append(pb, "nom, borne, porteur ou menace diffèrent de menaces.json")
		}
		t := d.ParID[r.Test]
		if t == nil || t.Adversarial == nil || t.Adversarial.Threat == nil || *t.Adversarial.Threat != r.Threat {
			pb = append(pb, fmt.Sprintf("test %s absent ou d'une autre menace", r.Test))
		} else if t.Status.State != r.TestState {
			pb = append(pb, fmt.Sprintf("test_state %s diffère de l'état de %s", r.TestState, r.Test))
		}
		if r.Tested == "" || r.NotTested == "" {
			pb = append(pb, "tested ou not_tested vide")
		}
		if len(pb) > 0 {
			rap.Discorde("10.6", r.ID, "%s", strings.Join(pb, " ; "))
		} else {
			rap.Concorde("10.6", r.ID, "menace %s, test %s (%s), nom, borne et porteur égaux à menaces.json", r.Threat, r.Test, r.TestState)
		}
	}
	rap.Verdict(len(sansTA) == 0, "EX-5.2", "menaces", "%d menaces sur %d avec un TA- ; sans TA- : %v", len(d.Menaces.Threats)-len(sansTA), len(d.Menaces.Threats), sansTA)
	m := &d.Resultats.Mien
	m.Threats.Total, m.Threats.WithTA, m.Threats.WithoutTA = len(d.Menaces.Threats), len(d.Menaces.Threats)-len(sansTA), sansTA
	d.Resultats.SansTA = sansTA
}

func (d *Depot) scenarios() []*Test {
	var out []*Test
	for i := range d.Cat.Tests {
		t := &d.Cat.Tests[i]
		if t.Level == "TA" && t.Adversarial != nil && t.Adversarial.Threat == nil {
			out = append(out, t)
		}
	}
	return out
}

func contient(l []string, x string) bool {
	for _, y := range l {
		if y == x {
			return true
		}
	}
	return false
}

// verifierIndex : EX-A.13, index-ta-par-menace.json recalculé depuis le
// catalogue (TA-, état, scénarios qui le composent).
func (d *Depot) verifierIndex(rap *Rapport) {
	var index IndexParMenace
	if err := LireJSON(filepath.Join(d.Vecteurs, "index-ta-par-menace.json"), &index); err != nil {
		rap.Discorde("EX-A.13", "index-ta-par-menace.json", "illisible : %v", err)
		return
	}
	rap.Verdict(index.Version == 0 && index.Date == d.Cat.Date, "EX-A.13", "index-ta-par-menace.json en-tête", "version %d, date %s (catalogue : %s)", index.Version, index.Date, d.Cat.Date)
	attendu := map[string]EntreeIndex{}
	for i := range d.Cat.Tests {
		t := &d.Cat.Tests[i]
		if t.Level != "TA" || t.Adversarial == nil || t.Adversarial.Threat == nil {
			continue
		}
		e := EntreeIndex{Test: t.ID, State: t.Status.State, Scenarios: []string{}}
		for _, s := range d.scenarios() {
			if contient(s.Adversarial.Composition, t.ID) {
				e.Scenarios = append(e.Scenarios, s.ID)
			}
		}
		attendu[*t.Adversarial.Threat] = e
	}
	rap.Verdict(len(index.Index) == len(attendu), "EX-A.13", "index-ta-par-menace.json", "%d menaces indexées, %d TA- à menace dans le catalogue", len(index.Index), len(attendu))
	for _, mn := range ClesTriees(compteCles(attendu)) {
		a := attendu[mn]
		lu, ok := index.Index[mn]
		egal := ok && lu.Test == a.Test && lu.State == a.State && strings.Join(lu.Scenarios, ",") == strings.Join(a.Scenarios, ",")
		rap.Verdict(egal, "EX-A.13", "index "+mn, "%s, %s, scénarios %v", a.Test, a.State, a.Scenarios)
	}
}

func compteCles(m map[string]EntreeIndex) map[string]int {
	out := map[string]int{}
	for k := range m {
		out[k] = 1
	}
	return out
}

// verifierTraceabilite : règle (c), EX-0.1, EX-5.3 et les comptes par
// fichier que la section 0.2 imprime.
func (d *Depot) verifierTraceabilite(rap *Rapport) {
	var clesOcc, clesTC []string
	for _, o := range d.Occ {
		clesOcc = append(clesOcc, o.Cle)
	}
	for _, r := range d.Cat.Traceability {
		clesTC = append(clesTC, r.Key)
	}
	mo, mt := MultiEnsemble(clesOcc), MultiEnsemble(clesTC)
	var missing, orphans []string
	for _, k := range ClesTriees(mo) {
		if mt[k] < mo[k] {
			missing = append(missing, fmt.Sprintf("%s (%d)", k, mo[k]-mt[k]))
		}
	}
	for _, k := range ClesTriees(mt) {
		if mo[k] < mt[k] {
			orphans = append(orphans, fmt.Sprintf("%s (%d)", k, mt[k]-mo[k]))
		}
	}
	for _, k := range ClesTriees(mo) {
		rap.Verdict(mo[k] == mt[k], "EX-5.3", k, "%d occurrence(s) de « CT-9 », %d ligne(s) TC-", mo[k], mt[k])
	}
	for _, k := range ClesTriees(mt) {
		if mo[k] == 0 {
			rap.Discorde("EX-5.3", k, "%d ligne(s) TC- sans occurrence", mt[k])
		}
	}
	for _, r := range d.Cat.Traceability {
		rap.Verdict(r.Line >= 1 && r.Delegated != "" && r.Response != "", "EX-0.1", r.ID, "ligne %d, clé %s, réponse de %d caractères", r.Line, r.Key, len(r.Response))
	}
	rap.Verdict(len(missing) == 0 && len(orphans) == 0, "EX-5.3", "total", "%d occurrences de « CT-9 », %d lignes TC- ; manques %v, orphelines %v", len(d.Occ), len(d.Cat.Traceability), missing, orphans)
	// Comptes par fichier imprimés en 0.2 : « N occurrences sur M lignes (CT-1 : 1 ; … ) ».
	s := Normaliser(SectionTexte(d.CT9.Texte, "0.2"))
	m := regexp.MustCompile(`\*\*([0-9]+) occurrences sur ([0-9]+) lignes\*\* \((.*?)\)\. La table`).FindStringSubmatch(s)
	if m == nil {
		rap.Discorde("0.2", "comptes par fichier", "phrase « N occurrences sur M lignes (…) » non lue dans le texte")
	} else {
		occParFichier, lignesParFichier := map[string]int{}, map[string]int{}
		lignesVues := map[string]bool{}
		for _, o := range d.Occ {
			occParFichier[o.Fichier]++
			k := fmt.Sprintf("%s:%d", o.Fichier, o.Ligne)
			if !lignesVues[k] {
				lignesVues[k] = true
				lignesParFichier[o.Fichier]++
			}
		}
		rap.Verdict(m[1] == fmt.Sprint(len(d.Occ)) && m[2] == fmt.Sprint(len(lignesVues)), "0.2", "occurrences et lignes", "texte : %s occurrences sur %s lignes ; recalculé : %d sur %d", m[1], m[2], len(d.Occ), len(lignesVues))
		reItem := regexp.MustCompile(`^(.+?) : ([0-9]+)(?: occurrences sur ([0-9]+) lignes)?$`)
		for _, item := range strings.Split(m[3], " ; ") {
			im := reItem.FindStringSubmatch(strings.TrimSpace(item))
			if im == nil {
				rap.Discorde("0.2", item, "compte par fichier non lu")
				continue
			}
			occ, lignes := im[2], im[3]
			if lignes == "" {
				lignes = occ
			}
			f := im[1]
			rap.Verdict(occ == fmt.Sprint(occParFichier[f]) && lignes == fmt.Sprint(lignesParFichier[f]), "0.2", f, "texte : %s occurrences sur %s lignes ; recalculé : %d sur %d", occ, lignes, occParFichier[f], lignesParFichier[f])
		}
	}
	r := &d.Resultats.Mien
	r.Traceability.Occurrences, r.Traceability.Rows, r.Traceability.Missing, r.Traceability.Orphans = len(d.Occ), len(d.Cat.Traceability), missing, orphans
}

// verifierTitres : règle (d), EX-4.2, EX-5.4, et EX-10.7 / EX-A.11 sur
// test/adversarial.test.js.
func (d *Depot) verifierTitres(rap *Rapport) {
	ci := EtapesCI(d.TexteCI)
	var titresAbsents []TitreAbsent
	var exeTotal, titresCites int
	for i := range d.Cat.Tests {
		t := &d.Cat.Tests[i]
		if t.Status.State != "executable" {
			continue
		}
		exeTotal++
		var absents []string
		for _, x := range t.Status.Tests {
			titresCites++
			if !TitreExiste(d.Titres, x) {
				titre := x.Describe
				if x.It != nil {
					titre += " | " + *x.It
				}
				titresAbsents = append(titresAbsents, TitreAbsent{t.ID, x.File, titre})
				absents = append(absents, x.File+" : "+titre)
			}
		}
		for _, s := range t.Status.CISteps {
			titresCites++
			if !ci[s] {
				titresAbsents = append(titresAbsents, TitreAbsent{t.ID, ".github/workflows/ci.yml", s})
				absents = append(absents, "ci.yml : "+s)
			}
		}
		rap.Verdict(len(absents) == 0, "EX-5.4", t.ID, "%d titre(s) et %d étape(s) cités ; absents : %v", len(t.Status.Tests), len(t.Status.CISteps), absents)
	}
	rap.Verdict(len(titresAbsents) == 0, "EX-5.4", "total", "%d entrées exécutables, %d titres ou étapes cités, %d absent(s)", exeTotal, titresCites, len(titresAbsents))
	// EX-10.7, EX-A.11 : chaque it de test/adversarial.test.js.
	adv, ok := d.Titres["test/adversarial.test.js"]
	if !ok {
		rap.Discorde("EX-A.11", "test/adversarial.test.js", "fichier absent")
	} else {
		citePar := map[string]map[string]bool{} // it → TA- qui le citent
		for i := range d.Cat.Tests {
			t := &d.Cat.Tests[i]
			for _, x := range t.Status.Tests {
				if x.File == "test/adversarial.test.js" && x.It != nil {
					if citePar[*x.It] == nil {
						citePar[*x.It] = map[string]bool{}
					}
					citePar[*x.It][t.ID] = true
				}
			}
		}
		for _, c := range adv.Cas {
			lu, ok := LireTitreTA(c.It)
			var pb []string
			if !ok {
				pb = append(pb, "titre sans la forme d'EX-10.7")
			} else {
				// EX-10.4 : TA-23 et TA-72 n'ont pas de mutant à tuer dans le fichier
				// (la régénération en tient lieu) ; les autres finissent par « (tué) »
				// ou « (tués) » (EX-10.7).
				regeneration := true
				for _, id := range lu.TAs {
					if id != "TA-23" && id != "TA-72" {
						regeneration = false
					}
				}
				if !lu.Tue && !regeneration {
					pb = append(pb, "titre sans « (tué) » ni « (tués) »")
				}
				var menaces []string
				for _, id := range lu.TAs {
					t := d.ParID[id]
					if t == nil || t.Level != "TA" || t.Status.State != "executable" || !citePar[c.It][id] {
						pb = append(pb, id+" absent du catalogue, non exécutable ou ne cite pas cet it")
						continue
					}
					menaces = append(menaces, t.Threats...)
				}
				if strings.Join(menaces, ",") != strings.Join(lu.Menaces, ",") {
					pb = append(pb, fmt.Sprintf("menaces du titre %v, menaces des TA- %v", lu.Menaces, menaces))
				}
			}
			objet := c.It
			if len(objet) > 60 {
				objet = objet[:57] + "…"
			}
			if len(pb) > 0 {
				rap.Discorde("EX-10.7", objet, "%s", strings.Join(pb, " ; "))
			} else {
				mutant := "mutant(s) tué(s)"
				if !lu.Tue {
					mutant = "oracle sur le vecteur, mutant = régénération (EX-10.4)"
				}
				rap.Concorde("EX-10.7", objet, "TA- %v exécutables et citant cet it, menaces %v, %s", lu.TAs, lu.Menaces, mutant)
			}
		}
		// EX-A.11 : « 60 it répartis en dix describe par composant ».
		s := Normaliser(SectionTexte(d.CT9.Texte, "A.6"))
		m := regexp.MustCompile("([0-9]+) `it` répartis en ([a-zé-]+) `describe`").FindStringSubmatch(s)
		nbDescribes := len(adv.Describes) - 1 // le describe englobant n'est pas un composant
		if m == nil {
			rap.Discorde("EX-A.11", "test/adversarial.test.js", "phrase « N it répartis en N describe » non lue dans A.6")
		} else {
			its, _ := EntierFrancais(m[1])
			desc, okD := EntierFrancais(m[2])
			rap.Verdict(int(its) == len(adv.Cas) && okD && int(desc) == nbDescribes, "EX-A.11", "test/adversarial.test.js", "texte : %s it en %s describe ; lus : %d it, %d describe par composant", m[1], m[2], len(adv.Cas), nbDescribes)
		}
	}
	r := &d.Resultats.Mien
	r.Executable.Total, r.Executable.TitlesChecked, r.Executable.TitlesMissing = exeTotal, titresCites, titresAbsents
}

// verifierTables : EX-4.4, EX-A.4, EX-5.10.
func (d *Depot) verifierTables(rap *Rapport) error {
	tables, err := ImprimerTables(&d.Cat)
	if err != nil {
		return err
	}
	compared, differences := ComparerTables(tables, d.CT9.Texte)
	parTable := map[string][]string{}
	for _, x := range differences {
		nom := strings.TrimPrefix(strings.SplitN(x, " ", 3)[1], "")
		nom = strings.TrimSuffix(nom, ",")
		parTable[nom] = append(parTable[nom], x)
	}
	for _, nom := range Tables {
		rap.Verdict(len(parTable[nom]) == 0, "EX-4.4", "table "+nom, "%d lignes imprimées depuis le catalogue ; différences : %v", len(tables[nom])-2, parTable[nom])
	}
	for nom := range parTable {
		if !contient(Tables, nom) {
			rap.Discorde("EX-4.4", "table "+nom, "%v", parTable[nom])
		}
	}
	d.Resultats.Tables, d.Resultats.Compared, d.Resultats.Differences = tables, compared, differences
	r := &d.Resultats.Mien
	r.TextTables.Compared, r.TextTables.Differences = compared, differences
	d.chiffres55(rap)
	return nil
}

var (
	re55Identifiants = regexp.MustCompile(`([0-9]+) identifiants définis par CT-1 à CT-8 : ([0-9]+) couverts par une entrée, ([0-9]+) par une justification NC-, \*\*([0-9]+) non couverts?\*\*`)
	re55Menaces      = regexp.MustCompile(`([0-9]+) menaces sur ([0-9]+) avec un TA-`)
	re55Occurrences  = regexp.MustCompile(`([0-9]+) occurrences de « CT-9 » et ([0-9]+) lignes TC-`)
	re55Executables  = regexp.MustCompile(`([0-9]+) entrées exécutables citant ([0-9]+) titres`)
)

// chiffres55 compare les chiffres imprimés en 5.5 (EX-5.10) aux chiffres
// recalculés.
func (d *Depot) chiffres55(rap *Rapport) {
	s := Normaliser(SectionTexte(d.CT9.Texte, "5.5"))
	m := &d.Resultats.Mien
	lire := func(re *regexp.Regexp, nom string, attendus ...int) {
		x := re.FindStringSubmatch(s)
		if x == nil {
			rap.Discorde("EX-5.10", "5.5 "+nom, "non lu dans le texte")
			return
		}
		var lus []string
		ok := true
		for i, a := range attendus {
			lus = append(lus, x[i+1])
			if x[i+1] != fmt.Sprint(a) {
				ok = false
			}
		}
		rap.Verdict(ok, "EX-5.10", "5.5 "+nom, "texte %v, recalculé %v", lus, attendus)
	}
	lire(re55Identifiants, "identifiants", m.Identifiers.Total, m.Identifiers.CoveredByTests, m.Identifiers.CoveredByNC, m.Identifiers.Uncovered)
	lire(re55Menaces, "menaces", m.Threats.WithTA, m.Threats.Total)
	lire(re55Occurrences, "occurrences", m.Traceability.Occurrences, m.Traceability.Rows)
	lire(re55Executables, "exécutables", m.Executable.Total, m.Executable.TitlesChecked)
	for _, p := range m.Identifiers.PerSpec {
		lire(regexp.MustCompile(regexp.QuoteMeta(p.Spec)+` ([0-9]+), ([0-9]+), ([0-9]+)`), p.Spec, p.Total, p.CoveredByTests, p.CoveredByNC)
	}
	// 5.2 : inventaire par spécification (EX-, vérifications, total, familles, version).
	inv := SectionTexte(d.CT9.Texte, "5.2")
	reLigne := regexp.MustCompile(`(?m)^\| (CT-[1-8]) \(([0-9.]+)\) \| ([0-9]+) \| ([0-9]+) \| ([0-9]+) \| (.*?) \|$`)
	lignes := reLigne.FindAllStringSubmatch(inv, -1)
	rap.Verdict(len(lignes) == 8, "EX-5.6", "5.2 inventaire", "%d lignes de spécification lues (huit attendues)", len(lignes))
	for _, l := range lignes {
		s := d.ParSpec[l[1]]
		if s == nil {
			continue
		}
		ex := comptePrefixe(s.IDs, "EX-")
		fam := map[string]int{}
		for x := range s.IDs {
			if !strings.HasPrefix(x, "EX-") {
				fam[Famille(x)]++
			}
		}
		var pb []string
		if l[2] != s.Version {
			pb = append(pb, fmt.Sprintf("version %s dans la table, %s dans l'en-tête de %s", l[2], s.Version, s.ID))
		}
		if l[3] != fmt.Sprint(ex) || l[4] != fmt.Sprint(len(s.IDs)-ex) || l[5] != fmt.Sprint(len(s.IDs)) {
			pb = append(pb, fmt.Sprintf("EX-/vérifications/total : table %s/%s/%s, recalculé %d/%d/%d", l[3], l[4], l[5], ex, len(s.IDs)-ex, len(s.IDs)))
		}
		lus := map[string]int{}
		for _, item := range strings.Split(l[6], ", ") {
			parts := strings.Fields(item)
			if len(parts) == 2 {
				n, _ := EntierFrancais(parts[1])
				lus[parts[0]] = int(n)
			}
		}
		if len(lus) != len(fam) {
			pb = append(pb, fmt.Sprintf("%d familles dans la table, %d recalculées", len(lus), len(fam)))
		}
		for k, v := range fam {
			if lus[k] != v {
				pb = append(pb, fmt.Sprintf("famille %s : %d dans la table, %d recalculé", k, lus[k], v))
			}
		}
		if len(pb) > 0 {
			rap.Discorde("EX-5.6", "5.2 "+s.ID, "%s", strings.Join(pb, " ; "))
		} else {
			rap.Concorde("EX-5.6", "5.2 "+s.ID, "version %s, %d EX-, %d vérifications, %d familles égales à la table", s.Version, ex, len(s.IDs)-ex, len(fam))
		}
	}
	if t := regexp.MustCompile(`(?m)^\| Total \| ([0-9]+) \| ([0-9]+) \| ([0-9]+) \| — \|$`).FindStringSubmatch(inv); t != nil {
		var ex, tot int
		for _, s := range d.Specs {
			ex += comptePrefixe(s.IDs, "EX-")
			tot += len(s.IDs)
		}
		rap.Verdict(t[1] == fmt.Sprint(ex) && t[2] == fmt.Sprint(tot-ex) && t[3] == fmt.Sprint(tot), "EX-5.6", "5.2 total", "table %s/%s/%s, recalculé %d/%d/%d", t[1], t[2], t[3], ex, tot-ex, tot)
	} else {
		rap.Discorde("EX-5.6", "5.2 total", "ligne Total non lue")
	}
}

// verifierMesuresEtRejeux : EX-A.17 pour TM- (measured nul, source définie,
// result_name unique, cible et comparaison cohérentes, EX-11.14, EX-11.16)
// et TR- (grille existante ou null, EX-12.7, EX-3.8).
func (d *Depot) verifierMesuresEtRejeux(rap *Rapport) {
	noms := map[string]string{}
	var executables []string
	for i := range d.Cat.Tests {
		t := &d.Cat.Tests[i]
		switch t.Level {
		case "TM":
			if t.Measure == nil {
				continue
			}
			m := t.Measure
			var pb []string
			if !EstNull(m.Measured) {
				pb = append(pb, "measured non nul (EX-11.16)")
			}
			if autre, vu := noms[m.ResultName]; vu {
				pb = append(pb, fmt.Sprintf("result_name %q déjà porté par %s", m.ResultName, autre))
			}
			noms[m.ResultName] = t.ID
			if strings.Contains(m.Source, "§") {
				if !d.SectionConnue(m.Source) {
					pb = append(pb, fmt.Sprintf("source %s, section inconnue", m.Source))
				}
			} else if !d.Connu(m.Source) {
				pb = append(pb, fmt.Sprintf("source %s non définie dans sa spécification", m.Source))
			}
			if m.Comparison == "aucune_cible" && !EstNull(m.Target) || m.Comparison != "aucune_cible" && EstNull(m.Target) {
				pb = append(pb, "cible et comparaison incohérentes (EX-11.14)")
			}
			if m.Quantity == "" || m.Unit == "" || m.FailureThreshold == "" || m.Method == "" {
				pb = append(pb, "grandeur, unité, seuil d'échec ou méthode vide (EX-3.7)")
			}
			if t.Status.State == "executable" {
				executables = append(executables, t.ID)
			}
			if len(pb) > 0 {
				rap.Discorde("EX-A.17", t.ID, "%s", strings.Join(pb, " ; "))
			} else {
				rap.Concorde("EX-A.17", t.ID, "measured nul, source %s définie, result_name %s unique, comparaison %s", m.Source, m.ResultName, m.Comparison)
			}
		case "TR":
			if t.Replay == nil {
				continue
			}
			r := t.Replay
			var pb []string
			if r.Grid != nil {
				if _, err := os.Stat(filepath.Join(d.Racine, filepath.FromSlash(*r.Grid))); err != nil {
					pb = append(pb, fmt.Sprintf("grille %s introuvable", *r.Grid))
				}
			}
			if r.Participant == "" || len(r.Material) == 0 || r.Judge == "" || r.VerdictRule == "" {
				pb = append(pb, "participant, matériel, juge ou règle de verdict vide (EX-3.8)")
			}
			if t.Status.State != "a_ecrire" || t.Status.Phase2Step == nil || *t.Status.Phase2Step != 8 {
				pb = append(pb, "épreuve qui n'est pas à écrire à l'étape 8 (12.2)")
			}
			if len(pb) > 0 {
				rap.Discorde("EX-12.7", t.ID, "%s", strings.Join(pb, " ; "))
			} else {
				grille := "verdict d'outil"
				if r.Grid != nil {
					grille = *r.Grid
				}
				rap.Concorde("EX-12.7", t.ID, "grille %s, à écrire (étape 8)", grille)
			}
		}
	}
	sort.Strings(executables)
	rap.Verdict(strings.Join(executables, ",") == "TM-10,TM-11,TM-12,TM-13,TM-14,TM-15,TM-16,TM-17,TM-18,TM-19,TM-20,TM-22,TM-24,TM-26,TM-28,TM-29,TM-30,TM-31,TM-41,TM-42,TM-6", "EX-11.16", "TM- exécutables", "%v (texte : TM-6, TM-10, TM-31, TM-16, TM-11 à TM-14, TM-17 à TM-19, TM-30, TM-41, TM-42, TM-15, TM-20 ; étape 7 : TM-22, TM-24, TM-26, TM-28, TM-29)", executables)
	if t := d.ParID["TM-22"]; t != nil && t.Measure != nil {
		rap.Verdict(string(t.Measure.Target) == "450" && t.Measure.Unit == "min" && strings.Contains(t.Measure.FailureThreshold, "480"), "EX-11.14", "TM-22", "cible %s %s, seuil « %s »", t.Measure.Target, t.Measure.Unit, t.Measure.FailureThreshold)
	}
}

// comparerPublie compare le rapport recalculé au rapport publié, membre par
// membre (EX-A.17).
func (d *Depot) comparerPublie(rap *Rapport) {
	mien, publie := &d.Resultats.Mien, &d.Publie
	cmp := func(nom string, a, b any) {
		rap.Verdict(fmt.Sprint(a) == fmt.Sprint(b), "couverture.json", nom, "%v recalculé, %v publié", a, b)
	}
	cmpListe := func(nom string, a, b []string) {
		rap.Verdict(egalesTriees(a, b), "couverture.json", nom, "%v recalculé, %v publié", a, b)
	}
	rap.Verdict(publie.Version == 0 && publie.Kind == "rapport-couverture", "couverture.json", "version, kind", "%d, %q", publie.Version, publie.Kind)
	rap.Verdict(publie.Tool.Name == "scripts/tests/couverture.mjs", "couverture.json", "tool.name", "%q (EX-5.8)", publie.Tool.Name)
	cmp("identifiers.total", mien.Identifiers.Total, publie.Identifiers.Total)
	cmp("identifiers.covered_by_tests", mien.Identifiers.CoveredByTests, publie.Identifiers.CoveredByTests)
	cmp("identifiers.covered_by_nc", mien.Identifiers.CoveredByNC, publie.Identifiers.CoveredByNC)
	cmp("identifiers.uncovered", mien.Identifiers.Uncovered, publie.Identifiers.Uncovered)
	cmpListe("identifiers.unknown_cited", mien.Identifiers.UnknownCited, publie.Identifiers.UnknownCited)
	if len(mien.Identifiers.PerSpec) != len(publie.Identifiers.PerSpec) {
		rap.Discorde("couverture.json", "identifiers.per_spec", "%d spécifications recalculées, %d publiées", len(mien.Identifiers.PerSpec), len(publie.Identifiers.PerSpec))
	} else {
		for i, p := range mien.Identifiers.PerSpec {
			q := publie.Identifiers.PerSpec[i]
			cmp(p.Spec+".spec", p.Spec, q.Spec)
			cmp(p.Spec+".total", p.Total, q.Total)
			cmp(p.Spec+".covered_by_tests", p.CoveredByTests, q.CoveredByTests)
			cmp(p.Spec+".covered_by_nc", p.CoveredByNC, q.CoveredByNC)
			cmp(p.Spec+".uncovered", p.Uncovered, q.Uncovered)
			cmpListe(p.Spec+".uncovered_ids", p.UncoveredIDs, q.UncoveredIDs)
			var diff []string
			for _, k := range ClesTriees(p.Families) {
				if q.Families[k] != p.Families[k] {
					diff = append(diff, fmt.Sprintf("%s : %d recalculé, %d publié", k, p.Families[k], q.Families[k]))
				}
			}
			for k := range q.Families {
				if _, ok := p.Families[k]; !ok {
					diff = append(diff, k+" publiée, non recalculée")
				}
			}
			rap.Verdict(len(diff) == 0, "couverture.json", p.Spec+".families", "%d familles ; écarts %v", len(p.Families), diff)
		}
	}
	cmp("threats.total", mien.Threats.Total, publie.Threats.Total)
	cmp("threats.with_ta", mien.Threats.WithTA, publie.Threats.WithTA)
	cmpListe("threats.without_ta", mien.Threats.WithoutTA, publie.Threats.WithoutTA)
	cmp("traceability.occurrences", mien.Traceability.Occurrences, publie.Traceability.Occurrences)
	cmp("traceability.rows", mien.Traceability.Rows, publie.Traceability.Rows)
	cmpListe("traceability.missing", mien.Traceability.Missing, publie.Traceability.Missing)
	cmpListe("traceability.orphans", mien.Traceability.Orphans, publie.Traceability.Orphans)
	cmp("executable.total", mien.Executable.Total, publie.Executable.Total)
	cmp("executable.titles_checked", mien.Executable.TitlesChecked, publie.Executable.TitlesChecked)
	cmp("executable.titles_missing (nombre)", len(mien.Executable.TitlesMissing), len(publie.Executable.TitlesMissing))
	cmp("text_tables.compared", mien.TextTables.Compared, publie.TextTables.Compared)
	cmp("text_tables.differences (nombre)", len(mien.TextTables.Differences), len(publie.TextTables.Differences))
	verdict := "reussi"
	if len(mien.Identifiers.UnknownCited) > 0 || mien.Identifiers.Uncovered > 0 || len(mien.Threats.WithoutTA) > 0 || len(mien.Traceability.Missing) > 0 || len(mien.Traceability.Orphans) > 0 || len(mien.Executable.TitlesMissing) > 0 || len(mien.TextTables.Differences) > 0 {
		verdict = "echec"
	}
	cmp("verdict", verdict, publie.Verdict)
	rap.Verdict(len(publie.Errors) == 0 == (verdict == "reussi"), "couverture.json", "errors", "%d entrée(s) publiée(s), verdict recalculé %s", len(publie.Errors), verdict)
}

func triee(l []string) []string {
	out := append([]string(nil), l...)
	sort.Strings(out)
	return out
}

func egalesTriees(a, b []string) bool {
	a, b = triee(a), triee(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// verifierCondenses : EX-A.6, SHA-256 des entrées de couverture.json.
func (d *Depot) verifierCondenses(rap *Rapport) error {
	comparer := func(nom string, publie []FichierCondense, attendus []string) error {
		if len(publie) != len(attendus) {
			rap.Discorde("EX-A.6", nom, "%d fichiers publiés, %d attendus", len(publie), len(attendus))
			return nil
		}
		for i, f := range attendus {
			h, err := sha256Fichier(filepath.Join(d.Racine, filepath.FromSlash(f)))
			if err != nil {
				return err
			}
			rap.Verdict(publie[i].File == f && publie[i].SHA256 == h, "EX-A.6", nom+" "+f, "SHA-256 %s", h[:16])
		}
		return nil
	}
	var specs []string
	for _, s := range d.Specs {
		specs = append(specs, s.Fichier)
	}
	if err := comparer("inputs.specs", d.Publie.Inputs.Specs, specs); err != nil {
		return err
	}
	if err := comparer("inputs.catalogue", []FichierCondense{d.Publie.Inputs.Catalogue}, []string{"spec/vecteurs/ct-9/catalogue.json"}); err != nil {
		return err
	}
	if err := comparer("inputs.threats", []FichierCondense{d.Publie.Inputs.Threats}, []string{"spec/vecteurs/ct-7/menaces.json"}); err != nil {
		return err
	}
	return comparer("inputs.tests", d.Publie.Inputs.Tests, d.Fichiers)
}
