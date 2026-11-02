package main

// Catalogue du plan de tests (CT-9 §4, schéma plan-de-tests-v0), modèle de
// menace de CT-7 (menaces.json), rapport de couverture (CT-9 §5.4), index
// TA- par menace (EX-A.13), rapports de mesure (11.3), consignations
// (12.1), grilles (A.9) et listes de cas (A.2, A.7, A.8). Les structures
// ne lisent que les membres recalculés ; un membre inconnu est ignoré.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

// Catalogue est la racine de catalogue.json.
type Catalogue struct {
	Version       int       `json:"version"`
	Kind          string    `json:"kind"`
	Spec          string    `json:"spec"`
	SpecVersion   string    `json:"spec_version"`
	Date          string    `json:"date"`
	Levels        []Niveau  `json:"levels"`
	Phase2Steps   []Etape   `json:"phase2_steps"`
	Tests         []Test    `json:"tests"`
	NonTests      []NonTest `json:"non_tests"`
	AcceptedRisks []Risque  `json:"accepted_risks"`
	Traceability  []LigneTC `json:"traceability"`
}

// Niveau est une ligne de la table des niveaux (3.1).
type Niveau struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Object  string `json:"object"`
	Oracle  string `json:"oracle"`
	Section string `json:"section"`
}

// Etape est une étape de la phase 2 (3.4).
type Etape struct {
	Step          int    `json:"step"`
	Component     string `json:"component"`
	DeliveredWhen string `json:"delivered_when"`
}

// Test est une entrée du catalogue (EX-4.1).
type Test struct {
	ID            string       `json:"id"`
	Level         string       `json:"level"`
	Title         string       `json:"title"`
	Specs         []string     `json:"specs"`
	Covers        []string     `json:"covers"`
	Preconditions []string     `json:"preconditions"`
	Steps         []string     `json:"steps"`
	Oracle        string       `json:"oracle"`
	Status        Etat         `json:"status"`
	Threats       []string     `json:"threats"`
	Adversarial   *Adversarial `json:"adversarial"`
	Measure       *Mesure      `json:"measure"`
	Replay        *Rejeu       `json:"replay"`
	Review        *Revue       `json:"review"`
}

// Etat est le membre status (EX-3.10).
type Etat struct {
	State      string         `json:"state"`
	Tests      []TestExistant `json:"tests"`
	Command    string         `json:"command"`
	Phase2Step *int           `json:"phase2_step"`
	Blocking   string         `json:"blocking"`
	CISteps    []string       `json:"ci_steps"`
	Complement *Complement    `json:"complement"`
}

// Complement est la partie de l'oracle due à une étape de la phase 2.
type Complement struct {
	Phase2Step int    `json:"phase2_step"`
	Blocking   string `json:"blocking"`
}

// TestExistant est un test du dépôt cité par son fichier et ses titres.
type TestExistant struct {
	File     string  `json:"file"`
	Describe string  `json:"describe"`
	It       *string `json:"it"`
}

// Adversarial est le bloc propre d'un TA- (10.2).
type Adversarial struct {
	Threat          *string        `json:"threat"`
	Component       *string        `json:"component"`
	ResponseRemoved ReponseRetiree `json:"response_removed"`
	Attack          string         `json:"attack"`
	Execution       string         `json:"execution"`
	AcceptedRisk    *string        `json:"accepted_risk"`
	ThreatTestText  *string        `json:"threat_test_text"`
	Composition     []string       `json:"composition"`
}

// ReponseRetiree : quoi, comment, où.
type ReponseRetiree struct {
	What  string `json:"what"`
	How   string `json:"how"`
	Where string `json:"where"`
}

// Mesure est le bloc propre d'un TM- (11.5).
type Mesure struct {
	Measured         json.RawMessage `json:"measured"`
	Quantity         string          `json:"quantity"`
	Unit             string          `json:"unit"`
	Target           json.RawMessage `json:"target"`
	Comparison       string          `json:"comparison"`
	Source           string          `json:"source"`
	FailureThreshold string          `json:"failure_threshold"`
	Method           string          `json:"method"`
	ResultName       string          `json:"result_name"`
}

// Rejeu est le bloc propre d'un TR- (12.2).
type Rejeu struct {
	Participant       string   `json:"participant"`
	Material          []string `json:"material"`
	ForbiddenSections []string `json:"forbidden_sections"`
	Grid              *string  `json:"grid"`
	Judge             string   `json:"judge"`
	VerdictRule       string   `json:"verdict_rule"`
}

// Revue est le bloc propre d'un TQ- (13).
type Revue struct {
	Components []string `json:"components"`
	Scope      []string `json:"scope"`
	Grid       []string `json:"grid"`
}

// NonTest est une justification NC- (5.3).
type NonTest struct {
	ID            string   `json:"id"`
	Category      string   `json:"category"`
	Covers        []string `json:"covers"`
	Justification string   `json:"justification"`
	DelegatedTo   string   `json:"delegated_to"`
}

// Risque est un risque accepté relié à son test (10.6).
type Risque struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Bound     string `json:"bound"`
	Owner     string `json:"owner"`
	Threat    string `json:"threat"`
	Test      string `json:"test"`
	TestState string `json:"test_state"`
	Tested    string `json:"tested"`
	NotTested string `json:"not_tested"`
}

// LigneTC est une ligne de traçabilité (0.2).
type LigneTC struct {
	ID        string `json:"id"`
	Key       string `json:"key"`
	Line      int    `json:"line"`
	Delegated string `json:"delegated"`
	Response  string `json:"response"`
}

// Menaces est spec/vecteurs/ct-7/menaces.json, réduit aux membres lus.
type Menaces struct {
	Threats []Menace `json:"threats"`
}

// Menace est une menace MN-n.
type Menace struct {
	ID        string `json:"id"`
	Component string `json:"component"`
	Test      string `json:"test"`
	Response  struct {
		Refs []string `json:"refs"`
	} `json:"response"`
	Residual *struct {
		AcceptedRisk *struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Bound string `json:"bound"`
			Owner string `json:"owner"`
		} `json:"accepted_risk"`
	} `json:"residual"`
}

// RapportCouverture est #/$defs/rapport_couverture (5.4, EX-5.9).
type RapportCouverture struct {
	Version int    `json:"version"`
	Kind    string `json:"kind"`
	Date    string `json:"date"`
	Tool    struct {
		Name    string `json:"name"`
		Command string `json:"command"`
	} `json:"tool"`
	Inputs struct {
		Specs     []FichierCondense `json:"specs"`
		Catalogue FichierCondense   `json:"catalogue"`
		Threats   FichierCondense   `json:"threats"`
		Tests     []FichierCondense `json:"tests"`
	} `json:"inputs"`
	Identifiers struct {
		Total          int       `json:"total"`
		CoveredByTests int       `json:"covered_by_tests"`
		CoveredByNC    int       `json:"covered_by_nc"`
		Uncovered      int       `json:"uncovered"`
		UnknownCited   []string  `json:"unknown_cited"`
		PerSpec        []ParSpec `json:"per_spec"`
	} `json:"identifiers"`
	Threats struct {
		Total     int      `json:"total"`
		WithTA    int      `json:"with_ta"`
		WithoutTA []string `json:"without_ta"`
	} `json:"threats"`
	Traceability struct {
		Occurrences int      `json:"occurrences"`
		Rows        int      `json:"rows"`
		Missing     []string `json:"missing"`
		Orphans     []string `json:"orphans"`
	} `json:"traceability"`
	Executable struct {
		Total         int           `json:"total"`
		TitlesChecked int           `json:"titles_checked"`
		TitlesMissing []TitreAbsent `json:"titles_missing"`
	} `json:"executable"`
	TextTables struct {
		Compared    int      `json:"compared"`
		Differences []string `json:"differences"`
	} `json:"text_tables"`
	Verdict string   `json:"verdict"`
	Errors  []string `json:"errors"`
}

// FichierCondense : fichier et SHA-256.
type FichierCondense struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

// ParSpec : comptes d'une spécification.
type ParSpec struct {
	Spec           string         `json:"spec"`
	Total          int            `json:"total"`
	CoveredByTests int            `json:"covered_by_tests"`
	CoveredByNC    int            `json:"covered_by_nc"`
	Uncovered      int            `json:"uncovered"`
	UncoveredIDs   []string       `json:"uncovered_ids"`
	Families       map[string]int `json:"families"`
}

// TitreAbsent : titre cité introuvable.
type TitreAbsent struct {
	TestID string `json:"test_id"`
	File   string `json:"file"`
	Title  string `json:"title"`
}

// IndexParMenace est index-ta-par-menace.json (EX-A.13).
type IndexParMenace struct {
	Version int                    `json:"version"`
	Date    string                 `json:"date"`
	Index   map[string]EntreeIndex `json:"index"`
}

// EntreeIndex : TA-, état et scénarios d'une menace.
type EntreeIndex struct {
	Test      string   `json:"test"`
	State     string   `json:"state"`
	Scenarios []string `json:"scenarios"`
}

// RapportMesure est #/$defs/rapport_mesure (11.3), membres recalculés.
type RapportMesure struct {
	Version int    `json:"version"`
	Kind    string `json:"kind"`
	Date    string `json:"date"`
	Commit  string `json:"commit"`
	System  struct {
		Reference bool `json:"reference"`
	} `json:"system"`
	CountsForTargets bool             `json:"counts_for_targets"`
	Results          []ResultatMesure `json:"results"`
}

// ResultatMesure est une ligne d'un rapport de mesure.
type ResultatMesure struct {
	Name           string          `json:"name"`
	TestID         string          `json:"test_id"`
	Unit           string          `json:"unit"`
	N              json.RawMessage `json:"n"`
	Connections    json.RawMessage `json:"connections"`
	Samples        json.RawMessage `json:"samples"`
	SamplesSHA256  json.RawMessage `json:"samples_sha256"`
	Value          json.RawMessage `json:"value"`
	P50            json.RawMessage `json:"p50"`
	P95            json.RawMessage `json:"p95"`
	P99            json.RawMessage `json:"p99"`
	Min            json.RawMessage `json:"min"`
	Max            json.RawMessage `json:"max"`
	Mean           json.RawMessage `json:"mean"`
	TextValue      json.RawMessage `json:"text_value"`
	Target         json.RawMessage `json:"target"`
	Met            json.RawMessage `json:"met"`
	Conditions     []string        `json:"conditions"`
	ExcludedReason json.RawMessage `json:"excluded_reason"`
}

// Consignation est #/$defs/consignation_rejeu (12.1), membres recalculés.
type Consignation struct {
	Version     int    `json:"version"`
	Kind        string `json:"kind"`
	TestID      string `json:"test_id"`
	Participant struct {
		Pseudonym string `json:"pseudonym"`
	} `json:"participant"`
	Judge struct {
		Pseudonym   string `json:"pseudonym"`
		Independent bool   `json:"independent"`
	} `json:"judge"`
	Material []struct {
		Item   string  `json:"item"`
		SHA256 *string `json:"sha256"`
	} `json:"material"`
	ForbiddenSections []string        `json:"forbidden_sections"`
	Grid              *string         `json:"grid"`
	DurationS         json.RawMessage `json:"duration_s"`
}

// Grille est #/$defs/grille_acceptation (A.9, EX-A.16).
type Grille struct {
	Version     int    `json:"version"`
	Kind        string `json:"kind"`
	TestID      string `json:"test_id"`
	Description string `json:"description"`
	Questions   []struct {
		ID       string `json:"id"`
		Question string `json:"question"`
		Elements []struct {
			Element string   `json:"element"`
			Rules   []string `json:"rules"`
		} `json:"elements"`
	} `json:"questions"`
	Disqualifying []string `json:"disqualifying"`
}

// ListeCas est attendu.json de cas/ ou cas.json de mesures/cas et
// consignations/cas : un fichier, une définition, un verdict attendu et,
// selon la famille, le mot-clé fautif (cas/) ou la raison.
type ListeCas struct {
	Family string `json:"family"`
	Cases  []struct {
		File     string  `json:"file"`
		Def      string  `json:"def"`
		Expected string  `json:"expected"`
		Keyword  *string `json:"keyword"`
		Reason   string  `json:"reason"`
	} `json:"cases"`
}

// LireJSON décode un fichier JSON dans une structure typée.
func LireJSON(chemin string, cible any) error {
	octets, err := os.ReadFile(chemin)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(octets))
	if err := dec.Decode(cible); err != nil {
		return fmt.Errorf("%s : %v", chemin, err)
	}
	return nil
}

// EstNull dit si un membre JSON brut est absent ou null.
func EstNull(r json.RawMessage) bool { return len(r) == 0 || string(r) == "null" }

// NombreJS imprime un nombre comme JavaScript le fait dans un gabarit
// (« 5 », « 0.2 », « 1588.11 »).
func NombreJS(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

// ClesOrdonnees rend les clés d'un objet JSON dans l'ordre du document et
// ses valeurs numériques imprimées comme JavaScript.
func ClesOrdonnees(objet json.RawMessage) ([][2]string, error) {
	dec := json.NewDecoder(bytes.NewReader(objet))
	t, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("objet attendu")
	}
	var out [][2]string
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return nil, err
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		f, err := strconv.ParseFloat(string(v), 64)
		val := string(v)
		if err == nil {
			val = NombreJS(f)
		}
		out = append(out, [2]string{k.(string), val})
	}
	return out, nil
}

// EgalBrut compare deux membres JSON bruts par valeur.
func EgalBrut(a, b json.RawMessage) bool {
	if EstNull(a) && EstNull(b) {
		return true
	}
	da, e1 := DecoderJSON(a)
	db, e2 := DecoderJSON(b)
	return e1 == nil && e2 == nil && EgalJSON(da, db)
}
