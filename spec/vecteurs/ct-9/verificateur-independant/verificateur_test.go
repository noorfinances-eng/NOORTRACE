package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestIdentifiantsDefinis(t *testing.T) {
	texte := "## 3. Modèle\n\n**EX-3.1** règle.\n**EX-3.2 (b)** règle.\n\n| Id | Objet |\n|---|---|\n| T-1 | jeton |\n| **AV-T-2** | avertissement |\n| CT-1 | relation |\n| EIP-191 | faux positif |\n\n```text\n**EX-9.9** dans un bloc\n| K-9 | dans un bloc |\n```\n### 3.2 Sous-section\n## Annexe A — Vecteurs\n### A.3 Outil\n"
	ids, sections := IdentifiantsDefinis("CT-6", texte)
	for _, id := range []string{"EX-3.1", "EX-3.2", "T-1", "AV-T-2"} {
		if !ids[id] {
			t.Errorf("%s attendu", id)
		}
	}
	for _, id := range []string{"CT-1", "EIP-191", "EX-9.9", "K-9"} {
		if ids[id] {
			t.Errorf("%s exclu attendu", id)
		}
	}
	for _, s := range []string{"3", "3.2", "A", "A.3"} {
		if !sections[s] {
			t.Errorf("section %s attendue : %v", s, sections)
		}
	}
	ids8, _ := IdentifiantsDefinis("CT-8", "DM-1 ligne\n```text\nDM-2 dans un bloc\n```\n**IR-3** gras\n### 10.12 RB-1 titre\n")
	for _, id := range []string{"DM-1", "DM-2", "IR-3", "RB-1"} {
		if !ids8[id] {
			t.Errorf("CT-8 : %s attendu", id)
		}
	}
	if Famille("EX-3.4") != "EX-3" || Famille("TR-101") != "TR" || Famille("AV-T-1") != "AV-T" {
		t.Errorf("famille")
	}
}

func TestAnalyserTitres(t *testing.T) {
	src := "// it(\"commentaire\")\nconst x = \"it(\\\"chaîne\\\")\";\nconst re = /it\\(\"regex\"\\)/;\ndescribe(\"A\", function () {\n  describe(`B ${n}`, () => {\n    it('c', () => { const s = \"x\".split(\"it(\"); });\n  });\n  it(\"d\", () => {});\n  obj.it(\"méthode\");\n});\nit(\"e\")\n"
	r := AnalyserTitres(src)
	if strings.Join(r.Describes, ",") != "A,B ${n}" {
		t.Errorf("describes : %v", r.Describes)
	}
	if len(r.Cas) != 3 {
		t.Fatalf("3 it attendus, %d lus : %+v", len(r.Cas), r.Cas)
	}
	if r.Cas[0].It != "c" || strings.Join(r.Cas[0].Describes, ",") != "A,B ${n}" {
		t.Errorf("c : %+v", r.Cas[0])
	}
	if r.Cas[1].It != "d" || strings.Join(r.Cas[1].Describes, ",") != "A" {
		t.Errorf("d : %+v", r.Cas[1])
	}
	if r.Cas[2].It != "e" || len(r.Cas[2].Describes) != 0 {
		t.Errorf("e : %+v", r.Cas[2])
	}
	index := map[string]TitresFichier{"test/x.test.js": r}
	it := "c"
	if !TitreExiste(index, TestExistant{"test/x.test.js", "A", &it}) || !TitreExiste(index, TestExistant{"test/x.test.js", "B ${n}", nil}) {
		t.Errorf("titre attendu")
	}
	if TitreExiste(index, TestExistant{"test/x.test.js", "Z", &it}) || TitreExiste(index, TestExistant{"test/y.test.js", "A", nil}) {
		t.Errorf("titre absent attendu")
	}
	if !EtapesCI("steps:\n      - name: régénérer les vecteurs\n        run: x\n")["régénérer les vecteurs"] {
		t.Errorf("étape de CI")
	}
}

func TestTitreTA(t *testing.T) {
	lu, ok := LireTitreTA("TA-37 et TA-42 (MN-37, MN-42) : un cas échoue ; mutant : passe (tués)")
	if !ok || strings.Join(lu.TAs, ",") != "TA-37,TA-42" || strings.Join(lu.Menaces, ",") != "MN-37,MN-42" || !lu.Pluriel || !lu.Tue {
		t.Errorf("titre à deux TA- : %+v %v", lu, ok)
	}
	lu, ok = LireTitreTA("TA-3 (MN-3) : cas fenetre-epuisee ; mutant : autorise (tué)")
	if !ok || len(lu.TAs) != 1 || lu.Pluriel {
		t.Errorf("titre à un TA- : %+v %v", lu, ok)
	}
	if _, ok := LireTitreTA("TA-3 : sans menace (tué)"); ok {
		t.Errorf("titre sans menace accepté")
	}
	lu, ok = LireTitreTA("TA-23 (MN-23, oracle sur le vecteur) : le vecteur régénéré diffère")
	if !ok || lu.Tue || lu.TAs[0] != "TA-23" || lu.Menaces[0] != "MN-23" {
		t.Errorf("titre à précision sans mutant : %+v %v", lu, ok)
	}
	if _, ok := LireTitreTA("TA-3 : sans menace (tué)"); ok {
		t.Errorf("titre sans menace accepté")
	}
}

func TestTables(t *testing.T) {
	if cellules("| a | b \\| c | d |")[1] != "b \\| c" {
		t.Errorf("cellules : %v", cellules("| a | b \\| c | d |"))
	}
	if ResumeCouverts([]string{"CT-6 T-1", "CT-6 T-2", "CT-6 §7", "CT-2 EX-10.3"}) != "CT-6 T- (2), CT-2 EX-10- (1)" {
		t.Errorf("résumé : %s", ResumeCouverts([]string{"CT-6 T-1", "CT-6 T-2", "CT-6 §7", "CT-2 EX-10.3"}))
	}
	m := &Mesure{Unit: "ms", Target: []byte(`{"p50":5,"p99":50}`)}
	if c, _ := CibleTM(m); c != "p50 ≤ 5, p99 ≤ 50 ms" {
		t.Errorf("cible : %s", c)
	}
	m = &Mesure{Unit: "min", Target: []byte(`450`)}
	if c, _ := CibleTM(m); c != "450 min" {
		t.Errorf("cible : %s", c)
	}
	lu := TablesDuTexte("x\n<!-- table TU -->\n| a |\n|---|\n| b |\n\ntexte\n")
	if len(lu["TU"]) != 3 {
		t.Errorf("table lue : %v", lu)
	}
	n, diff := ComparerTables(map[string][]string{"TU": {"| a |", "|---|", "| c |"}}, "<!-- table TU -->\n| a |\n|---|\n| b |\n")
	cellule := false
	for _, x := range diff {
		if strings.Contains(x, "table TU, ligne 3, cellule 1") {
			cellule = true
		}
	}
	if n != 1 || !cellule || len(diff) != len(Tables) {
		t.Errorf("une différence de cellule et %d marqueurs absents attendus : %d %v", len(Tables)-1, n, diff)
	}
}

func TestSchema(t *testing.T) {
	src := `{"$defs":{"id":{"type":"string","pattern":"^T-[0-9]+$"},"e":{"type":"object","additionalProperties":false,"required":["id","n"],"properties":{"id":{"$ref":"#/$defs/id"},"n":{"type":"integer","minimum":1},"t":{"anyOf":[{"type":"string","minLength":1,"maxLength":3},{"type":"null"}]},"l":{"type":"array","uniqueItems":true,"minItems":1,"items":{"enum":["a","b"]}},"k":{"const":"x"}},"allOf":[{"if":{"properties":{"k":{"const":"x"}},"required":["k"]},"then":{"required":["t"],"properties":{"l":false}}}]}},"type":"object","properties":{"e":{"$ref":"#/$defs/e"}}}`
	doc, err := DecoderJSON([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	s := &Schema{Racine: doc, Defs: doc.(map[string]any)["$defs"].(map[string]any), motifs: map[string]*regexp.Regexp{}}
	valider := func(j string) []string {
		d, err := DecoderJSON([]byte(j))
		if err != nil {
			t.Fatal(err)
		}
		v, err := s.Valider("e", d)
		if err != nil {
			t.Fatal(err)
		}
		return MotsCles(v)
	}
	cas := map[string]string{
		`{"id":"T-1","n":2,"t":"éà","l":["a"]}`:        "",
		`{"id":"T-1","n":2.0,"t":null}`:                "",
		`{"id":"X-1","n":2,"t":"a"}`:                   "pattern",
		`{"id":"T-1","n":0,"t":"a"}`:                   "minimum",
		`{"id":"T-1","n":1.5,"t":"a"}`:                 "type",
		`{"id":"T-1","t":"a"}`:                         "required",
		`{"id":"T-1","n":1,"t":"a","z":1}`:             "additionalProperties",
		`{"id":"T-1","n":1,"t":""}`:                    "anyOf,minLength,type",
		`{"id":"T-1","n":1,"t":"abcd"}`:                "anyOf,maxLength,type",
		`{"id":"T-1","n":1,"t":"a","l":["a","a"]}`:     "uniqueItems",
		`{"id":"T-1","n":1,"t":"a","l":[]}`:            "minItems",
		`{"id":"T-1","n":1,"t":"a","l":["c"]}`:         "enum",
		`{"id":"T-1","n":1,"k":"x"}`:                   "required",
		`{"id":"T-1","n":1,"k":"x","t":"a","l":["a"]}`: "false schema",
		`{"id":"T-1","n":1,"k":"y","t":"a"}`:           "const",
	}
	for j, attendu := range cas {
		if got := strings.Join(valider(j), ","); got != attendu {
			t.Errorf("%s : mots-clés %q, attendu %q", j, got, attendu)
		}
	}
	if !EgalJSON(json.Number("5"), json.Number("5.0")) || EgalJSON(json.Number("5"), "5") {
		t.Errorf("EgalJSON nombres")
	}
	if !EgalJSON(map[string]any{"a": []any{json.Number("1"), nil}}, map[string]any{"a": []any{json.Number("1.0"), nil}}) {
		t.Errorf("EgalJSON objets")
	}
}

func TestTexte(t *testing.T) {
	src := "# Titre\n\nen-tête\n\n## 1. Un\n\na\n\n### 1.1 Sous\n\nb\n\n```text\n## 2. faux titre\n```\n\n## 2. Deux\n\nc\n\n## Annexe A — Trucs\n\n### A.1 Premier\n\nd\n\n### A.2 Second\n\ne\n"
	if got := Couper(src, []string{"2"}, nil, nil); strings.Contains(got, "\nc\n") || !strings.Contains(got, "## 2. faux titre") || !strings.Contains(got, "\ne\n") {
		t.Errorf("retirer 2 : %q", got)
	}
	if got := Couper(src, []string{"Annexe A"}, nil, nil); strings.Contains(got, "A.1") || !strings.Contains(got, "\nc\n") {
		t.Errorf("retirer annexe : %q", got)
	}
	if got := Couper(src, nil, []string{"A.2"}, nil); strings.Contains(got, "\ne\n") || !strings.Contains(got, "\nd\n") {
		t.Errorf("retirer A.2 : %q", got)
	}
	if got := Couper(src, nil, nil, []string{"2"}); got != "## 2. Deux\n\nc\n" {
		t.Errorf("garder 2 : %q", got)
	}
	if got := SectionTexte(src, "1.1"); Normaliser(got) != "b ## 2. faux titre" && !strings.Contains(got, "\nb\n") {
		t.Errorf("section 1.1 : %q", got)
	}
	if got := SectionTexte(src, "1"); !strings.Contains(got, "### 1.1 Sous") || strings.Contains(got, "## 2. Deux") {
		t.Errorf("section 1 : %q", got)
	}
	if got := SectionTexte(src, "Annexe A"); !strings.Contains(got, "\ne\n") || strings.Contains(got, "\nc\n") {
		t.Errorf("annexe : %q", got)
	}
	for s, v := range map[string]float64{"14 293": 14293, "1 588,11": 1588.11, "dix": 10, "soixante-seize": 76, "trente-huit": 38, "cent": 100, "sept": 7} {
		if f, ok := EntierFrancais(s); !ok || f != v {
			t.Errorf("%q : %v %v", s, f, ok)
		}
	}
	if _, ok := EntierFrancais("mille"); ok {
		t.Errorf("« mille » n'est pas lu")
	}
	tailles, h := TaillesLignes([]byte("ab\ncdé\n"))
	if len(tailles) != 2 || tailles[0] != 3 || tailles[1] != 5 || len(h) != 64 {
		t.Errorf("tailles : %v %s", tailles, h)
	}
}

func TestGrillePorte2(t *testing.T) {
	section := "\n**EX-14.1** règle.\n\n| Critère « continuer si » | Entrées | Verdict calculable |\n|---|---|---|\n| C1 | TE-1, TM-3 | V1 |\n| C2 | TU-39 ; TR-10 | V2 |\n\n| Critère « arrêter ou reprendre si » | Entrées | Verdict calculable | Suite |\n|---|---|---|---|\n| S1 | TA-1 à TA-103 ; TQ-1 à TQ-8 | W1 | Arrêter |\n\n**EX-14.2** Ce que la porte 2 ne mesure pas, et le dit : les critères\nSU- (x) ; la conformité ; la revue (y).\n\n"
	niveaux := []Niveau{{ID: "TU", Name: "Unitaires"}, {ID: "TA", Name: "Adversariaux"}, {ID: "TM", Name: "Mesures"}, {ID: "TV", Name: "Vecteurs"}}
	g := GrillePorte2(section, niveaux)
	if len(g) != 3 || len(g[0]) != 2 || len(g[1]) != 3 || len(g[2]) != 4 {
		t.Fatalf("forme : %d %d %d", len(g[0]), len(g[1]), len(g[2]))
	}
	if g[0][0].Element != "C1 : V1" || g[0][0].Rules != "CT-9 §14 (entrées : TE-1, TM-3)\x00CT-9 EX-14.1" {
		t.Errorf("q1 : %+v", g[0][0])
	}
	if g[1][0].Element != "les critères SU- (x)" || g[1][2].Element != "la revue (y)" || g[1][0].Rules != "CT-9 EX-14.2" {
		t.Errorf("q2 : %+v", g[1])
	}
	if g[2][0].Element != "TU- (Unitaires) : continuer si : C2" || g[2][1].Element != "TA- (Adversariaux) : arrêter ou reprendre si : S1" || g[2][2].Element != "TM- (Mesures) : continuer si : C1" || g[2][3].Element != "TV- (Vecteurs) : " {
		t.Errorf("q3 : %+v", g[2])
	}
}

func TestEtatIndex(t *testing.T) {
	huit := 8
	if EtatIndex(&Test{Status: Etat{State: "a_ecrire", Phase2Step: &huit}}) != "à écrire (étape 8)" {
		t.Errorf("à écrire")
	}
	if EtatIndex(&Test{Status: Etat{State: "executable", Complement: &Complement{Phase2Step: 4}}}) != "exécutable, complément à écrire" {
		t.Errorf("complément")
	}
	if EtatIndex(&Test{Status: Etat{State: "executable"}}) != "exécutable" {
		t.Errorf("exécutable")
	}
}

// TestDepot rejoue le vérificateur sur le dépôt qui contient ce module et
// exige zéro discordance (EX-A.10).
func TestDepot(t *testing.T) {
	racine, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	rap, err := Verifier(racine)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range rap.Discordances() {
		t.Errorf("discordance : %s | %s : %s", d.Regle, d.Objet, d.Detail)
	}
	c := rap.Comptes
	if c.Menaces != c.MenacesAvecTA || c.NonCouverts != 0 || c.TablesComparees != len(Tables) || rap.Resume.Total != len(rap.Controles) {
		t.Errorf("comptes : %+v %+v", c, rap.Resume)
	}
}

// Révision 0.10 de CT-9 : nombres en lettres séparés par des espaces
// (« trente et une », EX-11.16).
func TestEntierFrancaisEspaces(t *testing.T) {
	for s, n := range map[string]float64{"trente et une": 31, "vingt-et-un": 21, "douze": 12, "trente et un": 31} {
		if v, ok := EntierFrancais(s); !ok || v != n {
			t.Errorf("%q : %v %v, %v attendu", s, v, ok, n)
		}
	}
}

// EX-11.16 : identifiants énumérés par la prose, plages « TM-a à TM-b »
// développées, dans l'ordre du texte, sans doublon.
func TestIdentifiantsPlages(t *testing.T) {
	got := IdentifiantsPlages("TM-6 et TM-10 ont leur résultat, TM-11 à TM-14, TM-17 à TM-19, TM-30 ; TM-6 encore, TM-1 à TM-3 (CT-2 EX-16.2)", "TM")
	if strings.Join(got, ",") != "TM-6,TM-10,TM-11,TM-12,TM-13,TM-14,TM-17,TM-18,TM-19,TM-30,TM-1,TM-2,TM-3" {
		t.Errorf("plages : %v", got)
	}
}

// EX-5.4 (d), révision 0.10 : un it cité a un corps, n'est ni skip ni only,
// et n'est pas sous un describe.skip.
func TestTitresModificateurs(t *testing.T) {
	src := "describe(\"A\", () => {\n  it(\"corps\", () => {});\n  it(\"sans corps\");\n  it(\"virgule seule\",\n  );\n  it.skip(\"sauté\", () => {});\n  it.only(\"seul\", () => {});\n  describe.skip(\"B\", () => {\n    it(\"sous skip\", async function () {});\n  });\n});\ndescribe(\"C\", () => { it(\"x\", f); });\n"
	r := AnalyserTitres(src)
	if strings.Join(r.Describes, ",") != "A,B,C" || len(r.Profondeurs) != 3 || r.Profondeurs[0] != 0 || r.Profondeurs[1] != 1 || r.Profondeurs[2] != 0 {
		t.Fatalf("describes %v, profondeurs %v", r.Describes, r.Profondeurs)
	}
	attendu := map[string]CasTest{
		"corps":         {Corps: true},
		"sans corps":    {},
		"virgule seule": {},
		"sauté":         {Corps: true, Modificateur: "skip"},
		"seul":          {Corps: true, Modificateur: "only"},
		"sous skip":     {Corps: true, SousSkip: true},
		"x":             {Corps: true},
	}
	if len(r.Cas) != len(attendu) {
		t.Fatalf("%d it lus : %+v", len(r.Cas), r.Cas)
	}
	for _, c := range r.Cas {
		a := attendu[c.It]
		if c.Corps != a.Corps || c.Modificateur != a.Modificateur || c.SousSkip != a.SousSkip {
			t.Errorf("%s : %+v", c.It, c)
		}
	}
	index := map[string]TitresFichier{"test/x.test.js": r}
	for it, pb := range map[string]string{"corps": "", "sans corps": "sans corps", "sauté": "skip", "seul": "only", "absent": "absent"} {
		x := it
		if got := EtatCite(index, TestExistant{"test/x.test.js", "A", &x}); got != pb {
			t.Errorf("%s : %q, %q attendu", it, got, pb)
		}
	}
	x := "sous skip"
	if got := EtatCite(index, TestExistant{"test/x.test.js", "B", &x}); got != "sous describe.skip" {
		t.Errorf("sous skip : %q", got)
	}
	if got := EtatCite(index, TestExistant{"test/x.test.js", "C", nil}); got != "" {
		t.Errorf("describe seul : %q", got)
	}
}

// EX-A.11 : describe de premier niveau, it par describe de premier niveau,
// describe qui contiennent directement des it (de composant ou de scénario).
func TestStructureDescribes(t *testing.T) {
	src := "describe(\"L\", () => {\n describe(\"c1\", () => { it(\"a\", f); it(\"b\", f); });\n describe(\"c2\", () => { it(\"c\", f); });\n});\ndescribe(\"D\", () => { it(\"d\", f); });\ndescribe(\"S\", () => {\n describe(\"s1\", () => { it(\"e\", f); it(\"g\", f); });\n});\n"
	s := StructureDescribes(AnalyserTitres(src))
	if strings.Join(s.Premiers, ",") != "L,D,S" || fmt.Sprint(s.ItsParPremier) != "[3 1 2]" || fmt.Sprint(s.FeuillesParPremier) != "[2 1 1]" || s.Feuilles != 4 {
		t.Errorf("structure : %+v", s)
	}
}

// EX-10.7 forme (4) : « réponse retirée », menaces du scénario.
func TestTitreTARetiree(t *testing.T) {
	lu, ok := LireTitreTA("TA-105 (MN-21, réponse retirée) : un mutant du démon (image) ; un événement est scellé (tué)")
	if !ok || !lu.Retiree || !lu.Tue || strings.Join(lu.Menaces, ",") != "MN-21" {
		t.Errorf("réponse retirée : %+v %v", lu, ok)
	}
	lu, ok = LireTitreTA("TA-105 (MN-21) : horloge pilotée ; les dates restent non décroissantes (borne RA-18, RA-54)")
	if !ok || lu.Retiree || lu.Tue {
		t.Errorf("bout en bout : %+v %v", lu, ok)
	}
	lu, ok = LireTitreTA("TA-104 (MN-18, MN-23, MN-96 et composés) : réponse retirée — un mutant (tué)")
	if !ok || !lu.Retiree || strings.Join(lu.Menaces, ",") != "MN-18,MN-23" {
		t.Errorf("qualificatif : %+v %v", lu, ok)
	}
	scen := []string{"MN-21", "MN-60"}
	if pb := ProblemesItScenario(TitreTA{TAs: []string{"TA-105"}, Menaces: []string{"MN-21"}, Retiree: true, Tue: true}, scen); len(pb) != 0 {
		t.Errorf("retrait valide : %v", pb)
	}
	if pb := ProblemesItScenario(TitreTA{TAs: []string{"TA-105"}, Menaces: []string{"MN-21"}}, scen); len(pb) != 0 {
		t.Errorf("bout en bout valide : %v", pb)
	}
	if pb := ProblemesItScenario(TitreTA{TAs: []string{"TA-105"}, Menaces: []string{"MN-21"}, Retiree: true}, scen); len(pb) == 0 {
		t.Errorf("retrait sans (tué) accepté")
	}
	if pb := ProblemesItScenario(TitreTA{TAs: []string{"TA-105"}, Menaces: []string{"MN-21"}, Tue: true}, scen); len(pb) == 0 {
		t.Errorf("bout en bout terminé par (tué) accepté")
	}
	if pb := ProblemesItScenario(TitreTA{TAs: []string{"TA-105"}, Menaces: []string{"MN-99"}}, scen); len(pb) == 0 {
		t.Errorf("menace hors du scénario acceptée")
	}
}

// 10.5, révision 0.10 : chaque scénario cite son it de bout en bout et,
// sauf l'exception nommée, l'it qui retire une réponse ; l'exception cite
// en plus les mutants tués de deux TA- composés.
func TestProblemesScenario(t *testing.T) {
	bout := "TA-105 (MN-21) : horloge pilotée (borne RA-18)"
	retrait := "TA-105 (MN-21, réponse retirée) : mutant (tué)"
	if pb := ProblemesScenario("TA-105", []string{bout, retrait}, false, nil); len(pb) != 0 {
		t.Errorf("TA-105 : %v", pb)
	}
	if pb := ProblemesScenario("TA-104", []string{"TA-104 (MN-18, réponse retirée) : mutant (tué)"}, false, nil); len(pb) == 0 {
		t.Errorf("scénario sans it de bout en bout accepté")
	}
	if pb := ProblemesScenario("TA-105", []string{bout}, false, nil); len(pb) == 0 {
		t.Errorf("scénario sans it de retrait accepté")
	}
	b103 := "TA-103 (MN-1, MN-22) : bout en bout (borne RA-1)"
	t1 := "TA-1 (MN-1) : connexion directe (tué)"
	t22 := "TA-22 (MN-22) : storage.root (tué)"
	if pb := ProblemesScenario("TA-103", []string{b103, t1, t22}, true, []string{"TA-1", "TA-22"}); len(pb) != 0 {
		t.Errorf("TA-103 : %v", pb)
	}
	if pb := ProblemesScenario("TA-103", []string{b103, t1}, true, []string{"TA-1", "TA-22"}); len(pb) == 0 {
		t.Errorf("TA-103 sans le mutant de TA-22 accepté")
	}
	if pb := ProblemesScenario("TA-105", []string{bout, retrait, t1}, false, nil); len(pb) == 0 {
		t.Errorf("it qui ne nomme pas le scénario accepté")
	}
}

// Lectures de la prose révisée en 0.10 (EX-11.16, 10.5, 10.8, EX-A.11,
// EX-A.15, section 16), sur des phrases de la forme du texte.
func TestLecturesProse(t *testing.T) {
	n, ids, ok := LireEX1116("**EX-11.15** TM-99. **EX-11.16** En versions 0.1 à 0.4, rien ; parmi les sept entrées exécutables, TM-6 et TM-10 ont leur résultat, TM-11 à TM-13 dans le rapport, et TM-1 dans les essais (CT-2 EX-16.2), jamais dans le catalogue.")
	if !ok || n != 7 || strings.Join(ids, ",") != "TM-6,TM-10,TM-11,TM-12,TM-13,TM-1" {
		t.Errorf("EX-11.16 : %d %v %v", n, ids, ok)
	}
	if _, _, ok := LireEX1116("parmi les sept entrées exécutables, TM-6"); ok {
		t.Errorf("EX-11.16 lu hors de son paragraphe")
	}
	sauf, plus, ok := LireException105("chacune cite son `it` de bout en bout et, sauf TA-103, l'`it` qui retire une réponse d'un test composé ; TA-103 cite en plus les mutants tués de TA-1 et de TA-22 joués")
	if !ok || sauf != "TA-103" || strings.Join(plus, ",") != "TA-1,TA-22" {
		t.Errorf("10.5 : %s %v %v", sauf, plus, ok)
	}
	if _, _, ok := LireException105("sauf TA-103, l'`it` qui retire une réponse ; TA-104 cite en plus les mutants tués de TA-1 et de TA-22"); ok {
		t.Errorf("10.5 : exceptions différentes acceptées")
	}
	a, b, c, ok := LireComptes108("Résultat : « 95 passing (4m) », 17 en attente, tous pour le démon Docker absent (démon, scénarios de 10.5, TA-96), 0 en échec. À la révision 0.9 : « 71 passing (3m) », 0 en échec, 0 en attente")
	if !ok || a != 95 || b != 17 || c != 0 {
		t.Errorf("10.8 : %d %d %d %v", a, b, c, ok)
	}
	a11, ok := LireA11("Il contient 12 `it` répartis en quatre `describe` de composant ou de scénario, sous trois `describe` de premier niveau (révision 0.10) : les bibliothèques (7 `it`, en deux `describe` par composant : clés ; registre) ; le démon (3 `it` qui lancent le démon) ; les scénarios de 10.5 (2, en un `describe` par scénario). Les `it` qui demandent Docker (9) sont en attente.")
	if !ok || a11.Its != "12" || a11.Feuilles != "quatre" || a11.Premiers != "trois" || fmt.Sprint(a11.Nombres) != "[7 3 2]" || a11.Decoupes[0] != [2]string{"deux", "composant"} || a11.Decoupes[2] != [2]string{"un", "scénario"} || len(a11.Decoupes) != 2 {
		t.Errorf("EX-A.11 : %+v %v", a11, ok)
	}
	n, fichiers, ok := LireCasA8("et `cas/cas.json` avec trois cas (`valide-gabarit`, `invalide-sans-materiel` et, depuis la révision 0.10, `invalide-externe-sans-condition` : `external` vrai) ; le gabarit porte `condition`")
	if !ok || n != 3 || strings.Join(fichiers, ",") != "valide-gabarit.json,invalide-sans-materiel.json,invalide-externe-sans-condition.json" {
		t.Errorf("A.8 : %d %v %v", n, fichiers, ok)
	}
	s16 := "les compléments des deux TA- exécutables qui en portent un (TA-25, TA-41) et ceux de TV-55, de TE-6, de TM-1 à TM-3 et TM-41 n'ont aucun résultat ; 12 entrées TA- à menace d'exécution `phase_2` à écrire (dont TA-95 et TA-97, épreuves), les compléments des trois entrées de l'étape 8 (TA-5, TA-14, TA-40) ;"
	ta, autres, ok := LireComplements16(s16)
	if !ok || strings.Join(ta, ",") != "TA-25,TA-41" || strings.Join(autres, ",") != "TV-55,TE-6,TM-1,TM-2,TM-3,TM-41" {
		t.Errorf("16 compléments : %v %v %v", ta, autres, ok)
	}
	n, dont, ok := LirePhase2_16(s16)
	if !ok || n != 12 || strings.Join(dont, ",") != "TA-95,TA-97" {
		t.Errorf("16 phase 2 : %d %v %v", n, dont, ok)
	}
	n, ids, ok = LireEtape16(s16, 8)
	if !ok || n != 3 || strings.Join(ids, ",") != "TA-5,TA-14,TA-40" {
		t.Errorf("16 étape 8 : %d %v %v", n, ids, ok)
	}
}

// Section 16, complément du 2026-11-16 : une seule entrée TA- garde un
// complément ; la phrase qui en donne le nombre se lit au pluriel avec un
// nombre écrit, au pluriel sans nombre (nombre des TA- nommés) et au
// singulier (1), sans jamais déduire le nombre du catalogue.
func TestLectures16Nombre(t *testing.T) {
	cas := []struct {
		s      string
		n      int
		nommes string
	}{
		{"les compléments des deux TA- exécutables qui en portent un (TA-25, TA-41) et ceux de TV-55 n'ont aucun résultat", 2, "TA-25,TA-41"},
		{"les compléments des TA- exécutables qui en portent un (TA-25) et ceux de TV-55 n'ont aucun résultat", 1, "TA-25"},
		{"les compléments des TA- exécutables qui en portent un (TA-25, TA-41) et ceux de TV-55 n'ont aucun résultat", 2, "TA-25,TA-41"},
		{"le complément du TA- exécutable qui en porte un (TA-25) et ceux de TV-55 n'ont aucun résultat", 1, "TA-25"},
		{"le complément du seul TA- exécutable qui en porte un (TA-25) et ceux de TV-55 n'ont aucun résultat", 1, "TA-25"},
		// Nombre écrit et liste en désaccord : le nombre écrit est rendu, la
		// vérification compare les deux.
		{"les compléments des trois TA- exécutables qui en portent un (TA-25) et ceux de TV-55 n'ont aucun résultat", 3, "TA-25"},
	}
	for _, c := range cas {
		n, nommes, ok := LireNombreTA16(c.s)
		if !ok || n != c.n || strings.Join(nommes, ",") != c.nommes {
			t.Errorf("TA- avec complément « %s » : %d %v %v", c.s, n, nommes, ok)
		}
		ta, autres, ok := LireComplements16(c.s)
		if !ok || strings.Join(ta, ",") != c.nommes || strings.Join(autres, ",") != "TV-55" {
			t.Errorf("liste « %s » : %v %v %v", c.s, ta, autres, ok)
		}
	}
	for _, s := range []string{
		"les compléments des TA- exécutables qui en portent un () et ceux de TV-55",
		"les compléments des quelques TA- exécutables qui en portent un (TA-25)",
		"les compléments des TA- exécutables",
	} {
		if n, nommes, ok := LireNombreTA16(s); ok {
			t.Errorf("lu à tort « %s » : %d %v", s, n, nommes)
		}
	}
	etapes := []struct {
		s      string
		etape  int
		n      int
		nommes string
		ok     bool
	}{
		{"les compléments des deux entrées de l'étape 8 (TA-25, TA-41) ;", 8, 2, "TA-25,TA-41", true},
		{"les compléments des entrées de l'étape 8 (TA-25), celui de TA-41 étant levé", 8, 1, "TA-25", true},
		{"le complément de l'entrée de l'étape 8 (TA-25) ;", 8, 1, "TA-25", true},
		{"le complément de la seule entrée de l'étape 4 (TE-3) ;", 4, 1, "TE-3", true},
		{"les compléments des deux entrées de l'étape 4 ;", 4, 2, "", true},
		{"les compléments des entrées de l'étape 8 ;", 8, 0, "", false},
		{"les compléments des entrées de l'étape 80 (TA-25)", 8, 0, "", false},
	}
	for _, c := range etapes {
		n, nommes, ok := LireEtape16(c.s, c.etape)
		if ok != c.ok || (ok && (n != c.n || strings.Join(nommes, ",") != c.nommes)) {
			t.Errorf("étape %d « %s » : %d %v %v", c.etape, c.s, n, nommes, ok)
		}
	}
	if l := LireLeves16("compléments des entrées de l'étape 8 (TA-25), celui de TA-41 étant levé (complément du 2026-11-16) ;"); strings.Join(l, ",") != "TA-41" {
		t.Errorf("levé : %v", l)
	}
	if l := LireLeves16("ceux de TA-25 et TA-41 étant levés"); strings.Join(l, ",") != "TA-25,TA-41" {
		t.Errorf("levés : %v", l)
	}
	if n, _, ok := LirePhase2_16("1 entrée TA- à menace d'exécution `phase_2` à écrire (dont TA-95 et TA-97"); !ok || n != 1 {
		t.Errorf("phase 2 au singulier : %d %v", n, ok)
	}
}

// Sur le dépôt, chaque phrase de la section 16 que le vérificateur lit
// donne un contrôle concordant : aucune n'est sautée en silence.
func TestDepot16(t *testing.T) {
	racine, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	rap, err := Verifier(racine)
	if err != nil {
		t.Fatal(err)
	}
	vus := map[string]string{}
	for _, c := range rap.Controles {
		if c.Regle == "16" {
			vus[c.Objet] = c.Statut
		}
	}
	for _, o := range []string{"entrées à écrire", "TA- avec complément", "compléments de l'étape 4", "TM- à écrire", "TA- avec complément (liste)", "autres entrées avec complément", "TA- à menace de phase 2 à écrire", "compléments de l'étape 8 nommés", "complément levé : TA-41"} {
		if vus[o] != Concordant {
			t.Errorf("16 | %s : %q", o, vus[o])
		}
	}
}
