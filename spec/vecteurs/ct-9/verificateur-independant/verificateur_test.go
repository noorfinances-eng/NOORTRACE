package main

import (
	"encoding/json"
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
