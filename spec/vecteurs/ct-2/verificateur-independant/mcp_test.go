package main

// Agrégation de tools/list (CT-2 §4.3) et lecture des transcriptions.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgregation(t *testing.T) {
	long := strings.Repeat("x", 129)
	serveurs, err := ParseJSON([]byte(`[
	  {"alias":"sap","tools":[{"name":"payments.create","annotations":{"readOnlyHint":false}},{"name":"claims.get","annotations":{"readOnlyHint":true}},{"name":"noortrace.x"}]},
	  {"alias":"crm","tools":[{"name":"` + long + `"},{"name":"b"},{"name":"a","annotations":{"readOnlyHint":true}}]}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	ag := Agreger(serveurs, true, 2)
	var noms []string
	for _, a := range ag.Annonces {
		noms = append(noms, a.Annonce+":"+a.Classe)
	}
	if strings.Join(noms, " ") != "crm__a:lecture crm__b:ecriture sap__claims.get:lecture sap__payments.create:ecriture" {
		t.Errorf("annonces : %v", noms)
	}
	var rejets []string
	for _, r := range ag.Rejets {
		rejets = append(rejets, r.Alias+"|"+r.Origine[:min(len(r.Origine), 12)])
	}
	if strings.Join(rejets, " ") != "crm|xxxxxxxxxxxx sap|noortrace.x" {
		t.Errorf("rejets : %v", rejets)
	}
	if len(ag.Pages) != 2 || len(ag.Pages[0]) != 2 || ag.Pages[1][1] != "sap__payments.create" {
		t.Errorf("pages : %v", ag.Pages)
	}
	if ag.RefusConfig {
		t.Error("refus inattendu")
	}
	// sans préfixe, deux serveurs : refus de configuration ; les deux outils
	// en collision sont rejetés (EX-4.11, lecture littérale)
	s2, _ := ParseJSON([]byte(`[{"alias":"a","tools":[{"name":"t"}]},{"alias":"b","tools":[{"name":"t"}]}]`))
	ag = Agreger(s2, false, 100)
	if !ag.RefusConfig || len(ag.Annonces) != 0 || len(ag.Rejets) != 2 {
		t.Errorf("collision sans préfixe : %+v", ag)
	}
	// un serveur, deux outils de même nom : tous deux rejetés ; définition annoncée = outil renommé
	s5, _ := ParseJSON([]byte(`[{"alias":"demo","tools":[{"name":"t","annotations":{"readOnlyHint":true}},{"name":"t"},{"name":"u","title":"U"}]}]`))
	ag = Agreger(s5, true, 100)
	if len(ag.Annonces) != 1 || len(ag.Rejets) != 2 || doitIntegral(ag.Annonces[0].Definition) != `{"name":"demo__u","title":"U"}` {
		t.Errorf("doublon dans un serveur : %+v", ag)
	}
	// nom d'origine de 126 caractères : annoncé sap__… = 131 > 128, rejeté
	s3, _ := ParseJSON([]byte(`[{"alias":"sap","tools":[{"name":"` + strings.Repeat("y", 123) + `"},{"name":"` + strings.Repeat("y", 124) + `"}]}]`))
	ag = Agreger(s3, true, 100)
	if len(ag.Annonces) != 1 || len(ag.Annonces[0].Annonce) != 128 || len(ag.Rejets) != 1 {
		t.Errorf("borne de 128 caractères : %+v", ag)
	}
	// pagination par 100
	var b strings.Builder
	b.WriteString(`[{"alias":"s","tools":[`)
	for i := 0; i < 150; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"name":"t%03d"}`, i)
	}
	b.WriteString(`]}]`)
	s4, _ := ParseJSON([]byte(b.String()))
	ag = Agreger(s4, true, 100)
	if len(ag.Pages) != 2 || len(ag.Pages[0]) != 100 || len(ag.Pages[1]) != 50 {
		t.Errorf("pagination : %d pages", len(ag.Pages))
	}
}

func TestTranscription(t *testing.T) {
	dir := t.TempDir()
	ligne := string(lireSpec(t, "annexe-a-hote-requete.jsonl"))
	env := Objet("dir", Chaine("in"), "t", Chaine("2026-11-03T13:52:40.000Z"), "line", Chaine(strings.TrimSuffix(ligne, "\n")))
	c, _ := CanoniqueIntegral(env)
	if err := os.WriteFile(filepath.Join(dir, "hote.jsonl"), append(c, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	ls, err := LireTranscription(filepath.Join(dir, "hote.jsonl"))
	if err != nil || len(ls) != 1 || ls[0].methode() != "tools/call" || ls[0].id() != `"h-77812-4"` {
		t.Fatalf("%v %+v", err, ls)
	}
	a := ls[0].Val.Get("params").Get("arguments")
	if octetsDe(ls[0], a) != `{"claim_id":"2026-77812","amount":"7400.00","currency":"CHF","beneficiary_iban":"CH9300762011623852957"}` {
		t.Errorf("octets des arguments : %s", octetsDe(ls[0], a))
	}
}
