package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func schemasTest(t *testing.T) *Schemas {
	t.Helper()
	d := filepath.Join("..", "..", "..", "schemas")
	sch, err := ChargerSchemas(filepath.Join(d, "politique-approbation-v0.schema.json"),
		filepath.Join(d, "ticket-v0.schema.json"), filepath.Join(d, "evenement-v0.schema.json"))
	if err != nil {
		t.Skipf("schémas introuvables : %v", err)
	}
	return sch
}

// politiqueTest construit un document à partir de règles écrites en JSON.
func politiqueTest(regles ...string) string {
	return `{"version":0,"default":{"name":"defaut","description":null,"level":"revue","decision":null,"contest_ms":0},` +
		`"rules":[` + strings.Join(regles, ",") + `],` +
		`"approver_set":{"source":"registre","chain_id":2124,"registry":"0xff7a89fa58a8ffa1173eb70799d7c184bf4d7fe1","set":"0x35312352c0065a3fc46ce14dba05df3fcee9fbc2","members":null,"threshold":null},` +
		`"separation":{"self_approval":"interdite","identities":[]}}`
}

func regleTest(nom, when string) string {
	return fmt.Sprintf(`{"name":%q,"description":null,"tools":["x"],"when":%s,"level":"revue","decision":null,"window":null,"contest_ms":0}`, nom, when)
}

func predicatTest(path string) string {
	return fmt.Sprintf(`{"path":%q,"op":"egal","value":"a"}`, path)
}

// Règles d'EX-4.2 que le schéma n'exprime pas, construites ici.
func TestValidationHorsSchema(t *testing.T) {
	sch := schemasTest(t)
	ptr32 := "/arguments" + strings.Repeat("/a", 31)
	ptr33 := ptr32 + "/a"
	prof := func(n int) string { // condition de n niveaux
		c := predicatTest("/arguments/a")
		for i := 1; i < n; i++ {
			c = `{"all":[` + c + `]}`
		}
		return c
	}
	preds := func(n int) string {
		var ps []string
		for i := 0; i < n; i++ {
			ps = append(ps, predicatTest("/arguments/a"))
		}
		if n <= 64 {
			return `{"all":[` + strings.Join(ps, ",") + `]}`
		}
		return `{"all":[{"all":[` + strings.Join(ps[:64], ",") + `]},{"all":[` + strings.Join(ps[64:], ",") + `]}]}`
	}
	cas := []struct {
		doc string
		att string
	}{
		{politiqueTest(regleTest("r", predicatTest(ptr32)), regleTest("s", prof(8)), regleTest("u", preds(64))), "[]"},
		{politiqueTest(regleTest("r", predicatTest(ptr33))), "[pointeur_trop_long /rules/0/when/path]"},
		{politiqueTest(regleTest("r", prof(9))), "[condition_trop_profonde /rules/0/when]"},
		{politiqueTest(regleTest("r", preds(65))), "[trop_de_predicats /rules/0/when]"},
		{politiqueTest(regleTest("r", "null"), regleTest("defaut", "null"), regleTest("r", "null")), "[nom_double /rules/1/name nom_double /rules/2/name]"},
		{strings.Replace(politiqueTest(regleTest("r", "null")), `"description":null,"tools"`, `"description":"a\ud800","tools"`, 1), "[substitut_isole /rules/0/description]"},
	}
	for i, c := range cas {
		v, err := ParseJSON([]byte(c.doc))
		if err != nil {
			t.Fatalf("cas %d : %v", i, err)
		}
		errs, det := ValiderPolitique(sch, v, "developpement", 3600000)
		var got []string
		for _, e := range errs {
			got = append(got, e.String())
		}
		if s := "[" + strings.Join(got, " ") + "]"; s != c.att {
			t.Errorf("cas %d : %s, attendu %s (%v)", i, s, c.att, det)
		}
	}
	// contest_ms ≥ expire_after_ms (EX-4.2, point 6).
	v, _ := ParseJSON([]byte(politiqueTest(regleTest("r", "null"))))
	errs, _ := ValiderPolitique(sch, v, "developpement", 1)
	if len(errs) != 0 {
		t.Errorf("contest_ms 0 < 1 : %v", errs)
	}
	v, _ = ParseJSON([]byte(strings.Replace(politiqueTest(regleTest("r", "null")), `"contest_ms":0}]`, `"contest_ms":5}]`, 1)))
	errs, _ = ValiderPolitique(sch, v, "developpement", 5)
	if len(errs) != 1 || errs[0].Pointeur == nil || *errs[0].Pointeur != "/rules/0/contest_ms" {
		t.Errorf("contest_ms 5 ≥ 5 : %v", errs)
	}
	// Non conforme au schéma et nom en double : exactement l'entrée schema (EX-4.2).
	v, _ = ParseJSON([]byte(strings.Replace(politiqueTest(regleTest("r", "null"), regleTest("r", "null")), `"version":0`, `"version":1`, 1)))
	if errs, _ = ValiderPolitique(sch, v, "developpement", 3600000); len(errs) != 1 || errs[0].Code != "schema" {
		t.Errorf("schéma et nom double : %v", errs)
	}
	// Pointeurs comparés en unités UTF-16 : /rules/10/name avant /rules/2/name.
	var regles []string
	for i := 0; i <= 10; i++ {
		regles = append(regles, regleTest(fmt.Sprintf("r%d", i), "null"))
	}
	regles[2], regles[10] = regleTest("r0", "null"), regleTest("r1", "null")
	v, _ = ParseJSON([]byte(politiqueTest(regles...)))
	errs, _ = ValiderPolitique(sch, v, "developpement", 3600000)
	var got []string
	for _, e := range errs {
		got = append(got, e.String())
	}
	if s := strings.Join(got, " "); s != "nom_double /rules/10/name nom_double /rules/2/name" {
		t.Errorf("ordre des pointeurs : %s", s)
	}
}

// Le validateur refuse ce que les schémas refusent.
func TestSchemasRefus(t *testing.T) {
	sch := schemasTest(t)
	ok := politiqueTest(regleTest("r", "null"))
	refus := []string{
		strings.Replace(ok, `"version":0`, `"version":1`, 1),
		strings.Replace(ok, `"tools":["x"]`, `"tools":["x*y"]`, 1),
		strings.Replace(ok, `"tools":["x"]`, `"tools":["x**"]`, 1),
		strings.Replace(ok, `"name":"r"`, `"name":"r "`, 1),
		strings.Replace(ok, `"name":"r"`, `"name":"r[1]"`, 1),
		strings.Replace(ok, `"level":"revue","decision":null,"window"`, `"level":"automatique","decision":null,"window"`, 1),
		strings.Replace(ok, `"when":null`, `{"when":1}`, 1),
		strings.Replace(ok, `"when":null`, `"when":{"path":"/arguments/a","op":"strictement_superieur","value":5000}`, 1),
		strings.Replace(ok, `"when":null`, `"when":{"path":"/arguments/a","op":"strictement_superieur","value":"5e3"}`, 1),
		strings.Replace(ok, `"when":null`, `"when":{"path":"/x","op":"existe","value":null}`, 1),
		strings.Replace(ok, `"when":null`, `"when":{"path":"/arguments/~2","op":"existe","value":null}`, 1),
		strings.Replace(ok, `"when":null`, `"when":{"path":"/arguments/a","op":"correspond","value":"^a"}`, 1),
	}
	for _, s := range refus {
		v, err := ParseJSON([]byte(s))
		if err != nil {
			continue // texte JSON invalide : refusé aussi
		}
		if errs := sch.Valider(RefPolitique, v); len(errs) == 0 {
			t.Errorf("accepté : %s", s)
		}
	}
	v, _ := ParseJSON([]byte(ok))
	if errs := sch.Valider(RefPolitique, v); len(errs) != 0 {
		t.Errorf("refusé : %v", errs)
	}
	// ticket-v0 : remise et horodatage.
	rem := `{"remise_id":"apr-0001/1","ticket":"apr-0001","approval":{"decision":"expire","ticket":"apr-0001","request_hash":"0x` + strings.Repeat("ab", 32) + `","threshold":{"required":2,"size":3},"approvers":[],"signatures":[],"reason":"x"},"approver_set":{"threshold":{"required":2,"size":3},"members":["0x` + strings.Repeat("11", 20) + `"],"source":"jeu statique de la politique p"}}`
	r, _ := ParseJSON([]byte(rem))
	if errs := sch.Valider(RefTicket+"#/$defs/remise", r); len(errs) != 0 {
		t.Errorf("remise refusée : %v", errs)
	}
	for _, alt := range []string{
		strings.Replace(rem, `"reason":"x"}`, `"reason":"x","at":"2026-11-12T09:00:00.000Z"}`, 1),
		strings.Replace(rem, `apr-0001/1`, `apr-0001/0`, 1),
		strings.Replace(rem, `jeu statique de la politique p`, `jeu`, 1),
		strings.Replace(rem, `"decision":"expire"`, `"decision":"retire"`, 1),
	} {
		r, _ := ParseJSON([]byte(alt))
		if errs := sch.Valider(RefTicket+"#/$defs/remise", r); len(errs) == 0 {
			t.Errorf("remise acceptée : %s", alt)
		}
	}
}
