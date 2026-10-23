package main

import (
	"os"
	"path/filepath"
	"testing"
)

func valeur(t *testing.T, s string) *Value {
	t.Helper()
	v, err := ParseJSON([]byte(s))
	if err != nil {
		t.Fatalf("%s : %v", s, err)
	}
	return v
}

// Exemples d'EX-4.6 : "5000.00" = "5000" = 5000 ; "5000.000000000000000001"
// > "5000" ; -0 et -0.00 valent zéro.
func TestComparaisonsExactes(t *testing.T) {
	d := func(s string) Decimal {
		x, ok := LireDecimal(s)
		if !ok {
			t.Fatalf("%q hors grammaire D", s)
		}
		return x
	}
	cinqMille, _ := Numerique(valeur(t, "5000"))
	if Comparer(d("5000.00"), d("5000")) != 0 || Comparer(d("5000.00"), cinqMille) != 0 {
		t.Error("5000.00 ≠ 5000")
	}
	if Comparer(d("5000.000000000000000001"), d("5000")) <= 0 {
		t.Error("5000.000000000000000001 ≤ 5000")
	}
	if Comparer(d("-0"), d("0")) != 0 || Comparer(d("-0.00"), d("0")) != 0 {
		t.Error("-0 ≠ 0")
	}
	if Comparer(d("10.00"), d("9.00")) <= 0 {
		t.Error("10.00 ≤ 9.00 (ordre des chaînes)")
	}
	for _, s := range []string{`"7,400.00"`, `"1e3"`, `" 12"`, `"+1"`, `".5"`, `"5."`, `"01"`, `7400.5`, `9007199254740992`, `"1234567890123456789012345678901"`, `"1.1234567890123456789"`} {
		if _, ok := Numerique(valeur(t, s)); ok {
			t.Errorf("%s numérique", s)
		}
	}
	for _, s := range []string{`9007199254740991`, `-9007199254740991`, `7400`, `7400.0`, `"123456789012345678901234567890.123456789012345678"`} {
		if _, ok := Numerique(valeur(t, s)); !ok {
			t.Errorf("%s non numérique", s)
		}
	}
}

// Résolution des pointeurs (EX-4.4).
func TestPointeurs(t *testing.T) {
	r := Objet("arguments", valeur(t, `{"a/b":{"m~n":1},"t":[10,20],"n":null,"s":"x","":{"":2}}`))
	cas := map[string]string{
		"/arguments/a~1b/m~0n":    "1",
		"/arguments/t/1":          "20",
		"/arguments/n":            "null",
		"/arguments//":            "2",
		"/arguments/t/-":          "",
		"/arguments/t/01":         "",
		"/arguments/t/2":          "",
		"/arguments/s/0":          "",
		"/arguments/absent":       "",
		"/arguments/n/x":          "",
		"/arguments/t/0000000000": "",
	}
	for p, a := range cas {
		x := Resoudre(p, r)
		got := ""
		if x != nil {
			got = Compact(x)
		}
		if got != a {
			t.Errorf("%s : %q, attendu %q", p, got, a)
		}
	}
}

// Logique de Kleene (EX-4.8) et garde existe (4.10).
func TestCombinaisons(t *testing.T) {
	r := Objet("arguments", valeur(t, `{"x":"a"}`))
	v := ValeurCondition(valeur(t, `{"all":[{"path":"/arguments/priority","op":"existe","value":null},{"path":"/arguments/priority","op":"egal","value":"haute"}]}`), r, nil)
	if v != FAUX {
		t.Errorf("garde existe : %v", v)
	}
	vrai := `{"path":"/arguments/x","op":"egal","value":"a"}`
	faux := `{"path":"/arguments/x","op":"egal","value":"b"}`
	ind := `{"path":"/arguments/y","op":"egal","value":"a"}`
	cas := []struct {
		c   string
		att Verite
	}{
		{`{"all":[` + vrai + `,` + ind + `]}`, INDETERMINE},
		{`{"all":[` + ind + `,` + faux + `]}`, FAUX},
		{`{"any":[` + ind + `,` + vrai + `]}`, VRAI},
		{`{"any":[` + faux + `,` + ind + `]}`, INDETERMINE},
		{`{"none":[` + faux + `,` + faux + `]}`, VRAI},
		{`{"none":[` + ind + `,` + faux + `]}`, INDETERMINE},
		{`{"none":[` + ind + `,` + vrai + `]}`, FAUX},
	}
	for _, c := range cas {
		if got := ValeurCondition(valeur(t, c.c), r, nil); got != c.att {
			t.Errorf("%s : %v, attendu %v", c.c, got, c.att)
		}
	}
}

// Sélection (EX-4.3).
func TestSelection(t *testing.T) {
	if !Selectionne([]string{"sap__*"}, "sap__payments.create") || Selectionne([]string{"sap__*"}, "sapx__payments.create") {
		t.Error("préfixe")
	}
	if Selectionne([]string{"sap.payments.create"}, "SAP.payments.create") || !Selectionne([]string{"*"}, "x") {
		t.Error("casse ou joker seul")
	}
}

// politiqueSpecification lit l'exemple complet de CT-3 §4.3 dans le texte de
// la spécification.
func politiqueSpecification(t *testing.T) (*Politique, string) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "CT-3-approbations.md"))
	if err != nil {
		t.Skip("spécification introuvable")
	}
	v, err := blocJSON(string(src), "<!-- schema: politique-approbation -->")
	if err != nil {
		t.Fatal(err)
	}
	sch, err := ChargerSchemas(filepath.Join("..", "..", "..", "schemas", "politique-approbation-v0.schema.json"),
		filepath.Join("..", "..", "..", "schemas", "ticket-v0.schema.json"), filepath.Join("..", "..", "..", "schemas", "evenement-v0.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if errs, det := ValiderPolitique(sch, v, "production", 3600000); len(errs) > 0 {
		t.Fatalf("exemple de §4.3 refusé : %v %v", errs, det)
	}
	return LirePolitique(v), string(src)
}

// Table de CT-3 §6.7, transcrite du texte, sur la politique de §4.3.
func TestCasLimites67(t *testing.T) {
	p, _ := politiqueSpecification(t)
	base := func(extra string) string {
		return `{"claim_id":"2026-77812","currency":"CHF","beneficiary_iban":"CH9300762011623852957"` + extra + `}`
	}
	tt, _ := LireInstant("2026-11-05T10:00:00.000Z")
	debut, _ := LireInstant("2026-11-05T08:00:00.000Z")
	fin, _ := LireInstant("2026-11-05T16:00:00.000Z")
	fenetre := func() []*Fenetre {
		return []*Fenetre{{Portee: Portee{PolicyVersion: "v", Regle: "paiement de 1000 a 5000 CHF", Outil: "sap.payments.create", LaunchedBy: "u.martin@assureur-demo.example", Valeurs: []string{"CH9300762011623852957"}}, Debut: debut, Fin: fin, Restant: 20, Ticket: "apr-3001"}}
	}
	sansIBAN := `{"claim_id":"2026-77812","currency":"CHF","amount":"2500.00"}`
	cas := []struct {
		outil, args string
		fen         bool
		dec, regle  string
	}{
		{"crm.claims.get", `{"claim_id":"2026-77812"}`, false, "autorise", "outil crm.claims.get : lecture autorisee"},
		{"sap.payments.create", base(`,"amount":"7400.00"`), false, "a_approuver", "paiement > 5000 CHF"},
		{"sap.payments.create", `{"amount":"7400.00","currency":"CHF","beneficiary_iban":"CH0000000000000000000"}`, false, "refuse", "beneficiaire hors liste blanche"},
		{"sap.payments.create", base(`,"amount":"800"`), false, "autorise", "paiement <= 1000 CHF"},
		{"sap.payments.create", base(`,"amount":"2500.00"`), false, "a_approuver", "paiement de 1000 a 5000 CHF"},
		{"sap.payments.create", base(`,"amount":"2500.00"`), true, "autorise", "paiement de 1000 a 5000 CHF [fenetre apr-3001 2026-11-05T16:00:00.000Z]"},
		{"sap.payments.create", `{"amount":"2500.00","currency":"CHF","beneficiary_iban":"CH5604835012345678009"}`, true, "a_approuver", "paiement de 1000 a 5000 CHF"},
		{"sap.payments.create", base(`,"amount":"5000.00"`), false, "a_approuver", "paiement de 1000 a 5000 CHF"},
		{"sap.payments.create", base(`,"amount":"5000.000000000000000001"`), false, "a_approuver", "paiement > 5000 CHF"},
		{"sap.payments.create", base(`,"amount":7400`), false, "a_approuver", "paiement > 5000 CHF"},
		{"sap.payments.create", base(`,"amount":7400.5`), false, "a_approuver", "paiement > 5000 CHF [indetermine]"},
		{"sap.payments.create", base(`,"amount":"7,400.00"`), false, "a_approuver", "paiement > 5000 CHF [indetermine]"},
		{"sap.payments.create", base(``), false, "a_approuver", "paiement > 5000 CHF [indetermine]"},
		{"sap.payments.create", `{"amount":"7400.00","beneficiary_iban":"CH9300762011623852957"}`, false, "refuse", "paiement hors CHF [indetermine]"},
		{"sap.payments.create", `{"amount":"7400.00","currency":"chf","beneficiary_iban":"CH9300762011623852957"}`, false, "refuse", "paiement hors CHF"},
		{"sap.payments.create", sansIBAN, true, "refuse", "beneficiaire hors liste blanche [indetermine]"},
		{"sap.payments.create", base(`,"amount":"0"`), false, "a_approuver", "defaut : revue"},
		{"sap.payments.create", base(`,"amount":"-0"`), false, "a_approuver", "defaut : revue"},
		{"mail.send", `{"recipient_role":"assure"}`, false, "autorise", "outil mail.send : envoi autorise vers l'assure"},
		{"mail.send", `{"recipient_role":"garage"}`, false, "a_approuver", "defaut : revue"},
		{"mail.send", `{}`, false, "a_approuver", "defaut : revue"},
		{"sap.payments.list", `{}`, false, "a_approuver", "defaut : revue"},
		{"SAP.payments.create", base(`,"amount":"7400.00"`), false, "a_approuver", "defaut : revue"},
		{"crm.claims.delete", `{"claim_id":"2026-77812"}`, false, "a_approuver", "suppression de sinistre"},
	}
	for _, c := range cas {
		var f []*Fenetre
		if c.fen {
			f = fenetre()
		}
		d := Demande{Outil: c.outil, Arguments: valeur(t, c.args), LaunchedBy: "u.martin@assureur-demo.example"}
		s := Evaluer(p, "v", d, f, tt, nil)
		if s.Decision != c.dec || s.Regle != c.regle {
			t.Errorf("%s %s : (%s, %s), attendu (%s, %s)", c.outil, c.args, s.Decision, s.Regle, c.dec, c.regle)
		}
		if c.fen && c.dec == "autorise" && (s.Consommee != 0 || f[0].Restant != 20) {
			t.Errorf("%s : fenêtre consommée %d", c.args, s.Consommee)
		}
	}
	// « crm.claims.delete : revue inconditionnelle, contest_ms 900 000 »
	s := Evaluer(p, "v", Demande{Outil: "crm.claims.delete", Arguments: Objet(), LaunchedBy: "x"}, nil, tt, nil)
	if s.ContestMs == nil || *s.ContestMs != 900000 {
		t.Errorf("contest_ms : %v", s.ContestMs)
	}
	// Ticket ouvrant (EX-5.3) : portée et fenêtre de la règle.
	s = Evaluer(p, "v", Demande{Outil: "sap.payments.create", Arguments: valeur(t, base(`,"amount":"2500.00"`)), LaunchedBy: "u.martin@assureur-demo.example"}, nil, tt, nil)
	if s.Ouverture == nil || s.Ouverture.DureeMs != 28800000 || s.Ouverture.MaxAppels != 20 || len(s.Ouverture.Portee.Valeurs) != 1 || s.Ouverture.Portee.Outil != "sap.payments.create" {
		t.Errorf("ouverture : %+v", s.Ouverture)
	}
}

// Exemple de 4.12 (EX-4.11) sur la politique de §4.3.
func TestCandidatsSpecification(t *testing.T) {
	p, _ := politiqueSpecification(t)
	got := Candidats(p, []string{"crm.claims.get", "crm.claims.delete", "documents.search", "mail.send", "sap.payments.create", "sap.payments.list", "mail.send"})
	att := []string{"crm.claims.delete", "mail.send", "sap.payments.create", "sap.payments.list"}
	if listeChaines(got) != listeChaines(att) {
		t.Errorf("%v, attendu %v", got, att)
	}
}
