package main

// Essais des lignes que les points 10 et 12 de la section 0 de CT-3 taisaient
// (complément du 2026-11-16, point 13), écrits depuis le seul texte : une
// opération expirer à l'instant indécodable ne se rejoue pas (EX-13.19,
// point 6) ; un received_at indécodable donne preuve_discordante, à côté de
// preuve_invalide si la signature est aussi fautive (EX-13.19, point 4) ; les
// instants que posent les opérations rejouées sont le texte de leur at
// (EX-13.19, point 6) ; et les quatre cas de annuaire/exports/ qui les
// exercent.

import (
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// indecodable rend le texte d'un instant décodable dont la date devient le
// 31 novembre 2026, à la même heure : il respecte le motif de
// $defs/horodatage sans se décoder (CT-1 §3).
func indecodable(t *testing.T, s string) string {
	t.Helper()
	if _, err := LireInstant(s); err != nil {
		t.Fatalf("instant de départ inattendu : %q", s)
	}
	x := "2026-11-31" + s[len("2026-11-10"):]
	if _, err := LireInstant(x); err == nil {
		t.Fatalf("%q se décode", x)
	}
	return x
}

// Règle 1. EX-13.19, point 6 (complément du 2026-11-16) : « une opération
// expirer dont l'at respecte le motif sans se décoder (CT-1 §3) ne se rejoue
// pas, la condition at ≥ created_at + 86 400 000 ne pouvant être établie ; le
// rejeu s'arrête à elle (/operations/<j>), en plus de l'écart du point 2 ».
func TestExpirerInstantIndecodable(t *testing.T) {
	s, _ := essaiExport(t)
	sch := s.e.Sch
	ops := s.e.Doc.Get("operations").Arr
	j := -1
	for i, op := range ops {
		if op.Get("op").S() == "expirer" {
			j = i
		}
	}
	if j != 4 {
		t.Fatalf("opération expirer en %d, attendue en 4", j)
	}
	doc := Copier(s.e.Doc)
	op := doc.Get("operations").Arr[j]
	poser(op, "at", Chaine(indecodable(t, op.Get("at").S())))
	// L'inscription d'apb-0001 (opération 0), placée plus haut, se rejoue
	// sans preuve : le rejeu s'arrête à l'expirer, non à elle.
	if got := ecartsTexte(VerifierAnnuaireExporte(sch, doc)); got != "operations_incoherentes /operations/4;revision_incoherente /operations/4/at" {
		t.Errorf("expirer à l'instant indécodable : %q", got)
	}
	// Même instant indécodable sur la dernière opération, un expirer : le
	// point 2 compare updated_at au texte de l'at, sans décodage.
	der := Copier(doc)
	dops := der.Get("operations")
	dops.Arr = dops.Arr[:j+1]
	poser(der, "revision", Entier(int64(j+1)))
	poser(der, "updated_at", Copier(dops.Arr[j].Get("at")))
	var garde []*Value
	for _, x := range der.Get("entries").Arr {
		if x.Get("id").S() == "apb-0002" {
			garde = append(garde, x)
		}
	}
	der.Get("entries").Arr = garde
	if got := ecartsTexte(VerifierAnnuaireExporte(sch, der)); got != "operations_incoherentes /operations/4;revision_incoherente /operations/4/at" {
		t.Errorf("expirer indécodable en dernière opération : %q", got)
	}
}

// Règle 2. EX-13.19, point 4 (complément du 2026-11-16) : « un received_at
// qui respecte le motif sans se décoder (CT-1 §3) n'établit pas cette
// condition et donne preuve_discordante » ; révision 0.6 : « les deux examens
// sont faits l'un et l'autre, et une preuve fautive aux deux porte les deux
// codes, au même pointeur » ; « un message qui ne s'analyse pas selon
// EX-13.12 ne donne que preuve_invalide ».
func TestReceivedAtIndecodable(t *testing.T) {
	s, _ := essaiExport(t)
	sch := s.e.Sch
	const P = "/entries/0/addresses/0/proof"
	preuve := func(doc *Value) *Value {
		_, x := entreeDuDoc(t, doc, "apb-0002")
		return x.Get("addresses").Arr[0].Get("proof")
	}
	recu := preuve(s.e.Doc).Get("received_at").S()
	ind := indecodable(t, recu)

	// Signature valable : preuve_discordante seul ; la preuve rejouée porte
	// l'at de l'opération, décodable : /entries.
	seul := Copier(s.e.Doc)
	poser(preuve(seul), "received_at", Chaine(ind))
	if got := ecartsTexte(VerifierAnnuaireExporte(sch, seul)); got != "operations_incoherentes /entries;preuve_discordante "+P {
		t.Errorf("received_at indécodable : %q", got)
	}

	// Signature non canonique (s haut, v inversé) : les deux codes.
	haute := Copier(s.e.Doc)
	p := preuve(haute)
	poser(p, "received_at", Chaine(ind))
	sig, err := DecoderSignature(p.Get("signature").S())
	if err != nil {
		t.Fatal(err)
	}
	sig.S = new(big.Int).Sub(secpN, sig.S)
	sig.V = 55 - sig.V
	poser(p, "signature", Chaine(sig.Encoder()))
	if got := ecartsTexte(VerifierAnnuaireExporte(sch, haute)); got != "operations_incoherentes /entries;preuve_discordante "+P+";preuve_invalide "+P {
		t.Errorf("received_at indécodable, signature haute : %q", got)
	}

	// Signature par une autre clé : les deux codes ; l'inscription ne se
	// rejoue pas (opération 1).
	autre := Copier(s.e.Doc)
	p = preuve(autre)
	poser(p, "received_at", Chaine(ind))
	sg, err := SignerMessage(s.k.Prives[s.k.Comptes[1]], []byte(p.Get("message").S()))
	if err != nil {
		t.Fatal(err)
	}
	poser(p, "signature", Chaine(sg))
	if got := ecartsTexte(VerifierAnnuaireExporte(sch, autre)); got != "preuve_discordante "+P+";preuve_invalide "+P+";operations_incoherentes /operations/1" {
		t.Errorf("received_at indécodable, autre clé : %q", got)
	}

	// Révision 0.6, même règle : signature par une autre clé et received_at
	// décodable hors de la fenêtre du message : les deux codes.
	hors := Copier(s.e.Doc)
	p = preuve(hors)
	expire, err := LireInstant(p.Get("expires_at").S())
	if err != nil {
		t.Fatal(err)
	}
	poser(p, "received_at", Chaine(expire.String()))
	poser(p, "signature", Chaine(sg))
	if got := ecartsTexte(VerifierAnnuaireExporte(sch, hors)); got != "preuve_discordante "+P+";preuve_invalide "+P+";operations_incoherentes /operations/1" {
		t.Errorf("received_at à Expire le, autre clé : %q", got)
	}

	// Message non analysable : preuve_invalide seul, même avec un
	// received_at indécodable.
	illisible := Copier(s.e.Doc)
	p = preuve(illisible)
	poser(p, "received_at", Chaine(ind))
	poser(p, "message", Chaine(p.Get("message").S()+"\n"))
	if got := ecartsTexte(VerifierAnnuaireExporte(sch, illisible)); got != "preuve_invalide "+P+";operations_incoherentes /operations/1" {
		t.Errorf("message non analysable, received_at indécodable : %q", got)
	}
}

// Règle 3. EX-13.19, point 6 (complément du 2026-11-16) : « Les instants que
// posent les opérations rejouées sont le texte de leur at, caractère pour
// caractère, sans décodage ni réécriture : created_at de l'entrée créée et
// received_at de la preuve (inscrire) ; validated_at de l'adresse validée et
// revoked_at de l'adresse active qu'elle remplace (valider) ; revoked_at de
// l'adresse révoquée (revoquer) et de chaque adresse en_attente ou active de
// l'entrée (desactiver) ; expirer, reactiver, lier_demandeur,
// delier_demandeur et changer_administrateurs n'en posent aucun. Le rejeu ne
// pose pas updated_at, que le point 2 compare au texte de l'at de la
// dernière opération. »
func TestInstantsPosesTexteAt(t *testing.T) {
	s := nouvelEssaiAnnuaire(t)
	k := s.k
	t0, _ := LireInstant("2026-11-10T08:00:00.000Z")
	a1, a2 := essaiIdentite("approbateur-1"), essaiIdentite("approbateur-2")
	ok := func(r IssueOperation, quoi string) {
		t.Helper()
		if !r.Accepte {
			t.Fatalf("%s : %s", quoi, r.Raison)
		}
	}
	s.inscrire(a1, k.Comptes[1], t0)                                                                                                                                 // 0 inscrire
	ok(s.operer("valider", `{"session_identity":"`+essaiAdmin+`","entry":"apb-0001","address":"`+k.Comptes[1]+`"}`, t0+111111), "valider")                           // 1
	s.inscrire(a1, k.Comptes[4], t0+222222)                                                                                                                          // 2 inscrire
	ok(s.operer("valider", `{"session_identity":"`+essaiAdmin+`","entry":"apb-0001","address":"`+k.Comptes[4]+`"}`, t0+333333), "remplacement")                      // 3
	s.inscrire(a2, k.Comptes[2], t0+444444)                                                                                                                          // 4 inscrire
	ok(s.operer("revoquer", `{"session_identity":"`+a2+`","entry":"apb-0002","address":"`+k.Comptes[2]+`","reason":"essai"}`, t0+555555), "revoquer")                // 5
	ok(s.operer("lier_demandeur", `{"session_identity":"`+essaiAdmin+`","entry":"apb-0001","launched_by":"u.dupont@assureur-demo.example"}`, t0+666666), "lier")     // 6
	ok(s.operer("desactiver", `{"session_identity":"`+essaiAdmin+`","entry":"apb-0001","reason":"essai"}`, t0+777777), "desactiver")                                 // 7
	ok(s.operer("reactiver", `{"session_identity":"`+essaiAdmin+`","entry":"apb-0001","reason":"essai"}`, t0+888888), "reactiver")                                   // 8
	ok(s.operer("delier_demandeur", `{"session_identity":"`+essaiAdmin+`","entry":"apb-0001","launched_by":"u.dupont@assureur-demo.example"}`, t0+999999), "delier") // 9
	sch := s.e.Sch
	if got := ecartsTexte(VerifierAnnuaireExporte(sch, s.e.Doc)); got != "" {
		t.Fatalf("annuaire de départ : %q", got)
	}

	// Chaque opération hors inscrire passe au 31 novembre ; les instants
	// qu'elle a posés dans le document prennent le même texte.
	src, err := Canonique(s.e.Doc)
	if err != nil {
		t.Fatal(err)
	}
	texte := string(src)
	var attendu []string
	for j, op := range s.e.Doc.Get("operations").Arr {
		if op.Get("op").S() == "inscrire" {
			continue
		}
		at := op.Get("at").S()
		if strings.Count(texte, `"`+at+`"`) < 1 {
			t.Fatalf("instant %s absent", at)
		}
		texte = strings.ReplaceAll(texte, `"`+at+`"`, `"`+indecodable(t, at)+`"`)
		attendu = append(attendu, "revision_incoherente /operations/"+itoa(j)+"/at")
	}
	doc, err := ParseJSON([]byte(texte))
	if err != nil {
		t.Fatal(err)
	}
	// Le document porte bien ces textes là où la règle les nomme.
	adr := func(d *Value, id string, n int) *Value {
		_, x := entreeDuDoc(t, d, id)
		return x.Get("addresses").Arr[n]
	}
	ops := doc.Get("operations").Arr
	for _, c := range []struct {
		quoi   string
		valeur *Value
		op     int
	}{
		{"validated_at du compte 1 (valider)", adr(doc, "apb-0001", 0).Get("validated_at"), 1},
		{"revoked_at du compte 1 (remplacee)", adr(doc, "apb-0001", 0).Get("revoked_at"), 3},
		{"validated_at du compte 4 (valider)", adr(doc, "apb-0001", 1).Get("validated_at"), 3},
		{"revoked_at du compte 2 (revoquer)", adr(doc, "apb-0002", 0).Get("revoked_at"), 5},
		{"revoked_at du compte 4 (desactivation)", adr(doc, "apb-0001", 1).Get("revoked_at"), 7},
		{"updated_at", doc.Get("updated_at"), 9},
	} {
		if c.valeur.S() != ops[c.op].Get("at").S() {
			t.Fatalf("%s : %q, attendu l'at de l'opération %d", c.quoi, c.valeur.S(), c.op)
		}
	}
	if got := ecartsTexte(VerifierAnnuaireExporte(sch, doc)); got != strings.Join(attendu, ";") {
		t.Errorf("instants posés égaux au texte de l'at :\n obtenu  %q\n attendu %q", got, strings.Join(attendu, ";"))
	}

	// Un autre texte à l'une de ces places : le rejeu, qui pose le texte de
	// l'at, aboutit à d'autres entrées.
	for _, c := range []struct {
		quoi  string
		id    string
		n     int
		champ string
	}{
		{"validated_at (valider)", "apb-0001", 0, "validated_at"},
		{"revoked_at (remplacee)", "apb-0001", 0, "revoked_at"},
		{"revoked_at (revoquer)", "apb-0002", 0, "revoked_at"},
		{"revoked_at (desactivation)", "apb-0001", 1, "revoked_at"},
	} {
		d := Copier(doc)
		poser(adr(d, c.id, c.n), c.champ, Chaine("2026-11-30T23:59:59.999Z"))
		want := "operations_incoherentes /entries;" + strings.Join(attendu, ";")
		if got := ecartsTexte(VerifierAnnuaireExporte(sch, d)); got != want {
			t.Errorf("%s autre que le texte de l'at : %q", c.quoi, got)
		}
	}

	// updated_at autre que le texte de l'at de la dernière opération :
	// /updated_at, même si les deux textes désignent le même jour.
	d := Copier(doc)
	poser(d, "updated_at", Chaine("2026-11-31T08:16:40.000Z"))
	if got := ecartsTexte(VerifierAnnuaireExporte(sch, d)); !strings.Contains(got, "revision_incoherente /updated_at") {
		t.Errorf("updated_at autre que l'at de la dernière opération : %q", got)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

// Les quatre cas de annuaire/exports/ du point 13 (EX-13.19, points 2, 4 et
// 6) : leurs écarts recalculés égalent ceux d'exports/attendu.json, et chacun
// porte ce que sa règle exerce.
func TestCasInstantsIndecodablesPublies(t *testing.T) {
	dir := filepath.Join("..", "annuaire", "exports")
	b, err := os.ReadFile(filepath.Join(dir, "attendu.json"))
	if err != nil {
		t.Skip("vecteurs publiés absents")
	}
	att, err := ParseJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	sch := schemasConsoleTest(t)
	lire := func(nom string) (*Value, string) {
		t.Helper()
		src, err := os.ReadFile(filepath.Join(dir, nom))
		if err != nil {
			t.Fatal(err)
		}
		doc, err := ParseJSON(src)
		if err != nil {
			t.Fatal(err)
		}
		var l []string
		for _, c := range att.Get("cases").Arr {
			if c.Get("file").S() == nom {
				for _, e := range c.Get("errors").Arr {
					p := "null"
					if !e.Get("pointer").IsNull() {
						p = e.Get("pointer").S()
					}
					l = append(l, e.Get("code").S()+" "+p)
				}
				return doc, strings.Join(l, ";")
			}
		}
		t.Fatalf("%s absent d'attendu.json", nom)
		return nil, ""
	}
	indec := func(s string) bool { _, err := LireInstant(s); return err != nil }
	verifier := func(nom string, doc *Value, attendu string) {
		t.Helper()
		if got := ecartsTexte(VerifierAnnuaireExporte(sch, doc)); got != attendu {
			t.Errorf("%s :\n obtenu  %q\n attendu %q", nom, got, attendu)
		}
	}

	// Règle 1.
	doc, want := lire("expiration-instant-indecodable.json")
	verifier("expiration-instant-indecodable.json", doc, want)
	vu := false
	for j, op := range doc.Get("operations").Arr {
		if op.Get("op").S() == "expirer" && indec(op.Get("at").S()) {
			vu = strings.Contains(want, "operations_incoherentes /operations/"+itoa(j))
		}
	}
	if !vu {
		t.Errorf("expiration-instant-indecodable.json n'arrête pas le rejeu à un expirer indécodable : %q", want)
	}

	// Règles 2 et 3 (created_at, received_at).
	doc, want = lire("inscription-instant-indecodable.json")
	verifier("inscription-instant-indecodable.json", doc, want)
	vu = false
	for _, op := range doc.Get("operations").Arr {
		if at := op.Get("at").S(); op.Get("op").S() == "inscrire" && indec(at) {
			for _, x := range doc.Get("entries").Arr {
				if x.Get("id").S() == op.Get("entry").S() && x.Get("created_at").S() == at {
					if a := adresseDeLEntree(x, op.Get("address").S()); a != nil && a.Get("proof").Get("received_at").S() == at {
						vu = true
					}
				}
			}
		}
	}
	if !vu || !strings.Contains(want, "preuve_discordante") || strings.Contains(want, "/entries;") || strings.HasSuffix(want, "/entries") {
		t.Errorf("inscription-instant-indecodable.json n'exerce pas created_at et received_at : %q", want)
	}

	// Règle 3 (validated_at, revoked_at de revoquer, updated_at ; revoked_at
	// de remplacee et de desactivation).
	for _, nom := range []string{"instants-indecodables-rejoues.json", "remplacement-instants-indecodables.json"} {
		doc, want = lire(nom)
		verifier(nom, doc, want)
		poses := map[string]bool{}
		for _, x := range doc.Get("entries").Arr {
			for _, a := range x.Get("addresses").Arr {
				for _, champ := range []string{"validated_at", "revoked_at"} {
					if v := a.Get(champ); !v.IsNull() && indec(v.S()) {
						cause := ""
						if champ == "revoked_at" {
							cause = " " + a.Get("revocation_cause").S()
						}
						poses[champ+cause] = true
						// Un autre texte à cette place : /entries.
						d := Copier(doc)
						for _, y := range d.Get("entries").Arr {
							if y.Get("id").S() == x.Get("id").S() {
								poser(adresseDeLEntree(y, a.Get("address").S()), champ, Chaine("2026-11-30T23:59:59.999Z"))
							}
						}
						if got := ecartsTexte(VerifierAnnuaireExporte(sch, d)); !strings.HasPrefix(got, "operations_incoherentes /entries;") {
							t.Errorf("%s : %s de %s changé : %q", nom, champ, a.Get("address").S(), got)
						}
					}
				}
			}
		}
		exige := map[string][]string{
			"instants-indecodables-rejoues.json":      {"validated_at", "revoked_at personne", "revoked_at administrateur"},
			"remplacement-instants-indecodables.json": {"validated_at", "revoked_at remplacee", "revoked_at desactivation"},
		}[nom]
		n := 0
		for _, e := range exige {
			if poses[e] {
				n++
			}
		}
		if n < 2 {
			t.Errorf("%s : instants indécodables posés %v, attendus parmi %v", nom, poses, exige)
		}
		if strings.Contains(want, "/entries") || strings.Contains(want, "/updated_at") {
			t.Errorf("%s : %q", nom, want)
		}
	}
	doc, _ = lire("instants-indecodables-rejoues.json")
	if !indec(doc.Get("updated_at").S()) {
		t.Errorf("instants-indecodables-rejoues.json : updated_at décodable")
	}
}
