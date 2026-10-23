package main

import (
	"strings"
	"testing"
)

func chargerEssai(t *testing.T, texte string) *Politique {
	t.Helper()
	doc, err := ParseJSON([]byte(texte))
	if err != nil {
		t.Fatal(err)
	}
	p, mq := ChargerPolitique(doc)
	if len(mq) > 0 {
		t.Fatal(mq)
	}
	return p
}

// EX-10.14 : passages jusqu'à un passage qui ne change rien ; EX-10.15 :
// idempotence ; les compteurs additionnent les passages.
func TestPassagesJusquAuPointFixe(t *testing.T) {
	p := chargerEssai(t, `{"version":0,"name":"essai","pseudonym_key":null,"named_patterns":{"lettre":{"pattern":"Q"}},"rules":[
	  {"id":"iban","scopes":["arguments"],"tools":"*","detectors":[{"type":"iban"}],"action":{"kind":"remplacer"}},
	  {"id":"q","scopes":["arguments"],"tools":"*","detectors":[{"type":"regex","name":"lettre"}],"action":{"kind":"remplacer"}}]}`)
	v, _ := ParseJSON([]byte(`{"t":"QCH9300762011623852957"}`))
	pc, res, err := PieceRedigeeJSON(p, "arguments", "", v)
	if err != nil {
		t.Fatal(err)
	}
	if string(pc.Octets) != `{"t":"[REDIGE:lettre][REDIGE:iban]"}` || res.Passages != 3 {
		t.Errorf("obtenu %s en %d passages", pc.Octets, res.Passages)
	}
	if len(res.Decomptes) != 2 {
		t.Errorf("décomptes : %+v", res.Decomptes)
	}
	w, _ := ParseJSON(pc.Octets)
	p2, _, _ := PieceRedigeeJSON(p, "arguments", "", w)
	if string(p2.Octets) != string(pc.Octets) || p2.Redigee {
		t.Errorf("idempotence : %s", p2.Octets)
	}
}

// EX-10.9 : un jeton est opaque (aucune correspondance dedans ni à cheval) et
// ses bords valent bords de chaîne ; EX-10.11 : champ laisse un jeton tel quel,
// et le pseudonyme d'une chaîne est calculé sur la chaîne elle-même.
func TestJetonsOpaquesEtChamp(t *testing.T) {
	p := chargerEssai(t, `{"version":0,"name":"essai","pseudonym_key":{"env":"`+VariableClePseudoTest+`","encoding":"hex"},"rules":[
	  {"id":"champ","scopes":["arguments"],"tools":"*","path":"/iban","detectors":[{"type":"champ","label":"iban"}],"action":{"kind":"pseudonyme"}},
	  {"id":"texte","scopes":["arguments"],"tools":"*","detectors":[{"type":"carte"},{"type":"iban"}],"action":{"kind":"pseudonyme"}}]}`)
	v, _ := ParseJSON([]byte(`{"iban":"CH9300762011623852957","note":"[PSEUDO:iban:378282246313] CH9300762011623852957"}`))
	pc, _, _ := PieceRedigeeJSON(p, "arguments", "", v)
	attendu := `{"iban":"[PSEUDO:iban:50d46ea9a82b]","note":"[PSEUDO:iban:378282246313] [PSEUDO:iban:50d46ea9a82b]"}`
	if string(pc.Octets) != attendu {
		t.Errorf("obtenu %s", pc.Octets)
	}
	w, _ := ParseJSON(pc.Octets)
	p2, _, _ := PieceRedigeeJSON(p, "arguments", "", w)
	if string(p2.Octets) != attendu || p2.Redigee {
		t.Errorf("champ sur un jeton : %s", p2.Octets)
	}
}

// 15.2, EX-10.12 : décodage de la clé selon son encoding.
func TestDecoderSecret(t *testing.T) {
	for _, c := range []struct{ v, enc, hex string }{{"0x00ff", "hex", "00ff"}, {"00ff", "hex", "00ff"}, {"AP8=", "base64", "00ff"}, {"é", "utf8", "c3a9"}} {
		b, err := DecoderSecret(c.v, c.enc)
		if err != nil || Hex0x(b) != "0x"+c.hex {
			t.Errorf("%s %s : %x %v", c.enc, c.v, b, err)
		}
	}
	for _, c := range [][2]string{{"0x0", "hex"}, {"zz", "hex"}, {"AP8", "base64"}, {"", "base64"}, {"x", "latin1"}} {
		if _, err := DecoderSecret(c[0], c[1]); err == nil {
			t.Errorf("%s %s : refus attendu", c[1], c[0])
		}
	}
}

// EX-10.6 : sous-ensemble commun ECMAScript/RE2, liste autorisée.
func TestSousEnsembleCommun(t *testing.T) {
	for _, m := range []string{`\b20[0-9]{2}-[0-9]{5}\b`, `[^\n]+`, `[ \t\n\r\f\v]`, `\x41\d\w\W\D`, `(?P<a>x)|(?<b>y)|(?:z)`, `a{2,1000}?`, `[-a-z\-]`, `^a$`} {
		if r := ErreurMotifCommun(m); r != "" {
			t.Errorf("%s : refusé (%s)", m, r)
		}
	}
	for _, m := range []string{`IBAN\s[A-Z]+`, `.`, `\u0041`, `\x{41}`, `\p{L}`, `\A`, `[[:alpha:]]`, `(?=a)`, `(?i)a`, `a*+`, `(a)\1`, `a{1001}`, `[]`, `\bx\b*`, `x{,3}`, `[z-a]`, `(?<n>a)(?<n>b)`} {
		if r := ErreurMotifCommun(m); r == "" {
			t.Errorf("%s : admis", m)
		} else if strings.TrimSpace(r) == "" {
			t.Errorf("%s : raison vide", m)
		}
	}
}

// EX-10.6, règles de structure et de taille (version 0.3) : chaque exemple
// du texte est refusé par la règle qu'il illustre, ou admis.
func TestReglesStructureEtTaille(t *testing.T) {
	for _, c := range []struct{ motif, regle string }{
		{`^(a+)+$`, "règle a)"}, {`([a-zA-Z]+)*$`, "règle a)"}, {`(a|aa)+$`, "règle a)"},
		{`(a|a?)+$`, "règle a)"}, {`(a|aa){1,1000}$`, "règle a)"}, {`(a{1,1000}){1,1000}$`, "règle a)"},
		{`(\w|\d)+$`, "règle a)"}, {`(?:[0-9]{4} ?){3}`, "règle a)"}, {`(?:a(?:b|c))+`, "règle a)"},
		{`(?:a(?:b+))?`, "règle a)"}, {`(?:a+)*?`, "règle a)"},
		{`(?:\b)+x`, "règle b)"}, {`()*`, "règle b)"}, {`(?:^$)?x`, "règle b)"}, {`(?:(?:\B))+`, "règle b)"},
		{`[0-9]{1000}x`, "règle c)"}, {`a{1000}b`, "règle c)"}, {`(?:ab){500,}`, "règle c)"}, {`a{999}|bc`, "règle c)"},
	} {
		if r := ErreurMotifCommun(c.motif); !strings.HasPrefix(r, c.regle) {
			t.Errorf("%s : %q, attendu %s", c.motif, r, c.regle)
		}
	}
	for _, m := range []string{`[0-9]+$`, `[a-z]*[a-z]*[a-z]*!`, `(?P<nom>[0-9]{4})`, `(?:ab)+`, `(?:\b[0-9])+`, `a{1000}`, `(?:ab){499,}`, `a{998}|b`, `(?:x){0}`, `(?:(?:a)b)*`} {
		if r := ErreurMotifCommun(m); r != "" {
			t.Errorf("%s : refusé (%s)", m, r)
		}
	}
	// tailles développées (règle c)
	for m, n := range map[string]int64{`[0-9]{1000}x`: 1001, `(a|aa){1,1000}$`: 3001, `a{0}`: 1, `(?:ab){3,}`: 8, `(?:)`: 0, `\b^a$`: 4, `a?b*c+d{2,5}`: 8} {
		if got := TailleDeveloppee(m); got != n {
			t.Errorf("%s : taille %d, attendue %d", m, got, n)
		}
	}
}

// EX-4.11 : collision après gabarit et normalisation d'une connexion d'hôte.
func TestCollisionApresNormalisation(t *testing.T) {
	s, _ := ParseJSON([]byte(`[{"alias":"demo","tools":[{"name":"a.b"},{"name":"a_b"},{"name":"c"}]}]`))
	if ag := Agreger(s, true, 100); len(ag.Annonces) != 3 {
		t.Errorf("sans normalisation : %d annoncés", len(ag.Annonces))
	}
	ag := Agreger(s, true, 100, Normalisation{Gabarit: "{tool_announced}", Normaliser: true})
	if len(ag.Annonces) != 1 || len(ag.Rejets) != 2 || ag.Rejets[0].Raison != "collision" {
		t.Errorf("avec normalisation : %+v %+v", ag.Annonces, ag.Rejets)
	}
	if n := NomVuParModele("demo__claims.get", "mcp__noortrace__{tool_announced}", true); n != "mcp__noortrace__demo__claims_get" {
		t.Errorf("nom vu : %s", n)
	}
}
