package jsonv

import (
	"strings"
	"testing"
)

func TestRefus(t *testing.T) {
	cas := map[string]string{
		"texte vide":                 "",
		"octets après le document":   `{} x`,
		"virgule finale":             `{"a":1,}`,
		"UTF-8 invalide":             "{\"a\":\"\xff\"}",
		"marque d'ordre d'octets":    "\xEF\xBB\xBF{}",
		"caractère de contrôle brut": "{\"a\":\"\x01\"}",
		"échappement inconnu":        `{"a":"\q"}`,
		"zéro de tête":               `{"a":01}`,
		"nombre sans chiffre":        `{"a":-}`,
		"fraction vide":              `{"a":1.}`,
		"littéral inconnu":           `{"a":nul}`,
		"guillemet simple":           `{'a':1}`,
		"tabulation verticale":       "{\v}",
	}
	for nom, texte := range cas {
		if _, err := Analyser([]byte(texte)); err == nil {
			t.Errorf("%s : accepté", nom)
		}
	}
}

// TestProfondeur : profondeur comptée sur les conteneurs imbriqués, la
// racine comprise (CT-6 EX-4.16, point 3, révision 0.4 ; CT-1 §4, règle
// 7) : 128 admise, 129 refusée, qu'un scalaire termine ou non
// l'imbrication. Le lecteur refusait 128 conteneurs dont le dernier n'est
// pas vide (il comptait le scalaire comme un niveau).
func TestProfondeur(t *testing.T) {
	for _, c := range []struct {
		texte string
		ok    bool
	}{
		{strings.Repeat("[", 128) + strings.Repeat("]", 128), true},
		{strings.Repeat("[", 128) + "1" + strings.Repeat("]", 128), true},
		{`{"a":` + strings.Repeat("[", 127) + `"x"` + strings.Repeat("]", 127) + `}`, true},
		{strings.Repeat("[", 129) + strings.Repeat("]", 129), false},
		{strings.Repeat("[", 129) + "1" + strings.Repeat("]", 129), false},
		{`{"a":` + strings.Repeat("[", 128) + strings.Repeat("]", 128) + `}`, false},
		{`1`, true},
	} {
		_, err := Analyser([]byte(c.texte))
		if c.ok && err != nil {
			t.Errorf("profondeur admise refusée (%d octets) : %v", len(c.texte), err)
		}
		if !c.ok && err != ErrProfondeur {
			t.Errorf("profondeur refusée admise (%d octets) : %v", len(c.texte), err)
		}
	}
	// Une profondeur hostile ne fait pas déborder la pile.
	tres := strings.Repeat("[", 1_000_000)
	if _, err := Analyser([]byte(tres)); err != ErrProfondeur {
		t.Errorf("profondeur hostile : %v", err)
	}
}

func TestDoublonsEtSubstituts(t *testing.T) {
	v, err := Analyser([]byte(`{"a":1,"a":2,"b":{"c":"\ud800"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !v.Doublon {
		t.Error("doublon non signalé")
	}
	if n, _ := v.Membre("a").Entier(); n != 2 {
		t.Errorf("dernière occurrence attendue, obtenu %d", n)
	}
	if !v.Chemin("b", "c").SubstitutIsole {
		t.Error("substitut isolé non signalé")
	}
	p, _ := Analyser([]byte(`"😀"`))
	if p.SubstitutIsole || p.Chaine != "😀" {
		t.Errorf("paire de substituts mal lue : %q", p.Chaine)
	}
}

func TestNombres(t *testing.T) {
	v, _ := Analyser([]byte(`[530.0, 1e3, -0, 9007199254740993]`))
	if v.Elements[0].Texte != "530.0" || v.Elements[0].Num != 530 {
		t.Error("530.0")
	}
	if n, ok := v.Elements[1].Entier(); !ok || n != 1000 {
		t.Error("1e3")
	}
	if _, ok := v.Elements[3].Entier(); ok {
		t.Error("hors de l'intervalle sûr accepté comme entier")
	}
}

func TestEgales(t *testing.T) {
	a, _ := Analyser([]byte(`{"x":[1,{"y":2}],"z":null}`))
	b, _ := Analyser([]byte(`{"z":null,"x":[1.0,{"y":2}]}`))
	if !Egales(a, b) {
		t.Error("valeurs égales jugées différentes")
	}
	c, _ := Analyser([]byte(`{"z":null,"x":[1,{"y":3}]}`))
	if Egales(a, c) {
		t.Error("valeurs différentes jugées égales")
	}
}

// TestSubstitutsEnOctets : une suite ED A0 80 à ED BF BF (CESU-8), seule ou
// en paire, est un substitut isolé (défaut de forme canonique), non un texte
// qui n'est pas du JSON (CT-6 EX-4.16, point 1 ; CT-1 §3, révision 0.5) ;
// toute autre suite mal formée reste refusée.
func TestSubstitutsEnOctets(t *testing.T) {
	for nom, texte := range map[string]string{
		"seul":        "{\"a\":\"x\xed\xa0\x80y\"}",
		"paire":       "{\"a\":\"\xed\xa0\xbd\xed\xb8\x80\"}",
		"bas":         "{\"a\":\"\xed\xbf\xbf\"}",
		"dans un nom": "{\"\xed\xa0\x80\":1}",
	} {
		v, err := Analyser([]byte(texte))
		if err != nil {
			t.Errorf("%s : refusé comme texte qui n'est pas du JSON : %v", nom, err)
			continue
		}
		iso := v.Membres[0].NomSubstitut || v.Membres[0].Valeur.SubstitutIsole
		if !iso {
			t.Errorf("%s : substitut non signalé", nom)
		}
	}
	for nom, texte := range map[string]string{
		"ED A0 seul":            "\"\xed\xa0\"",
		"ED 9F 80 hors":         "\"\xed\x9f\"",
		"forme trop longue":     "\"\xc0\x80\"",
		"au-delà de U+10FFFF":   "\"\xf4\x90\x80\x80\"",
		"substitut hors chaîne": "\xed\xa0\x80",
	} {
		if _, err := Analyser([]byte(texte)); err == nil {
			t.Errorf("%s : accepté", nom)
		}
	}
	// Témoin : un caractère valide de trois octets en ED (U+D7FF).
	if v, err := Analyser([]byte("\"\xed\x9f\xbf\"")); err != nil || v.SubstitutIsole {
		t.Errorf("U+D7FF : %v", err)
	}
}
