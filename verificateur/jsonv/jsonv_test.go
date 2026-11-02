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

func TestProfondeur(t *testing.T) {
	ok := strings.Repeat("[", 128) + strings.Repeat("]", 128)
	if _, err := Analyser([]byte(ok)); err != nil {
		t.Errorf("128 niveaux refusés : %v", err)
	}
	ko := strings.Repeat("[", 129) + strings.Repeat("]", 129)
	if _, err := Analyser([]byte(ko)); err != ErrProfondeur {
		t.Errorf("129 niveaux : %v", err)
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
