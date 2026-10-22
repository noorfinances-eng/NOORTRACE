package main

// RFC 8785 (JCS), lue sur rfc-editor.org : table 1 de l'annexe B (« Number
// Serialization Samples », à laquelle renvoie la section 3.2.2.3), exemple
// des sections 3.2.2 à 3.2.4, jeu de tri de 3.2.3, exemple de l'annexe E ;
// et les cas limites que l'annexe B.2 de CT-2 rend obligatoires.

import (
	"encoding/hex"
	"math"
	"strconv"
	"strings"
	"testing"
)

func TestTableRFC8785AnnexeB(t *testing.T) {
	finies := 0
	for _, l := range TableRFC8785 {
		bits, err := strconv.ParseUint(l.IEEE, 16, 64)
		if err != nil {
			t.Fatal(err)
		}
		f := math.Float64frombits(bits)
		if l.JSON == "" {
			if !math.IsNaN(f) && !math.IsInf(f, 0) {
				t.Errorf("%s : NaN ou Infinity attendu", l.IEEE)
			}
			continue
		}
		finies++
		if got := NombreES6(f); got != l.JSON {
			t.Errorf("%s → %s, attendu %s", l.IEEE, got, l.JSON)
		}
		// le texte de la colonne se relit sur la même double (sauf -0, qui s'écrit 0)
		g, err := NombreDouble(l.JSON)
		if err != nil {
			t.Errorf("%s : %v", l.JSON, err)
			continue
		}
		if l.IEEE != "8000000000000000" && math.Float64bits(g) != bits {
			t.Errorf("%s relu en %016x, attendu %s", l.JSON, math.Float64bits(g), l.IEEE)
		}
		// et passe par le JCS intégral d'un document
		c, err := CanoniqueIntegralTexte([]byte(`{"n":` + l.JSON + `}`))
		if err != nil || string(c) != `{"n":`+l.JSON+`}` {
			t.Errorf("document {\"n\":%s} : %s %v", l.JSON, c, err)
		}
	}
	if finies != 24 {
		t.Errorf("%d lignes finies, attendu 24", finies)
	}
	// formes équivalentes non canoniques citées par CT-2 B.2
	for in, out := range map[string]string{"1E+21": "1e+21", "0.000001000": "0.000001", "1.0": "1", "1e23": "1e+23", "-0.0000033333333333333333": "-0.0000033333333333333333", "1424953923781206.25": "1424953923781206.2"} {
		f, err := NombreDouble(in)
		if err != nil || NombreES6(f) != out {
			t.Errorf("%s → %s (%v), attendu %s", in, NombreES6(f), err, out)
		}
	}
}

func TestRFC8785NonFinisRefuses(t *testing.T) {
	for _, in := range []string{`NaN`, `Infinity`, `-Infinity`, `{"a":NaN}`, `{"a":Infinity}`, `{"a":1e400}`, `[-1e309]`} {
		if c, err := CanoniqueIntegralTexte([]byte(in)); err == nil {
			t.Errorf("%s accepté : %s", in, c)
		}
	}
	// un dénormalisé trop petit s'arrondit à 0 (valeur IEEE la plus proche)
	if c, err := CanoniqueIntegralTexte([]byte(`[1e-400,-1e-400,2e-324]`)); err != nil || string(c) != `[0,0,0]` {
		t.Errorf("sous-dépassement : %s %v", c, err)
	}
}

// RFC 8785 §3.2.2 (entrée), §3.2.3 (sortie), §3.2.4 (octets UTF-8).
func TestRFC8785ExempleSection3(t *testing.T) {
	entree := `{
       "numbers": [333333333.33333329, 1E30, 4.50,
                   2e-3, 0.000000000000000000000000001],
       "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
       "literals": [null, true, false]
     }`
	c, err := CanoniqueIntegralTexte([]byte(entree))
	if err != nil {
		t.Fatal(err)
	}
	attendu := `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`
	if string(c) != attendu {
		t.Errorf("obtenu  %s\nattendu %s", c, attendu)
	}
	hexa := `7b 22 6c 69 74 65 72 61 6c 73 22 3a 5b 6e 75 6c 6c 2c 74 72
     75 65 2c 66 61 6c 73 65 5d 2c 22 6e 75 6d 62 65 72 73 22 3a
     5b 33 33 33 33 33 33 33 33 33 2e 33 33 33 33 33 33 33 2c 31
     65 2b 33 30 2c 34 2e 35 2c 30 2e 30 30 32 2c 31 65 2d 32 37
     5d 2c 22 73 74 72 69 6e 67 22 3a 22 e2 82 ac 24 5c 75 30 30
     30 66 5c 6e 41 27 42 5c 22 5c 5c 5c 5c 5c 22 2f 22 7d`
	octets, err := hex.DecodeString(strings.Join(strings.Fields(hexa), ""))
	if err != nil {
		t.Fatal(err)
	}
	if string(c) != string(octets) {
		t.Errorf("octets UTF-8 de §3.2.4 : %x", c)
	}
}

// RFC 8785 §3.2.3 : ordre des membres par unités de code UTF-16.
func TestRFC8785Tri(t *testing.T) {
	entree := `{
       "\u20ac": "Euro Sign",
       "\r": "Carriage Return",
       "\ufb33": "Hebrew Letter Dalet With Dagesh",
       "1": "One",
       "\ud83d\ude00": "Emoji: Grinning Face",
       "\u0080": "Control",
       "\u00f6": "Latin Small Letter O With Diaeresis"
     }`
	v, err := ParseJSON([]byte(entree))
	if err != nil {
		t.Fatal(err)
	}
	c, _ := CanoniqueIntegral(v)
	w, _ := ParseJSON(c)
	var ordre []string
	for _, m := range w.Obj {
		ordre = append(ordre, m.Val.Str)
	}
	attendu := []string{"Carriage Return", "One", "Control", "Latin Small Letter O With Diaeresis", "Euro Sign", "Emoji: Grinning Face", "Hebrew Letter Dalet With Dagesh"}
	if strings.Join(ordre, "|") != strings.Join(attendu, "|") {
		t.Errorf("ordre : %v", ordre)
	}
}

// RFC 8785 annexe E : premier résultat (analyse JSON ordinaire).
func TestRFC8785AnnexeE(t *testing.T) {
	c, err := CanoniqueIntegralTexte([]byte(`{
       "time": "2019-01-28T07:45:10Z",
       "big": "055",
       "val": 3.5
     }`))
	if err != nil || string(c) != `{"big":"055","time":"2019-01-28T07:45:10Z","val":3.5}` {
		t.Errorf("%s %v", c, err)
	}
}

// CT-2 annexe B.2 : cas limites de CT-1 §4 qui restent valides en JCS
// intégral, cas invalides, contrôles échappés en minuscules.
func TestCasObligatoiresB2(t *testing.T) {
	valides := map[string]string{
		`{"a":1.0}`:               `{"a":1}`,
		`{"a":1e3}`:               `{"a":1000}`,
		`{"a":9007199254740993}`:  `{"a":9007199254740992}`,
		`{"b":1,"a":2}`:           `{"a":2,"b":1}`,
		`"\u001F\u0000"`:          `"\u001f\u0000"`,
		`"\u2028<>&"`:             "\"\u2028<>&\"",
		`{"a":-0.0}`:              `{"a":0}`,
		`[1.50, 1E+2, 0.0000001]`: `[1.5,100,1e-7]`,
	}
	for in, out := range valides {
		c, err := CanoniqueIntegralTexte([]byte(in))
		if err != nil || string(c) != out {
			t.Errorf("%s → %s (%v), attendu %s", in, c, err, out)
		}
	}
	for _, in := range []string{`{"a":1,"a":2}`, `{"a":"\ud800"}`, `{"a":"\udc00"}`, "\xef\xbb\xbf{}"} {
		if c, err := CanoniqueIntegralTexte([]byte(in)); err == nil {
			t.Errorf("%q accepté : %s", in, c)
		}
	}
}
