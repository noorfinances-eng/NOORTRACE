package main

import (
	"strings"
	"testing"
)

// Exemples de la RFC 8785 (§3.2.2 et §3.2.3), réduits à ce que la restriction
// v0 admet : les nombres non entiers de l'exemple sont testés comme refusés.
func TestRFC8785Chaines(t *testing.T) {
	entree := "{\"string\": \"\\u20ac$\\u000F\\u000aA'\\u0042\\u0022\\u005c\\\\\\\"\\/\", \"literals\": [null, true, false]}"
	attendu := "{\"literals\":[null,true,false],\"string\":\"\u20ac$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}"
	got, err := CanoniqueTexte([]byte(entree))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != attendu {
		t.Fatalf("obtenu %s\nattendu %s", got, attendu)
	}
}

func TestRFC8785NombresRefuses(t *testing.T) {
	entree := `{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001]}`
	if _, err := CanoniqueTexte([]byte(entree)); err == nil {
		t.Fatal("les nombres non entiers de l'exemple RFC 8785 doivent être refusés en v0")
	}
	for _, s := range []string{`[1E30]`, `[4.50]`, `[2e-3]`, `[1.0]`, `[9007199254740992]`, `[-9007199254740992]`} {
		if _, err := CanoniqueTexte([]byte(s)); err == nil {
			t.Errorf("%s devrait être refusé", s)
		}
	}
	for _, s := range []string{`[9007199254740991]`, `[-9007199254740991]`, `[0]`, `[-0]`} {
		if _, err := CanoniqueTexte([]byte(s)); err != nil {
			t.Errorf("%s : %v", s, err)
		}
	}
}

// Jeu de test du tri de la RFC 8785 §3.2.3 : l'émoji (substituts UTF-16
// 0xD83D 0xDE00) précède U+FB33, ce qu'un tri par points de code ne donne pas.
func TestRFC8785TriUTF16(t *testing.T) {
	entree := "{\n" +
		"  \"\\u20ac\": \"Euro Sign\",\n" +
		"  \"\\r\": \"Carriage Return\",\n" +
		"  \"\\ufb33\": \"Hebrew Letter Dalet With Dagesh\",\n" +
		"  \"1\": \"One\",\n" +
		"  \"\\ud83d\\ude00\": \"Emoji: Grinning Face\",\n" +
		"  \"\\u0080\": \"Control\",\n" +
		"  \"\\u00f6\": \"Latin Small Letter O With Diaeresis\"\n" +
		"}"
	got, err := CanoniqueTexte([]byte(entree))
	if err != nil {
		t.Fatal(err)
	}
	attendu := "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\"," +
		"\"\u00f6\":\"Latin Small Letter O With Diaeresis\",\"\u20ac\":\"Euro Sign\"," +
		"\"\U0001F600\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}"
	if string(got) != attendu {
		t.Fatalf("obtenu %q\nattendu %q", got, attendu)
	}
}

// Les quatorze cas limites de la table de CT-1 §4, plus quelques cas propres
// à l'implémentation (U+2028/2029 et <>& en clair, UTF-8 mal formé, BOM).
func TestCasLimitesCT1(t *testing.T) {
	cas := []struct {
		entree, attendu string
		invalide        bool
	}{
		{`{"b":1,"a":2}`, `{"a":2,"b":1}`, false},
		{"{\"\u00e9\":1,\"z\":2,\"Z\":3}", "{\"Z\":3,\"z\":2,\"\u00e9\":1}", false},
		{"{\"\\u00e9\":1}", "{\"\u00e9\":1}", false},
		{"{\"a\\ud83d\\ude00\":1}", "{\"a\U0001F600\":1}", false},
		{"{\"a\":\"x\\u0001y\"}", "{\"a\":\"x\\u0001y\"}", false},
		{"{\"a\":\"\\u001F\"}", "{\"a\":\"\\u001f\"}", false},
		{"{\"a\":\"\\u007f\"}", "{\"a\":\"\u007f\"}", false},
		{"{\"a\":\"\\/\"}", "{\"a\":\"/\"}", false},
		{`{"a":1.0}`, "", true},
		{`{"a":1e3}`, "", true},
		{`{"a":9007199254740993}`, "", true},
		{`{"a":9007199254740991}`, `{"a":9007199254740991}`, false},
		{`{"a":-0}`, `{"a":0}`, false},
		{`{"a":[],"b":{}}`, `{"a":[],"b":{}}`, false},
		{"{\"a\":\"\\ud800\"}", "", true},
		{"{\"a\":\"\\udc00\"}", "", true},
		{"{\"a\":\"\\ud800x\"}", "", true},
		{`{"a":1,"a":2}`, "", true},
		{"{\"a\":\"\\u2028\\u2029<>&\"}", "{\"a\":\"\u2028\u2029<>&\"}", false},
		{"{\"a\":\"\xff\"}", "", true},
		{"\xef\xbb\xbf{}", "", true},
		{"{\"a\":\"\\b\\t\\n\\f\\r\"}", "{\"a\":\"\\b\\t\\n\\f\\r\"}", false},
		{"{\"\":0,\"a\":1,\"aa\":2,\"ab\":3}", "{\"\":0,\"a\":1,\"aa\":2,\"ab\":3}", false},
	}
	for _, c := range cas {
		got, err := CanoniqueTexte([]byte(c.entree))
		if c.invalide {
			if err == nil {
				t.Errorf("%s : attendu invalide, obtenu %s", c.entree, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s : %v", c.entree, err)
			continue
		}
		if string(got) != c.attendu {
			t.Errorf("%s : obtenu %s, attendu %s", c.entree, got, c.attendu)
		}
	}
}

func TestComparerUTF16(t *testing.T) {
	ordre := []string{"", "a", "aa", "ab", "\u00e9", "\u20ac", "\U0001F600", "\ufb33"}
	for i := 0; i+1 < len(ordre); i++ {
		if ComparerUTF16(ordre[i], ordre[i+1]) >= 0 {
			t.Errorf("%q devrait précéder %q", ordre[i], ordre[i+1])
		}
	}
	if ComparerUTF16("a", "a") != 0 {
		t.Error("égalité")
	}
}

func TestParseJSONOrdreConserve(t *testing.T) {
	v, err := ParseJSON([]byte(`{"z":1,"a":[1,2,{"k":null}],"m":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(v.Keys(), ",") != "z,a,m" {
		t.Fatalf("ordre des clés non conservé : %v", v.Keys())
	}
	if v.Get("a").Arr[2].Get("k").Kind != KindNull {
		t.Fatal("accès imbriqué")
	}
	if v.Get("a").Arr[0].Num != "1" {
		t.Fatal("texte littéral du nombre")
	}
}

func TestParseJSONSyntaxe(t *testing.T) {
	for _, s := range []string{``, `{`, `{"a":}`, `[1,]`, `01`, `1.`, `"a`, "\"\x01\"", `{"a":1}x`, `tru`, `-`, `1e`, `{"a" 1}`, `{,}`, `[1 2]`, "\"\\x\"", "\"\\u12\""} {
		if _, err := ParseJSON([]byte(s)); err == nil {
			t.Errorf("%q devrait être refusé", s)
		}
	}
	// Une erreur de forme canonique est distinguée d'une erreur de syntaxe.
	_, err := ParseJSON([]byte(`{"a":1,"a":2}`))
	if e, ok := err.(*ErreurJSON); !ok || !e.Canonique {
		t.Errorf("clé en double : %v", err)
	}
	_, err = ParseJSON([]byte(`{"a":`))
	if e, ok := err.(*ErreurJSON); !ok || e.Canonique {
		t.Errorf("syntaxe : %v", err)
	}
}
