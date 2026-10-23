package main

import "testing"

// Cas limites de CT-1 §4 (JCS v0).
func TestJCSv0CasLimites(t *testing.T) {
	cas := []struct{ entree, attendu string }{
		{`{"b":1,"a":2}`, `{"a":2,"b":1}`},
		{`{"é":1,"z":2,"Z":3}`, `{"Z":3,"z":2,"é":1}`},
		{`{"a😀":1}`, `{"a😀":1}`},
		{`{"a":"x\u0001y"}`, `{"a":"x\u0001y"}`},
		{"{\"a\":\"\\u007f\"}", "{\"a\":\"\x7f\"}"},
		{`{"a":"/"}`, `{"a":"/"}`},
		{`{"a":1.0}`, ""},
		{`{"a":1e3}`, ""},
		{`{"a":9007199254740993}`, ""},
		{`{"a":-0}`, `{"a":0}`},
		{`{"a":[]}`, `{"a":[]}`},
		{`{"a":{}}`, `{"a":{}}`},
		{`{"a":"\ud800"}`, ""},
	}
	for _, c := range cas {
		v, err := ParseJSON([]byte(c.entree))
		if err != nil {
			t.Fatalf("%s : %v", c.entree, err)
		}
		got, err := Canonique(v)
		if c.attendu == "" {
			if err == nil {
				t.Errorf("%s : refus attendu, obtenu %s", c.entree, got)
			}
			continue
		}
		if err != nil || string(got) != c.attendu {
			t.Errorf("%s : %s (%v), attendu %s", c.entree, got, err, c.attendu)
		}
	}
	if _, err := ParseJSON([]byte(`{"a":1,"a":2}`)); err == nil {
		t.Error("clé en double acceptée")
	}
}

// Table de CT-2 EX-8.1 (JCS intégral).
func TestJCSIntegral(t *testing.T) {
	cas := map[string]string{
		"1": "1", "1.0": "1", "1.50": "1.5", "1e3": "1000", "1E+2": "100", "1e21": "1e+21",
		"1e20": "100000000000000000000", "-0": "0", "-0.0": "0", "0.000001": "0.000001",
		"0.0000001": "1e-7", "5e-324": "5e-324", "9007199254740993": "9007199254740992",
		"123456789012345678901234567890":   "1.2345678901234568e+29",
		"3.141592653589793238462643383279": "3.141592653589793",
	}
	for e, a := range cas {
		v, err := ParseJSON([]byte(e))
		if err != nil {
			t.Fatal(err)
		}
		got, err := CanoniqueIntegral(v)
		if err != nil || string(got) != a {
			t.Errorf("%s : %s (%v), attendu %s", e, got, err, a)
		}
	}
}

// JSON.stringify(v, null, 2) : indentation, conteneurs vides, substitut
// isolé.
func TestStringify2(t *testing.T) {
	v, err := ParseJSON([]byte(`{"a":[],"b":{},"c":[1,"\ud800x",true,null],"d":{"e":1.50}}`))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := Stringify2(v)
	att := "{\n  \"a\": [],\n  \"b\": {},\n  \"c\": [\n    1,\n    \"\\ud800x\",\n    true,\n    null\n  ],\n  \"d\": {\n    \"e\": 1.5\n  }\n}"
	if got != att {
		t.Errorf("obtenu\n%s\nattendu\n%s", got, att)
	}
}

// Horodatages de CT-1 §3 : dates inexistantes refusées, jamais décalées.
func TestHorodatages(t *testing.T) {
	for _, s := range []string{"2026-02-30T00:00:00.000Z", "2026-04-31T00:00:00.000Z", "2026-02-29T00:00:00.000Z", "2026-11-05T10:00:00Z", "2026-11-05T10:00:00.000+01:00"} {
		if _, err := LireInstant(s); err == nil {
			t.Errorf("%s accepté", s)
		}
	}
	i, err := LireInstant("2028-02-29T23:59:59.999Z")
	if err != nil || i.String() != "2028-02-29T23:59:59.999Z" {
		t.Errorf("29 février bissextile : %v %v", i, err)
	}
}
