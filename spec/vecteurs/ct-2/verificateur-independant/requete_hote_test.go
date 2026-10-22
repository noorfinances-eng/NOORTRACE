package main

import "testing"

// EX-4.44 : valeur décimale du littéral = valeur de sa forme JCS intégral.
func TestNombreExact(t *testing.T) {
	for _, l := range []string{"0", "-0", "0.75", "1.0", "1e3", "1E+2", "-12.50", "9007199254740992", "0.1", "5e-324", "1.7976931348623157e308"} {
		if !NombreExact(l) {
			t.Errorf("%s : exact attendu", l)
		}
	}
	for _, l := range []string{"12345678901234567890", "9007199254740993", "0.10000000000000000001", "1e400", "1e-400", "3.141592653589793238"} {
		if NombreExact(l) {
			t.Errorf("%s : non exact attendu", l)
		}
	}
}

// 4.4 pas 1, EX-4.3, EX-4.43, EX-4.44.
func TestLireRequeteHote(t *testing.T) {
	ligne := func(args, id string) []byte {
		return []byte(`{"jsonrpc":"2.0","id":` + id + `,"method":"tools/call","params":{"name":"demo__x","arguments":` + args + `}}`)
	}
	cas := []struct {
		texte   []byte
		cadrage string
		attendu string // JCS de l'erreur, ou "" si admise
		id      string
	}{
		{ligne(`{"n":12345678901234567890}`, `"h"`), "ligne", `{"code":-32602,"data":{"reason":"nombre_non_representable"},"message":"Invalid params"}`, `"h"`},
		{ligne(`{"n":1e400}`, `"h"`), "ligne", `{"code":-32602,"data":{"reason":"arguments_non_canonisables"},"message":"Invalid params"}`, "null"},
		{ligne(`{"a":1}`+"\r", `"h"`), "ligne", `{"code":-32700,"data":{"reason":"cr_dans_la_ligne"},"message":"Parse error"}`, "null"},
		{ligne(`{"a":1}`+"\r\n", `"h"`), "corps", "", `"h"`},
		{[]byte("[" + string(ligne("{}", "1")) + "]"), "ligne", `{"code":-32600,"data":{"reason":"lot_non_pris_en_charge"},"message":"Invalid Request"}`, "null"},
		{[]byte(`{"jsonrpc":"1.0","id":1,"method":"x"}`), "ligne", `{"code":-32600,"message":"Invalid Request"}`, "null"},
		{[]byte(`{pas du json`), "ligne", `{"code":-32700,"message":"Parse error"}`, "null"},
		{ligne(`{"n":1.0,"m":1e3}`, `12345678901234567890`), "ligne", "", `12345678901234567890`},
	}
	for i, c := range cas {
		lu := LireRequeteHote(c.texte, c.cadrage)
		obt := ""
		if lu.Erreur != nil {
			obt = doitIntegral(lu.Erreur)
		}
		if obt != c.attendu || lu.IDTexte != c.id {
			t.Errorf("cas %d : erreur %s id %s ; attendu %s id %s", i, obt, lu.IDTexte, c.attendu, c.id)
		}
	}
	if got := string(SansBlancs([]byte(" {\t\"a\" : [ 1.0 , \"x y\\n\" ] ,\r\n \"b\":{ } } "))); got != `{"a":[1.0,"x y\n"],"b":{}}` {
		t.Errorf("SansBlancs : %s", got)
	}
}
