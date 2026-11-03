package jsonv

import "testing"

// FuzzAnalyser : le lecteur JSON ne panique sur aucune entrée et refuse ou
// lit toute entrée en temps borné (CT-6 EX-15.2, EX-15.3).
func FuzzAnalyser(f *testing.F) {
	for _, s := range []string{`{}`, `{"a":[1,2,{"b":null}]}`, `"\ud800"`, `{"a":1,"a":2}`, `[1.5e300,-0]`, "\xEF\xBB\xBF{}", "\"\xed\xa0\x80\"", "\"\xed\xa0\xbd\xed\xb8\x80\"", "[[[[1]]]]"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		v, err := Analyser(b)
		if err == nil && v == nil {
			t.Fatal("valeur nulle sans erreur")
		}
	})
}
