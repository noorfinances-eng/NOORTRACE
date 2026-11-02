package registre

// Entrées hostiles (EX-15.1, EX-15.2) : JSON tronqué ou trop profond,
// longueurs absurdes, bornes de §15.1 dépassées, octets quelconques. Aucune
// ne doit provoquer de panique ; chacune met en échec la vérification qui
// porte la partie (R-1, R-3 ou R-5).

import (
	"fmt"
	"strings"
	"testing"

	"github.com/noorfinances-eng/noortrace/verificateur/commun"
)

func etatDe(r Resultat, id string) commun.Verification {
	for _, v := range r.Verifications {
		if v.ID == id {
			return v
		}
	}
	return commun.Verification{}
}

func TestEntreesHostiles(t *testing.T) {
	profond := strings.Repeat("[", 200) + strings.Repeat("]", 200)
	cas := []struct {
		nom    string
		partie string // registre, certificat, validateurs
		octets func(base []byte) []byte
		id     string
	}{
		{"registre vide", "registre", func([]byte) []byte { return nil }, "R-1"},
		{"registre octets quelconques", "registre", func([]byte) []byte { return []byte{0xff, 0xfe, 0x00, 0x7b} }, "R-1"},
		{"registre tronqué", "registre", func(b []byte) []byte { return b[:len(b)-1] }, "R-1"},
		{"registre profondeur 200", "registre", func([]byte) []byte { return []byte(`{"version":0,"source":"x","entries":` + profond + `}`) }, "R-1"},
		{"registre littéral null", "registre", func([]byte) []byte { return []byte("null") }, "R-1"},
		{"registre tableau", "registre", func([]byte) []byte { return []byte("[]") }, "R-1"},
		{"registre membre inconnu", "registre", func(b []byte) []byte { return []byte(`{"x":1,` + string(b[1:])) }, "R-1"},
		{"registre version 1", "registre", func(b []byte) []byte { return []byte(strings.Replace(string(b), `"version":0`, `"version":1`, 1)) }, "R-1"},
		{"registre 18 entrées", "registre", func(b []byte) []byte {
			s := string(b)
			i := strings.Index(s, `"entries":[`) + len(`"entries":[`)
			j := strings.Index(s[i:], `,{"block"`)
			if j < 0 {
				return nil
			}
			e := s[i : i+j]
			return []byte(s[:i] + strings.Repeat(e+",", 13) + s[i:])
		}, "R-1"},
		{"transaction_index absurde", "registre", func(b []byte) []byte {
			return []byte(strings.Replace(string(b), `"transaction_index":0`, `"transaction_index":1e400`, 1))
		}, "R-1"},
		{"transaction_index négatif", "registre", func(b []byte) []byte {
			return []byte(strings.Replace(string(b), `"transaction_index":0`, `"transaction_index":-1`, 1))
		}, "R-1"},
		{"quantité de 17 chiffres", "registre", func(b []byte) []byte {
			return []byte(strings.Replace(string(b), `"gasLimit":"0x1c9c380"`, `"gasLimit":"0x10000000000000000"`, 1))
		}, "R-1"},
		{"quantité à zéro de tête", "registre", func(b []byte) []byte {
			return []byte(strings.Replace(string(b), `"gasLimit":"0x1c9c380"`, `"gasLimit":"0x01c9c380"`, 1))
		}, "R-1"},
		{"données d'un journal hors borne", "registre", func(b []byte) []byte {
			return []byte(strings.Replace(string(b), `"data":"0x`, `"data":"0x`+strings.Repeat("00", 131073), 1))
		}, "R-1"},
		{"cinq sujets", "registre", func(b []byte) []byte {
			s := string(b)
			z := `"0x` + strings.Repeat("0", 64) + `"`
			return []byte(strings.Replace(s, `"topics":[`, `"topics":[`+z+`,`+z+`,`+z+`,`+z+`,`+z+`,`, 1))
		}, "R-1"},
		{"hachage en majuscules", "registre", func(b []byte) []byte {
			s := string(b)
			i := strings.Index(s, `"hash":"0x`) + len(`"hash":"0x`)
			return []byte(s[:i] + strings.ToUpper(s[i:i+64]) + s[i+64:])
		}, "R-1"},
		{"certificat vide", "certificat", func([]byte) []byte { return []byte(`{}`) }, "R-1"},
		{"certificat profondeur 200", "certificat", func([]byte) []byte { return []byte(`{"version":0,"certificates":` + profond + `}`) }, "R-1"},
		{"17 certificats", "certificat", func(b []byte) []byte {
			s := string(b)
			i := strings.Index(s, `"certificates":[`) + len(`"certificates":[`)
			fin := strings.LastIndex(s, "]")
			un := s[i:fin]
			return []byte(s[:i] + strings.Repeat(un+",", 4) + un + s[fin:])
		}, "R-1"},
		{"129 precommits", "certificat", func(b []byte) []byte {
			s := string(b)
			i := strings.Index(s, `"precommits":[`) + len(`"precommits":[`)
			j := strings.Index(s[i:], `}`) + 1
			p := s[i : i+j]
			return []byte(s[:i] + strings.Repeat(p+",", 129) + s[i:])
		}, "R-1"},
		{"ligne de plus de 4 Mio", "certificat", func(b []byte) []byte {
			s := string(b)
			i := strings.Index(s, `"line":"`) + len(`"line":"`)
			return []byte(s[:i] + strings.Repeat(" ", longueurLigneMax) + s[i:])
		}, "R-1"},
		{"hauteur de certificat négative", "certificat", func(b []byte) []byte {
			return []byte(strings.Replace(string(b), `"height":"0x64"`, `"height":"-0x64"`, 1))
		}, "R-1"},
		{"validateurs profondeur 200", "validateurs", func([]byte) []byte { return []byte(`{"version":0,"sets":` + profond + `}`) }, "R-3"},
		{"validateurs clé hors courbe", "validateurs", func([]byte) []byte {
			return []byte(`{"version":0,"sets":[{"from_height":1,"to_height":null,"validators":[{"id":"v1","pubKeyHex":"0x02` + strings.Repeat("ff", 32) + `"}],"source":"x"}]}`)
		}, "R-3"},
		{"validateurs octets quelconques", "validateurs", func([]byte) []byte { return []byte("\x00\x01") }, "R-3"},
		{"validateurs 17 jeux", "validateurs", func(b []byte) []byte {
			s := string(b)
			i := strings.Index(s, `"sets":[`) + len(`"sets":[`)
			fin := strings.LastIndex(s, "]")
			un := s[i:fin]
			return []byte(s[:i] + strings.Repeat(un+",", 16) + un + s[fin:])
		}, "R-3"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			m := nouveauMonde()
			e := m.entree()
			var p *Partie
			switch c.partie {
			case "registre":
				p = &e.Registre
			case "certificat":
				p = &e.Certificat
			default:
				p = &e.Validateurs
			}
			p.Octets = c.octets(p.Octets)
			var r Resultat
			func() {
				defer func() {
					if x := recover(); x != nil {
						t.Fatalf("panique : %v", x)
					}
				}()
				r = Verifier(e)
			}()
			if v := etatDe(r, c.id); v.Statut != commun.Echoue {
				t.Errorf("%s : %s %s (%s)", c.id, v.Statut, v.Raison, v.Detail.Fr)
			}
			if r.Statut != commun.Echoue {
				t.Errorf("contrôle 8 : %s", r.Statut)
			}
			if c.id == "R-1" {
				for _, v := range r.Verifications[1:] {
					if v.Statut != commun.NonExecute || v.Raison != commun.PrerequisEnEchec {
						t.Errorf("%s : %s %s", v.ID, v.Statut, v.Raison)
					}
				}
			}
		})
	}
}

// TestCleEnDouble : un nom en double dans registre.json est lu comme
// JSON.parse le lit (dernière occurrence) ; CT-6 ne le refuse pas (voir
// LISEZMOI.md, « Lectures »).
func TestCleEnDouble(t *testing.T) {
	m := nouveauMonde()
	e := m.entree()
	e.Registre.Octets = []byte(`{"version":1,` + string(e.Registre.Octets[1:]))
	if r := Verifier(e); r.Statut != commun.Reussi {
		t.Errorf("contrôle 8 : %s (%s)", r.Statut, etatDe(r, "R-1").Detail.Fr)
	}
}

// TestLignesHostiles : lignes que le décodeur du nœud refuse ou accepte
// sous une forme inattendue ; aucune panique, R-5 en échec.
func TestLignesHostiles(t *testing.T) {
	lignes := []string{
		"", "null", "[]", `"x"`, "{", `{"height":-1}`, `{"height":1.5}`, `{"height":1e3}`, `{"height":"1"}`,
		`{"valsetHash":"%%%"}`, `{"sig":"` + strings.Repeat("A", 1<<16) + `"}`, `{"body":` + strings.Repeat(`{"a":`, 5000) + `1` + strings.Repeat(`}`, 5000) + `}`,
		"\xff\xfe", `{"domain":"noor/v1/bft","type":"CONS_PRECOMMIT","body":null}`,
	}
	m := nouveauMonde()
	e := m.entree()
	certs, d := lireCertificats(e.Certificat.Octets)
	if d != nil {
		t.Fatal(d.Fr)
	}
	jeu := m.jeu()
	for i, l := range lignes {
		c := certs[0]
		c.precommits = []string{l, c.precommits[1], c.precommits[2]}
		r := verifierCertificat(&c, &jeu)
		if r.valide {
			t.Errorf("ligne %d acceptée", i)
		}
		if !strings.Contains(r.detail.Fr, fmt.Sprintf("bloc %d", c.hauteur)) {
			t.Errorf("détail %s", r.detail.Fr)
		}
	}
}
