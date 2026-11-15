package ancres

// Essais de la revue de sécurité interne de l'étape 8, suite de
// branches de rejet de N-1 (EX-12.2) que la grille du relecteur
// nommait sans essai Go : fichier de plus de 16 Mio, noms d'autorités en
// double, intermédiaire illisible, dates de la qualification, déclarations de
// non-révocation (revocation.statements, chemin jamais exécuté), jeux de
// validateurs (from_height > to_height, clé inexploitable, clé en double,
// recouvrement des jeux).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ancresDecodees relit un fichier d'ancres publié comme un objet décodé.
func ancresDecodees(t *testing.T, nom string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repAncres, nom))
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func octetsDe(t *testing.T, v map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func autorite(v map[string]any) map[string]any {
	return v["tsa_authorities"].([]any)[0].(map[string]any)
}
func jeux(v map[string]any) []any { return v["registry"].(map[string]any)["validator_sets"].([]any) }
func validateurs(v map[string]any, i int) []any {
	return jeux(v)[i].(map[string]any)["validators"].([]any)
}

// TestN1Branches : CT-6 N-1. Chaque branche de refus de N-1 rend le fichier
// d'ancres inutilisable (ancres_inutilisables, N-1) avec le motif attendu.
func TestN1Branches(t *testing.T) {
	cas := []struct {
		nom    string
		base   string
		muter  func(v map[string]any)
		detail string
	}{
		{"noms d'autorités en double", "ancres-test.json", func(v map[string]any) {
			v["tsa_authorities"] = []any{autorite(v), autorite(v)}
		}, "deux autorités portent le nom « AC de test CT-6 »"},
		{"intermédiaire illisible", "ancres-test.json", func(v map[string]any) {
			autorite(v)["intermediates"] = []any{"-----BEGIN CERTIFICATE-----\nMIIBAAAA\n-----END CERTIFICATE-----\n"}
		}, "/tsa_authorities/0/intermediates/0"},
		{"qualified.valid_from inexistante", "ancres-test.json", func(v map[string]any) {
			autorite(v)["qualified"] = map[string]any{"framework": "eidas", "valid_from": "2026-02-30T00:00:00.000Z", "valid_to": nil, "source": "essai"}
		}, "/tsa_authorities/0/qualified/valid_from n'est pas une date existante"},
		{"qualified.valid_to inexistante", "ancres-test.json", func(v map[string]any) {
			autorite(v)["qualified"] = map[string]any{"framework": "eidas", "valid_from": "2026-01-01T00:00:00.000Z", "valid_to": "2026-02-30T00:00:00.000Z", "source": "essai"}
		}, "/tsa_authorities/0/qualified/valid_to n'est pas une date existante"},
		{"qualified : valid_from suit valid_to", "ancres-test.json", func(v map[string]any) {
			autorite(v)["qualified"] = map[string]any{"framework": "eidas", "valid_from": "2026-03-01T00:00:00.000Z", "valid_to": "2026-02-01T00:00:00.000Z", "source": "essai"}
		}, "/tsa_authorities/0/qualified : valid_from suit valid_to"},
		{"statements : not_revoked_at inexistante", "ancres-test.json", func(v map[string]any) {
			v["revocation"].(map[string]any)["statements"] = []any{map[string]any{"certificate_sha256": "0x" + strings.Repeat("ab", 32), "not_revoked_at": "2026-02-30T00:00:00.000Z", "method": "ocsp", "source": "essai"}}
		}, "/revocation/statements/0/not_revoked_at n'est pas une date existante"},
		{"jeu : from_height supérieur à to_height", "ancres-test.json", func(v map[string]any) {
			j := jeux(v)[0].(map[string]any)
			j["from_height"], j["to_height"] = 10, 5
		}, "/registry/validator_sets/0 : from_height supérieur à to_height"},
		{"jeu : clé de validateur inexploitable", "ancres-test.json", func(v map[string]any) {
			validateurs(v, 0)[0].(map[string]any)["pubKeyHex"] = "0x04" + strings.Repeat("00", 64)
		}, "/registry/validator_sets/0 : clé du validateur v1 inexploitable"},
		{"jeu : deux validateurs portent la même clé", "ancres-test.json", func(v map[string]any) {
			validateurs(v, 0)[1].(map[string]any)["pubKeyHex"] = validateurs(v, 0)[0].(map[string]any)["pubKeyHex"]
		}, "/registry/validator_sets/0 : deux validateurs portent la même clé"},
		{"jeux qui se recouvrent", "ancres-deux-jeux.json", func(v map[string]any) {
			j := jeux(v)[1].(map[string]any)
			j["from_height"], j["to_height"] = 16660, 20000
		}, "les jeux /registry/validator_sets/0 et /registry/validator_sets/1 se recouvrent"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			v := ancresDecodees(t, c.base)
			c.muter(v)
			a, d := AnalyserAncres(octetsDe(t, v), nil)
			if a != nil || d == nil {
				t.Fatalf("accepté")
			}
			if d.Genre != "ancres_inutilisables" || d.Verification != "N-1" || !strings.Contains(d.Message.Fr, c.detail) {
				t.Errorf("%s %s : %s, attendu « %s »", d.Genre, d.Verification, d.Message.Fr, c.detail)
			}
		})
	}
	t.Run("plus de 16 Mio", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "ancres.json")
		if err := os.WriteFile(f, make([]byte, 16<<20+1), 0o644); err != nil {
			t.Fatal(err)
		}
		_, d := Lire(f, nil)
		if d == nil || d.Genre != "ancres_inutilisables" || d.Verification != "N-1" || !strings.Contains(d.Message.Fr, "plus de 16 Mio") {
			t.Fatalf("fichier de 16 Mio + 1 : %+v", d)
		}
	})
}

// TestN1CleDeValidateurSansPrefixe : CT-6 N-1. Une clé de validateur de 64
// octets (forme non compressée sans le préfixe 04, admise par le schéma) est
// chargée comme la clé de 65 octets qui lui correspond.
func TestN1CleDeValidateurSansPrefixe(t *testing.T) {
	v := ancresDecodees(t, "ancres-test.json")
	val := validateurs(v, 0)[0].(map[string]any)
	avec := val["pubKeyHex"].(string)
	if !strings.HasPrefix(avec, "0x04") || len(avec) != 132 {
		t.Fatalf("clé de v1 : %s", avec)
	}
	val["pubKeyHex"] = "0x" + avec[4:]
	a, d := AnalyserAncres(octetsDe(t, v), nil)
	if d != nil {
		t.Fatalf("refusé : %s", d.Message.Fr)
	}
	j := a.Registre.Jeux[0].Validateurs[0]
	if j.ID != "v1" || j.CleHex != "0x"+avec[4:] || len(j.Cle) != 64 {
		t.Errorf("validateur chargé : %+v", j)
	}
	// La même clé que v1 sous sa forme de 65 octets : deux validateurs
	// portent la même clé.
	validateurs(v, 0)[1].(map[string]any)["pubKeyHex"] = avec
	if _, d := AnalyserAncres(octetsDe(t, v), nil); d == nil || !strings.Contains(d.Message.Fr, "deux validateurs portent la même clé") {
		t.Errorf("formes de 64 et 65 octets de la même clé non confondues : %v", d)
	}
}

// TestN1DeclarationsDeNonRevocation : CT-6 N-1. revocation.statements est lu
// (chemin jamais exécuté par la suite) : une déclaration conforme est gardée
// avec son instant, sa méthode, sa source et l'empreinte du certificat visé.
func TestN1DeclarationsDeNonRevocation(t *testing.T) {
	v := ancresDecodees(t, "ancres-test.json")
	v["revocation"].(map[string]any)["statements"] = []any{map[string]any{"certificate_sha256": "0x" + strings.Repeat("ab", 32), "not_revoked_at": "2026-11-10T08:00:00.000Z", "method": "ocsp", "source": "déclaration d'essai"}}
	a, d := AnalyserAncres(octetsDe(t, v), nil)
	if d != nil {
		t.Fatalf("refusé : %s", d.Message.Fr)
	}
	if len(a.Declarations) != 1 {
		t.Fatalf("%d déclaration(s)", len(a.Declarations))
	}
	dcl := a.Declarations[0]
	attendu := time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC)
	if dcl.Pointeur != "/revocation/statements/0" || !dcl.NonRevoqueA.Equal(attendu) || dcl.Methode != "ocsp" || dcl.Source != "déclaration d'essai" {
		t.Errorf("déclaration lue : %+v", dcl)
	}
	for _, b := range dcl.CertificatSha256 {
		if b != 0xab {
			t.Fatalf("empreinte du certificat visé : %x", dcl.CertificatSha256)
		}
	}
}
