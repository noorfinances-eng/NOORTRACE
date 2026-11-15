package ancres

// Essai de la revue de sécurité interne de l'étape 8 : une CRL
// du fichier d'ancres dont un numéro de série est encodé sous forme non
// minimale (02 02 00 02) ne rend plus le fichier d'ancres inutilisable
// (EX-9.6 : la forme minimale des INTEGER n'est pas contrôlée) ; le lecteur
// du profil de §9.3 (paquet horodatage) la juge en production, et
// horodatage/revue_test.go montre que T-10 voit alors la révocation.

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestCRLNumeroNonMinimalGardee(t *testing.T) {
	crl, err := os.ReadFile("testdata/crl-serie-non-minimale.pem")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(repAncres + "/ancres-test.json")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	v["revocation"].(map[string]any)["crls"] = []any{string(crl)}
	octets, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	a, d := AnalyserAncres(octets, nil)
	if d != nil {
		t.Fatalf("fichier d'ancres refusé : %s", d.Message.Fr)
	}
	if len(a.CRLs) != 1 || a.CRLs[0].Pointeur != "/revocation/crls/0" {
		t.Fatalf("CRL non gardée : %+v", a.CRLs)
	}
	// Le même fichier avec une CRL qui n'est pas du PEM reste refusé.
	v["revocation"].(map[string]any)["crls"] = []any{strings.Replace(string(crl), "X509 CRL", "CERTIFICATE", 2)}
	octets, _ = json.Marshal(v)
	if _, d := AnalyserAncres(octets, nil); d == nil {
		t.Fatal("PEM d'un autre type accepté")
	}
}
