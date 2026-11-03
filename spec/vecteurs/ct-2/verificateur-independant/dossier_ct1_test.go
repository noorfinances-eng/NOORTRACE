package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Un dossier dont l'index est illisible (code 2, CT-1 §11.4 et §11.5
// révision 0.5) ne passe jamais pour valide dans la famille evenements :
// Resultats est vide, mais Illisible le signale.
func TestDossierCT1Illisible(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dossier.json"), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := VerifierDossier(dir)
	if res.Illisible == "" || res.TypeErreur != "dossier_illisible" || !res.Resultats.Valide() {
		t.Fatalf("index illisible : %q %q", res.Illisible, res.TypeErreur)
	}
	attenduValide, _ := ParseJSON([]byte(`{"valide":true,"controles_en_echec":[]}`))
	rap := &Rapport{}
	comparerDossierCT1(rap, "evenements", "d", attenduValide, res, true)
	if _, c, d, _ := rap.Comptes(); c != 0 || d != 1 {
		t.Errorf("attendu valide, index illisible : %d concordante(s), %d discordante(s)", c, d)
	}
	attenduCode2, _ := ParseJSON([]byte(`{"valide":null,"controle":null,"controles_en_echec":[],"exit_code":2,"error_kind":"dossier_illisible"}`))
	rap = &Rapport{}
	comparerDossierCT1(rap, "evenements", "d", attenduCode2, res, true)
	if _, c, d, _ := rap.Comptes(); c != 1 || d != 0 {
		t.Errorf("attendu code 2 : %d concordante(s), %d discordante(s)", c, d)
	}
	// Un dossier lisible n'est pas confondu avec une entrée inutilisable.
	rap = &Rapport{}
	comparerDossierCT1(rap, "evenements", "d", attenduCode2, &Dossier{Resultats: NouveauxResultats()}, true)
	if _, c, d, _ := rap.Comptes(); c != 0 || d != 1 {
		t.Errorf("attendu code 2, verdict rendu : %d concordante(s), %d discordante(s)", c, d)
	}
}
