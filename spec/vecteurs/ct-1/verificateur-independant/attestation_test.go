package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Révision 0.4 : l'exemple de attestation-perimetre.json imprimé en §11.2,
// écrit comme les autres parties (JSON.stringify(objet, null, 2) suivi d'un
// saut de ligne), fait 5 443 octets et a le SHA-256 que la ligne de §11.1
// déclare ; joint au dossier de référence (quatorze parties, la treizième
// absente), AT-1 à AT-5 réussissent, AT-6 et AT-7 ne sont pas exécutées
// (partie absente) et le dossier reste valide.

const cheminCT1 = "../../../CT-1-evenements-et-formats.md"

// blocExemple rend le bloc JSON qui suit le repère donné dans CT-1.
func blocExemple(t *testing.T, repere string) string {
	t.Helper()
	b, err := os.ReadFile(cheminCT1)
	if err != nil {
		t.Skip("texte de CT-1 absent")
	}
	lignes := strings.Split(string(b), "\n")
	for i, l := range lignes {
		if !strings.Contains(l, repere) {
			continue
		}
		var sb strings.Builder
		dedans := false
		for _, m := range lignes[i+1:] {
			if strings.HasPrefix(m, "```") {
				if dedans {
					return sb.String()
				}
				dedans = true
				continue
			}
			if dedans {
				sb.WriteString(m + "\n")
			}
		}
	}
	t.Fatalf("repère %q introuvable", repere)
	return ""
}

// indenter écrit une valeur comme JSON.stringify(v, null, 2).
func indenter(sb *strings.Builder, v *Value, marge string) {
	switch v.Kind {
	case KindObject:
		if len(v.Obj) == 0 {
			sb.WriteString("{}")
			return
		}
		sb.WriteString("{\n")
		for i, m := range v.Obj {
			sb.WriteString(marge + "  ")
			EchapperChaine(sb, m.Key)
			sb.WriteString(": ")
			indenter(sb, m.Val, marge+"  ")
			if i < len(v.Obj)-1 {
				sb.WriteByte(',')
			}
			sb.WriteByte('\n')
		}
		sb.WriteString(marge + "}")
	case KindArray:
		if len(v.Arr) == 0 {
			sb.WriteString("[]")
			return
		}
		sb.WriteString("[\n")
		for i, x := range v.Arr {
			sb.WriteString(marge + "  ")
			indenter(sb, x, marge+"  ")
			if i < len(v.Arr)-1 {
				sb.WriteByte(',')
			}
			sb.WriteByte('\n')
		}
		sb.WriteString(marge + "]")
	default:
		c, _ := Canonique(v)
		sb.Write(c)
	}
}

func partieExemple(t *testing.T) []byte {
	v, err := ParseJSON([]byte(blocExemple(t, "<!-- schema: attestation_perimetre -->")))
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	indenter(&sb, v, "")
	sb.WriteByte('\n')
	return []byte(sb.String())
}

// dossierAvecAttestation copie le dossier de référence, y écrit la partie
// et déclare les quatorze parties.
func dossierAvecAttestation(t *testing.T, partie []byte) string {
	t.Helper()
	dir := dossierTemporaire(t, nil, false)
	if err := os.WriteFile(filepath.Join(dir, "attestation-perimetre.json"), partie, 0o644); err != nil {
		t.Fatal(err)
	}
	index, err := os.ReadFile(filepath.Join(dir, "dossier.json"))
	if err != nil {
		t.Fatal(err)
	}
	fin := "    }\n  ]\n}"
	ajout := "    },\n" +
		"    {\n      \"name\": \"points_de_controle\",\n      \"file\": \"points-de-controle.json\",\n      \"sha256\": null,\n      \"present\": false,\n      \"reason_if_absent\": \"aucun point de contrôle\"\n    },\n" +
		"    {\n      \"name\": \"attestation_perimetre\",\n      \"file\": \"attestation-perimetre.json\",\n      \"sha256\": \"" + Hex0x(SHA256(partie)) + "\",\n      \"present\": true,\n      \"reason_if_absent\": null\n" + fin
	texte := strings.Replace(string(index), fin, ajout, 1)
	if texte == string(index) {
		t.Fatal("index de référence de forme inattendue")
	}
	if err := os.WriteFile(filepath.Join(dir, "dossier.json"), []byte(texte), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAttestationExempleReference(t *testing.T) {
	partie := partieExemple(t)
	if len(partie) != 5443 {
		t.Errorf("partie de %d octets, 5 443 attendus (§11.2)", len(partie))
	}
	if got := Hex0x(SHA256(partie)); got != "0x08c7b70e7b757bebc9137210446eabb60032c38f8d7bc2434da2df97cb423072" {
		t.Errorf("SHA-256 de la partie %s ≠ celui de §11.1", got)
	}
	v, _ := ParseJSON(partie)
	c, _ := Canonique(v.Get("signed").Get("attestation"))
	if dp := Hex0x(Keccak256(append([]byte(PrefixeAttestation), c...))); dp != "0x4481a2e47712539c4ca50f2eea3d6062ec11a70d497c153c1a6f707606657cfd" {
		t.Errorf("D_P %s ≠ celui de §13 et de l'annexe B", dp)
	}
	if h := Hex0x([]byte(PrefixeAttestation)); h != "0x6e6f6f7274726163652f6174746573746174696f6e2d706572696d657472652f76300a" {
		t.Errorf("P_P %s", h)
	}
	d := VerifierDossier(dossierAvecAttestation(t, partie))
	if !d.Valide() {
		t.Fatalf("dossier avec la partie invalide :\n%s", d.Resultats.Resume("  "))
	}
	attendu := "AT-1 reussi null, AT-2 reussi null, AT-3 reussi null, AT-4 reussi null, AT-5 reussi null, AT-6 non_execute partie_absente, AT-7 non_execute partie_absente"
	if got := strings.Join(d.PerimetreTexte(), ", "); got != attendu {
		t.Errorf("statuts %s", got)
	}
}

// Altérations de la partie : chaque AT- en échec reste sans effet sur la
// validité du dossier (§11.4, révision 0.4).
func TestAttestationAlterations(t *testing.T) {
	base := string(partieExemple(t))
	cas := []struct {
		nom, avant, apres, statuts string
	}{
		{"signature du compte 2 attribuée au compte 3", `"address": "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
        "signature"`, `"address": "0x90f79bf6eb2c4f870365e785982e1f101e93b906",
        "signature"`, "AT-1 reussi null, AT-2 reussi null, AT-3 echoue null, AT-4 non_execute prerequis_en_echec, AT-5 reussi null, AT-6 non_execute partie_absente, AT-7 non_execute partie_absente"},
		{"condensé déclaré faux", `"digest": "0x4481`, `"digest": "0x5481`, "AT-1 reussi null, AT-2 echoue null, AT-3 reussi null, AT-4 reussi null, AT-5 reussi null, AT-6 non_execute partie_absente, AT-7 non_execute partie_absente"},
		{"seuil de trois", `"required": 2`, `"required": 3`, "AT-1 reussi null, AT-2 reussi null, AT-3 reussi null, AT-4 echoue null, AT-5 reussi null, AT-6 non_execute partie_absente, AT-7 non_execute partie_absente"},
		{"validité terminée avant l'événement", `"until": "2027-01-31T23:59:59.999Z"`, `"until": "2026-11-01T23:59:59.999Z"`, ""},
		{"date inexistante", `"until": "2027-01-31T23:59:59.999Z"`, `"until": "2027-02-30T23:59:59.999Z"`, "AT-1 echoue null, AT-2 non_execute prerequis_en_echec, AT-3 non_execute prerequis_en_echec, AT-4 non_execute prerequis_en_echec, AT-5 non_execute prerequis_en_echec, AT-6 non_execute prerequis_en_echec, AT-7 non_execute prerequis_en_echec"},
		{"membre inconnu", `"declaration": `, `"extra": 1, "declaration": `, "AT-1 echoue null, AT-2 non_execute prerequis_en_echec, AT-3 non_execute prerequis_en_echec, AT-4 non_execute prerequis_en_echec, AT-5 non_execute prerequis_en_echec, AT-6 non_execute prerequis_en_echec, AT-7 non_execute prerequis_en_echec"},
	}
	for _, c := range cas {
		texte := strings.Replace(base, c.avant, c.apres, 1)
		if texte == base {
			t.Fatalf("%s : altération sans effet", c.nom)
		}
		d := VerifierDossier(dossierAvecAttestation(t, []byte(texte)))
		if !d.Valide() {
			t.Errorf("%s : le dossier devient invalide :\n%s", c.nom, d.Resultats.Resume("  "))
		}
		got := strings.Join(d.PerimetreTexte(), ", ")
		if c.statuts == "" {
			// La validité modifiée change D_P : AT-2 et AT-3 échouent aussi.
			if !strings.Contains(got, "AT-5 echoue") {
				t.Errorf("%s : AT-5 devait échouer : %s", c.nom, got)
			}
			continue
		}
		if got != c.statuts {
			t.Errorf("%s :\n  obtenu  %s\n  attendu %s", c.nom, got, c.statuts)
		}
	}
	// Index à quatorze parties dont la quatorzième n'est pas déclarée
	// présente : aucune AT-.
	dir := dossierAvecAttestation(t, []byte(base))
	idx, _ := os.ReadFile(filepath.Join(dir, "dossier.json"))
	texte := strings.Replace(string(idx), `"sha256": "`+Hex0x(SHA256([]byte(base)))+`",
      "present": true,
      "reason_if_absent": null`, `"sha256": null,
      "present": false,
      "reason_if_absent": "aucune attestation de périmètre"`, 1)
	os.Remove(filepath.Join(dir, "attestation-perimetre.json"))
	os.WriteFile(filepath.Join(dir, "dossier.json"), []byte(texte), 0o644)
	if d := VerifierDossier(dir); !d.Valide() || d.Perimetre != nil {
		t.Errorf("partie déclarée absente : valide %v, AT- %v", d.Valide(), d.PerimetreTexte())
	}
}
