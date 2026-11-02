package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/noorfinances-eng/noortrace/verificateur/horodatage"
	"github.com/noorfinances-eng/noortrace/verificateur/jsonv"
	"github.com/noorfinances-eng/noortrace/verificateur/schema"
)

const (
	ct1 = "../../../spec/vecteurs/ct-1/dossiers/"
	ct6 = "../../../spec/vecteurs/ct-6/"
)

func executer(args ...string) (int, string, string) {
	var o, e bytes.Buffer
	code := Executer(args, &o, &e)
	return code, o.String(), e.String()
}

// conforme vérifie qu'une sortie --json suit rapport-verification-v0
// (EX-8.5, EX-8.7) et rend le document.
func conforme(t *testing.T, sortie string) *jsonv.Valeur {
	t.Helper()
	v, err := jsonv.Analyser([]byte(sortie))
	if err != nil {
		t.Fatalf("sortie --json qui n'est pas du JSON : %v", err)
	}
	if err := schema.Valider(schema.RapportVerification, v); err != nil {
		t.Fatalf("sortie --json non conforme : %v", err)
	}
	return v
}

// TestUsage : EX-8.2, code 2, type usage.
func TestUsage(t *testing.T) {
	rep := ct1 + "valide-seq-7"
	cas := map[string][]string{
		"aucun répertoire":                {},
		"deux répertoires":                {rep, rep},
		"option inconnue":                 {rep, "--inconnue"},
		"option courte":                   {rep, "-j"},
		"option répétée":                  {rep, "--json", "--json"},
		"--langue répétée sous deux noms": {rep, "--langue=fr", "--langue", "en"},
		"option sans valeur":              {rep, "--ancres"},
		"valeur vide":                     {rep, "--ancres="},
		"langue hors domaine":             {rep, "--langue", "de"},
		"exiger hors domaine":             {rep, "--exiger", "9"},
		"exiger vide":                     {rep, "--exiger", ""},
		"exiger en double":                {rep, "--exiger", "4,4"},
		"exiger mal formé":                {rep, "--exiger", "4,,5"},
		"exiger zéro de tête":             {rep, "--exiger", "04"},
		"drapeau avec valeur":             {rep, "--json=oui"},
		"--version avec répertoire":       {"--version", rep},
		"--version avec --json":           {"--version", "--json"},
		"--aide avec --detail":            {"--aide", "--detail"},
		"--version et --aide":             {"--version", "--aide"},
		"--help et --aide":                {"--help", "--aide"},
	}
	for nom, args := range cas {
		code, _, e := executer(args...)
		if code != 2 || !strings.HasPrefix(e, "Erreur : ") {
			t.Errorf("%s : code %d, erreur %q", nom, code, e)
		}
	}
	// Avec --json, le rapport d'erreur d'usage est en JSON (EX-8.2, EX-8.5).
	code, o, _ := executer(rep, "--json", "--inconnue")
	if code != 2 {
		t.Fatalf("code %d", code)
	}
	v := conforme(t, o)
	if v.Chemin("error", "kind").S() != "usage" || !v.Membre("verdict").EstNul() || !v.Membre("inputs").EstNul() {
		t.Errorf("rapport d'erreur d'usage : %s", o)
	}
	// --option=valeur et --option valeur sont équivalents.
	c1, o1, _ := executer(rep, "--json", "--exiger=4,5,8")
	c2, o2, _ := executer(rep, "--json", "--exiger", "4,5,8")
	if c1 != 3 || c2 != 3 || o1 != o2 {
		t.Errorf("--option=valeur : %d, %d", c1, c2)
	}
}

func TestVersionEtAide(t *testing.T) {
	code, o, _ := executer("--version")
	if code != 0 || !strings.HasPrefix(o, "noortrace-verifier ") || !strings.Contains(o, runtime.Version()) || strings.Count(o, "\n") != 11 {
		t.Errorf("--version : %d %q", code, o)
	}
	for _, args := range [][]string{{"--aide"}, {"--help"}, {"--aide", "--langue", "en"}, {"--langue=en", "--version"}} {
		if code, o, _ := executer(args...); code != 0 || o == "" {
			t.Errorf("%v : code %d", args, code)
		}
	}
	_, fr, _ := executer("--aide")
	_, en, _ := executer("--aide", "--langue", "en")
	if fr == en || !strings.Contains(en, "Exit codes") {
		t.Error("aide anglaise")
	}
}

// exempleSpec extrait de CT-6 §8.5 le rapport lisible d'une commande.
func exempleSpec(t *testing.T, commande string) []string {
	t.Helper()
	b, err := os.ReadFile("../../../spec/CT-6-verificateur.md")
	if err != nil {
		t.Fatal(err)
	}
	texte := string(b)
	i := strings.Index(texte, "$ "+commande+"\n")
	if i < 0 {
		t.Fatalf("exemple introuvable : %s", commande)
	}
	bloc := texte[i+len(commande)+3:]
	bloc = bloc[:strings.Index(bloc, "$ echo $?")]
	return strings.Split(strings.TrimRight(bloc, "\n"), "\n")
}

// comparerExemple : le rapport lisible égale l'exemple de CT-6 §8.5, à la
// ligne « Vérificateur » près (nom, version, environnement) et aux chemins
// abrégés « …/ » près.
func comparerExemple(t *testing.T, attendu []string, obtenu string) {
	t.Helper()
	racine, _ := filepath.Abs("../../..")
	lignes := strings.Split(strings.TrimRight(obtenu, "\n"), "\n")
	if len(lignes) != len(attendu) {
		t.Fatalf("%d lignes, %d attendues :\n%s", len(lignes), len(attendu), obtenu)
	}
	for i := range attendu {
		a := strings.ReplaceAll(attendu[i], "…/", racine+"/")
		if strings.HasPrefix(a, "Vérificateur  : ") || strings.HasPrefix(a, "Verifier      : ") {
			continue
		}
		if a != lignes[i] {
			t.Errorf("ligne %d :\n obtenu  %q\n attendu %q", i+1, lignes[i], a)
		}
	}
}

func TestExemplesLisibles(t *testing.T) {
	code, o, _ := executer(ct1 + "valide-seq-7")
	if code != 0 {
		t.Fatalf("code %d", code)
	}
	comparerExemple(t, exempleSpec(t, "node scripts/verify/dossier.mjs spec/vecteurs/ct-1/dossiers/valide-seq-7"), o)

	code, o, _ = executer(ct1 + "invalide-hash-faux")
	if code != 1 {
		t.Fatalf("code %d", code)
	}
	comparerExemple(t, exempleSpec(t, "node scripts/verify/dossier.mjs spec/vecteurs/ct-1/dossiers/invalide-hash-faux"), o)

	code, o, _ = executer(ct1+"valide-seq-7", "--exiger", "4,5,8")
	if code != 3 || !strings.Contains(o, "\nRésultat      : INCOMPLET — contrôle(s) exigé(s) non réussi(s) : 4, 5, 8\n") {
		t.Errorf("--exiger 4,5,8 : code %d\n%s", code, o)
	}
	code, o, _ = executer(ct1+"valide-seq-7", "--exiger", "tous")
	if code != 3 || !strings.Contains(o, "4, 5, 7, 8") && !strings.Contains(o, "4, 5, 8") {
		t.Errorf("--exiger tous : code %d", code)
	}
	if code, _, _ := executer(ct1+"valide-seq-7", "--exiger", "1,2,3,6,7"); code != 0 {
		t.Errorf("--exiger 1,2,3,6,7 : code %d", code)
	}
	code, o, _ = executer(ct1+"valide-seq-7", "--langue", "en", "--detail")
	if code != 0 || !strings.Contains(o, "Offline verification") || !strings.Contains(o, "\nChecks:\n") || !strings.Contains(o, "Statement     : Event seq 7") {
		t.Errorf("anglais, --detail : %d\n%s", code, o)
	}
}

// TestJSON : rapports conformes au schéma (EX-8.7), mêmes octets à chaque
// exécution (V-8), --langue ne change que les textes (EX-8.3).
func TestJSON(t *testing.T) {
	for _, d := range []string{"valide-seq-7", "valide-seq-6", "invalide-hash-faux", "invalide-partie-nulle", "invalide-k1-double-defaut", "valide-seq-12-attestation-inscrite", "valide-seq-7-point-de-controle", "valide-at6-cle-non-ancree", "invalide-index-seq"} {
		code, o, _ := executer(ct1+d, "--json")
		v := conforme(t, o)
		if n, _ := v.Membre("exit_code").Entier(); int(n) != code {
			t.Errorf("%s : exit_code %d, code %d", d, n, code)
		}
		_, o2, _ := executer(ct1+d, "--json")
		if o != o2 {
			t.Errorf("%s : deux exécutions, deux rapports", d)
		}
		_, en, _ := executer(ct1+d, "--json", "--langue", "en")
		ve := conforme(t, en)
		if !jsonv.Egales(v.Membre("statement"), ve.Membre("statement")) || !jsonv.Egales(v.Membre("failed_checks"), ve.Membre("failed_checks")) || ve.Membre("language").S() != "en" {
			t.Errorf("%s : --langue change autre chose que les textes", d)
		}
	}
	// Exemple de CT-6 §8.6 : rapport d'erreur d'un répertoire sans
	// dossier.json.
	vide := t.TempDir()
	code, o, _ := executer(vide, "--json")
	v := conforme(t, o)
	if code != 2 || v.Chemin("error", "kind").S() != "dossier_illisible" || v.Chemin("error", "message").S() != "dossier.json absent : le répertoire n'est pas un dossier de preuve" || !v.Chemin("inputs", "dossier", "index_sha256").EstNul() {
		t.Errorf("dossier.json absent : %d %s", code, o)
	}
}

// TestEntreesAPart : fichier d'ancres, en-têtes, second manifeste, pièces
// (EX-4.6, EX-4.7, EX-4.10, EX-4.12).
func TestEntreesAPart(t *testing.T) {
	rep := ct1 + "valide-seq-7"
	tmp := t.TempDir()
	mauvais := filepath.Join(tmp, "mauvais.json")
	os.WriteFile(mauvais, []byte(`{"version":1}`), 0o644)
	for _, c := range []struct {
		args         []string
		genre, verif string
	}{
		{[]string{"--ancres", mauvais}, "ancres_inutilisables", "N-1"},
		{[]string{"--ancres", filepath.Join(tmp, "absent")}, "ancres_inutilisables", "N-1"},
		{[]string{"--entetes-bitcoin", mauvais}, "entree_illisible", "N-2"},
		{[]string{"--second-manifeste", mauvais}, "entree_illisible", ""},
		{[]string{"--pieces", mauvais}, "entree_illisible", ""},
	} {
		code, o, _ := executer(append([]string{rep, "--json"}, c.args...)...)
		v := conforme(t, o)
		chk := ""
		if c := v.Chemin("error", "check"); c.EstChaine() {
			chk = c.Chaine
		}
		if code != 2 || v.Chemin("error", "kind").S() != c.genre || chk != c.verif {
			t.Errorf("%v : %d %s %s", c.args, code, v.Chemin("error", "kind").S(), chk)
		}
	}
	// Second manifeste : le suivant se chaîne (P-5 réussie), un manifeste
	// non adjacent met P-5 en échec.
	man := "../../../spec/vecteurs/ct-1/manifestes/"
	if code, o, _ := executer(rep, "--second-manifeste", man+"periode-2.json", "--detail"); code != 0 || !strings.Contains(o, "continuité avec le second manifeste vérifiée") {
		t.Errorf("manifeste suivant : %d\n%s", code, o)
	}
	if code, o, _ := executer(rep, "--second-manifeste", man+"periode-3.json"); code != 1 || !strings.Contains(o, "INVALIDE — vérification(s) en échec : P-5") {
		t.Errorf("manifeste non adjacent : %d\n%s", code, o)
	}
	// Pièces : une pièce dont les octets correspondent ; une pièce altérée
	// fait échouer E-6.
	pieces := t.TempDir()
	if code, o, _ := executer(rep, "--pieces", pieces, "--json"); code != 0 || !strings.Contains(o, `"files": 0`) {
		t.Errorf("répertoire de pièces vide : %d", code)
	}
	ev, _ := os.ReadFile(rep + "/evenement.json")
	e, _ := jsonv.Analyser(ev)
	sha := e.Chemin("execution", "result", "sha256").S()[2:]
	os.WriteFile(filepath.Join(pieces, sha), []byte("pièce altérée"), 0o644)
	if code, o, _ := executer(rep, "--pieces", pieces); code != 1 || !strings.Contains(o, "E-6") {
		t.Errorf("pièce altérée : %d\n%s", code, o)
	}
}

// TestBinaireProvisoire : tant que les contrôles 4, 5 et 8 sont à
// construire, un dossier qui porte leurs parties n'a pas de verdict (code 2,
// erreur_interne) au lieu d'un verdict qui ignorerait une partie présente
// (EX-4.2).
func TestBinaireProvisoire(t *testing.T) {
	if horodatage.Construit() {
		t.Skip("contrôle 4 construit")
	}
	code, o, _ := executer(ct6+"dossiers/valide-seq-7-complet", "--json", "--ancres", ct6+"ancres/ancres-test.json", "--entetes-bitcoin", ct6+"ots/entetes/chaine.json")
	v := conforme(t, o)
	if code != 2 || v.Chemin("error", "kind").S() != "erreur_interne" || !strings.Contains(v.Chemin("error", "message").S(), "T-1") {
		t.Errorf("binaire provisoire : %d %s", code, o)
	}
}
