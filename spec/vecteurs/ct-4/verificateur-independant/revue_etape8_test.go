package main

// Essais de la revue de sécurité de l'étape 8 : partie « Provision » d'OP-4
// (CT-4 révision 0.8, EX-4.19, EX-4.20, EX-8.20), entrée absente sans
// panique (garde nil), plancher et cas comptés contre INDEX.md (CT-9 TA-66).

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestMain permet aux essais du plancher de lancer main() dans un processus
// fils (code de retour observé tel que le module le rend).
func TestMain(m *testing.M) {
	if os.Getenv("NOORTRACE_REVUE_MAIN") == "1" {
		os.Args = append([]string{"verificateur-independant"}, strings.Split(os.Getenv("NOORTRACE_REVUE_ARGS"), "\x1f")...)
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func lancerCT4(t *testing.T, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "NOORTRACE_REVUE_MAIN=1", "NOORTRACE_REVUE_ARGS="+strings.Join(args, "\x1f"))
	var sortie bytes.Buffer
	cmd.Stdout, cmd.Stderr = &sortie, &sortie
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, sortie.String()
	case errors.As(err, &ee):
		return ee.ExitCode(), sortie.String()
	}
	t.Fatal(err)
	return -1, ""
}

// monterRacineCT4 rend une racine faite de liens vers les entrées publiées
// de ct-4, sauf celles de sans ; reels sont des répertoires réels faits de
// liens vers leurs entrées.
func monterRacineCT4(t *testing.T, reels []string, sans map[string]bool) string {
	t.Helper()
	abs, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	// Les familles lisent ../../CT-4-registre.md, ../../schemas, ../ct-1 et
	// ../ct-6 : la racine est placée dans une copie de liens de spec/.
	spec := filepath.Join(dst, "spec")
	vec := filepath.Join(spec, "vecteurs")
	if err := os.MkdirAll(vec, 0o755); err != nil {
		t.Fatal(err)
	}
	specAbs := filepath.Dir(filepath.Dir(abs))
	for _, d := range []struct{ src, dst string }{{specAbs, spec}, {filepath.Dir(abs), vec}} {
		es, _ := os.ReadDir(d.src)
		for _, e := range es {
			if e.Name() == "vecteurs" && d.src == specAbs || e.Name() == "ct-4" && d.src == filepath.Dir(abs) {
				continue
			}
			if err := os.Symlink(filepath.Join(d.src, e.Name()), filepath.Join(d.dst, e.Name())); err != nil {
				t.Fatal(err)
			}
		}
	}
	depot := filepath.Dir(specAbs)
	es, _ := os.ReadDir(depot)
	for _, e := range es {
		if e.Name() != "spec" {
			if err := os.Symlink(filepath.Join(depot, e.Name()), filepath.Join(dst, e.Name())); err != nil {
				t.Fatal(err)
			}
		}
	}
	racine := filepath.Join(vec, "ct-4")
	var copier func(rel string)
	copier = func(rel string) {
		if err := os.MkdirAll(filepath.Join(racine, rel), 0o755); err != nil {
			t.Fatal(err)
		}
		es, err := os.ReadDir(filepath.Join(abs, rel))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range es {
			r := filepath.Join(rel, e.Name())
			if sans[r] || r == "verificateur-independant" {
				continue
			}
			reel := false
			for _, x := range reels {
				reel = reel || x == r
			}
			if reel {
				copier(r)
				continue
			}
			if err := os.Symlink(filepath.Join(abs, r), filepath.Join(racine, r)); err != nil {
				t.Fatal(err)
			}
		}
	}
	copier("")
	return racine
}

// CT-4 OP-4 « Provision » (révision 0.8) : funder différent de la trésorerie
// donnée (compte_inattendu), amount_wei différent de P_k et daily_budget_gas
// au-delà de fees.max_daily_budget_gas (provision_excessive) ; un dossier
// conforme sous des frais donnés passe.
func TestRevueProvisionOP4(t *testing.T) {
	src := filepath.Join("..", "inscription", "valides", "assureur-demo-prepare.json")
	if !fichierExisteCT4(src) {
		t.Skip("vecteurs publiés absents")
	}
	racine := monterRacineCT4(t, []string{"inscription"}, map[string]bool{filepath.Join("inscription", "inscription.json"): true})
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	base := string(b)
	ecrire := func(nom, contenu string) {
		if err := os.MkdirAll(filepath.Join(racine, "inscription", "revue"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(racine, "inscription", "revue", nom), []byte(contenu), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	remplacer := func(s, a, n string) string {
		if !strings.Contains(s, a) {
			t.Fatalf("altération sans effet : %s", a)
		}
		return strings.Replace(s, a, n, 1)
	}
	ecrire("funder-etranger.json", remplacer(base, `"funder": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"`, `"funder": "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65"`))
	ecrire("provision-differente.json", remplacer(base, `"amount_wei": "327000000"`, `"amount_wei": "327000001"`))
	ecrire("budget-au-dela.json", remplacer(remplacer(base, `"daily_budget_gas": 10800000`, `"daily_budget_gas": 10800001`), `"amount_wei": "327000000"`, `"amount_wei": "327000030"`))
	ecrire("frais-donnes.json", remplacer(base, `"amount_wei": "327000000"`, `"amount_wei": "111000000"`))
	frais := `{"transaction_type":2,"max_fee_per_gas_wei":"1","max_priority_fee_per_gas_wei":"1","gas_limit":3000000,"gas_limit_max":16777216,"provision_days":10,"refill_below_days":7,"max_daily_budget_gas":10800000}`
	plafond := `{"transaction_type":2,"max_fee_per_gas_wei":"1","max_priority_fee_per_gas_wei":"1","gas_limit":3000000,"gas_limit_max":16777216,"provision_days":30,"refill_below_days":7,"max_daily_budget_gas":10800000}`
	cas := func(id, fichier, extra, refus string) string {
		exp := `{"result":"valide","org_id":"0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab"}`
		ref := "null"
		if refus != "" {
			exp, ref = "null", `{"check":"OP-4","code":"`+refus+`"}`
		}
		return `{"id":"` + id + `","description":"revue","checks":["OP-4"],"input":{"file":"inscription/revue/` + fichier + `","nature":"developpement","operator_accounts":[]` + extra + `},"expected":` + exp + `,"refusal":` + ref + `}`
	}
	famille := `{"version":0,"family":"inscription","description":"revue","cases":[` + strings.Join([]string{
		cas("funder-etranger", "funder-etranger.json", `,"treasury":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"`, "compte_inattendu"),
		cas("funder-tresorerie", "../valides/assureur-demo-prepare.json", `,"treasury":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"`, ""),
		cas("provision-differente", "provision-differente.json", "", "provision_excessive"),
		cas("budget-au-dela", "budget-au-dela.json", `,"fees":`+plafond, "provision_excessive"),
		cas("budget-au-plafond", "../valides/assureur-demo-prepare.json", `,"fees":`+plafond, ""),
		cas("frais-donnes", "frais-donnes.json", `,"fees":`+frais, ""),
	}, ",") + `]}`
	if err := os.WriteFile(filepath.Join(racine, "inscription", "inscription.json"), []byte(famille), 0o644); err != nil {
		t.Fatal(err)
	}
	rap := VerifierVecteurs(racine)
	f := rap.F("inscription")
	for _, d := range f.Discordances {
		t.Errorf("%s · %s : attendu %s, recalculé %s", d.Cas, d.Valeur, d.Attendu, d.Recalcule)
	}
	if f.Cas < 6 {
		t.Errorf("%d cas confrontés, 6 attendus", f.Cas)
	}
}

func fichierExisteCT4(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// Entrée absente sans panique : constantes.json absent : erreur consignée, rapport
// imprimé, code 1, jamais une panique.
func TestRevueConstantesAbsentSansPanique(t *testing.T) {
	if !fichierExisteCT4(filepath.Join("..", "constantes.json")) {
		t.Skip("vecteurs publiés absents")
	}
	racine := monterRacineCT4(t, nil, map[string]bool{"constantes.json": true})
	code, sortie := lancerCT4(t, racine)
	if code != 1 || strings.Contains(sortie, "panic") || strings.Contains(sortie, "panne interne") || !strings.Contains(sortie, "famille capture non confrontée") || !strings.Contains(sortie, "total ") {
		t.Errorf("code %d (attendu 1, rapport imprimé, sans panique) :\n%s", code, sortie)
	}
}

// CT-9 TA-66 : fichier de famille sans cas, cas retiré, cas non indexé,
// INDEX.md absent : code 1 et l'erreur nommée ; vecteurs complets : code 0.
func TestRevuePlancherCT4(t *testing.T) {
	if !fichierExisteCT4(filepath.Join("..", "INDEX.md")) {
		t.Skip("vecteurs publiés absents")
	}
	reecrire := func(f func(string) string) string {
		r := monterRacineCT4(t, []string{"inscription"}, map[string]bool{filepath.Join("inscription", "inscription.json"): true})
		b, err := os.ReadFile(filepath.Join("..", "inscription", "inscription.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(r, "inscription", "inscription.json"), []byte(f(string(b))), 0o644); err != nil {
			t.Fatal(err)
		}
		return r
	}
	v, _, err := LireJSON(filepath.Join("..", "inscription", "inscription.json"))
	if err != nil {
		t.Fatal(err)
	}
	dernier := v.Get("cases").Arr[len(v.Get("cases").Arr)-1].Get("id").S()
	sansCas := reecrire(func(s string) string {
		i := strings.Index(s, `"cases"`)
		return s[:i] + `"cases": []}` + "\n"
	})
	sansDernier := reecrire(func(s string) string {
		i := strings.LastIndex(s, `{`+"\n"+`      "id": "`+dernier+`"`)
		if i < 0 {
			i = strings.LastIndex(s, `"id": "`+dernier+`"`)
			i = strings.LastIndex(s[:i], "{")
		}
		j := strings.LastIndex(s[:i], ",")
		return s[:j] + "\n  ]\n}\n"
	})
	enTrop := reecrire(func(s string) string {
		return strings.Replace(s, `"id": "`+dernier+`"`, `"id": "copie-non-indexee"`, 1)
	})
	cas := []struct{ nom, racine, message string }{
		{"inscription sans cas", sansCas, "famille inscription : aucun cas (plancher, CT-9 TA-66)"},
		{"dernier cas retiré", sansDernier, "le cas " + dernier + " est nommé par INDEX.md mais absent de inscription/inscription.json"},
		{"cas non indexé", enTrop, "le cas copie-non-indexee de inscription/inscription.json n'est pas nommé par INDEX.md"},
		{"sans INDEX.md", monterRacineCT4(t, nil, map[string]bool{"INDEX.md": true}), "INDEX.md illisible"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			code, sortie := lancerCT4(t, c.racine)
			if code != 1 || !strings.Contains(sortie, c.message) {
				t.Errorf("code %d (attendu 1), message « %s » attendu :\n%s", code, c.message, sortie)
			}
		})
	}
	t.Run("vecteurs complets", func(t *testing.T) {
		if code, sortie := lancerCT4(t, monterRacineCT4(t, nil, nil)); code != 0 {
			t.Errorf("code %d, attendu 0 :\n%s", code, sortie)
		}
	})
}

// Table de 9.3 (CT-4 révision 0.8) : le nom de chaque fichier de la capture
// est contrôlé avant toute lecture. L'index désigne l'en-tête sous le nom
// ../bloc-16648.json, et un en-tête valide est posé à cet endroit, hors du
// répertoire des captures : il ne doit pas être lu (CP-2 en échec, CP-6 en
// échec).
func TestRevueNomHorsRepertoireNonLu(t *testing.T) {
	c := contexteVecteurs(t)
	src := filepath.Join("..", "capture", "periode-1")
	idxB, err := os.ReadFile(filepath.Join(src, "capture-16648-0-inscription.json"))
	if err != nil {
		t.Skip("vecteurs publiés absents")
	}
	dst := t.TempDir()
	rep := filepath.Join(dst, "captures")
	if err := os.MkdirAll(rep, 0o755); err != nil {
		t.Fatal(err)
	}
	copier := func(nom, vers string) {
		b, err := os.ReadFile(filepath.Join(src, nom))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vers, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	idx := string(idxB)
	if !strings.Contains(idx, `"name": "bloc-16648.json"`) {
		t.Fatalf("index sans bloc-16648.json")
	}
	idx = strings.Replace(idx, `"name": "bloc-16648.json"`, `"name": "../bloc-16648.json"`, 1)
	if err := os.WriteFile(filepath.Join(rep, "capture-16648-0-inscription.json"), []byte(idx), 0o644); err != nil {
		t.Fatal(err)
	}
	copier("bloc-16648.json", filepath.Join(dst, "bloc-16648.json"))
	es, _ := os.ReadDir(src)
	for _, e := range es {
		if strings.HasPrefix(e.Name(), "recu-") || e.Name() == "certificat-16648.json" {
			copier(e.Name(), filepath.Join(rep, e.Name()))
		}
	}
	jeu, _ := c.jeuDe("test/fixtures/certificat-commit/validators.json")
	res := c.VerifierCapture(rep, "capture-16648-0-inscription.json", jeu, "noortrace-2124-dev")
	if e := res.Verdicts["CP-2"]; e == nil || !strings.Contains(e.Raison, "hors du répertoire des captures") {
		t.Errorf("CP-2 : %v, échec « hors du répertoire des captures » attendu (fichier hors du répertoire lu)", e)
	}
	if e := res.Verdicts["CP-6"]; e == nil {
		t.Errorf("CP-6 réussie, échec attendu")
	}
}
