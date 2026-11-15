package main

// Essais de la revue de sécurité de l'étape 8 (CT-7 révision 0.5) : CR-4
// (un temoin, un auditeur ou un observateur n'exécute aucune étape), CR-5
// (module RSA d'au moins 3 072 bits), plancher de l'oracle et cas comptés
// contre INDEX.md (CT-9 TA-66).

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
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

func lancerCT7(t *testing.T, args ...string) (int, string) {
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

// CR-4 (révision 0.5) : performed_by est un participant de rôle officiant,
// detenteur_part ou membre. Le procès-verbal de l'exemple de 5.10 reçoit, au
// besoin, un quatrième participant (compte 3), puis est signé de nouveau.
func TestRevueCR4RoleExecutant(t *testing.T) {
	sch := chargerSchemaTest(t, "ceremonie-cles-v0")
	b, err := os.ReadFile("../ceremonies/valide-creation-enregistreur/proces-verbal.json")
	if err != nil {
		t.Skip("vecteurs absents")
	}
	cles, _ := Comptes("test test test test test test test test test test test junk", 5)
	parAdr := map[string][]byte{}
	for _, k := range cles {
		a, _ := AdresseDePrivee(k)
		parAdr[Hex0x(a)] = k
	}
	resigner := func(texte string) []byte {
		pv, err := AnalyserJSON([]byte(texte))
		if err != nil {
			t.Fatal(err)
		}
		dc, err := CondenseCeremonie(pv)
		if err != nil {
			t.Fatal(err)
		}
		adr := map[string]string{}
		for _, p := range pv.Get("participants").Arr {
			adr[p.Get("id").Str] = p.Get("address").Str
		}
		for _, s := range pv.Get("signatures").Arr {
			sig, _ := Signer(parAdr[adr[s.Get("participant").Str]], MessageEIP191(dc))
			s.Get("signature").Str = sig
		}
		c, _ := Canonique(pv)
		return c
	}
	remplacer := func(s, a, n string) string {
		if !strings.Contains(s, a) {
			t.Fatalf("mutation sans effet : %s", a)
		}
		return strings.Replace(s, a, n, 1)
	}
	// Quatrième participant de rôle donné (compte 3), et sa signature.
	avecP4 := func(role string) string {
		s := remplacer(string(b), `"address": "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65"
    }`, `"address": "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65"
    },
    {
      "id": "p4",
      "name": "Quatrième participant (compte de test 3)",
      "role": "`+role+`",
      "affiliation": "assureur-demo",
      "address": "0x90f79bf6eb2c4f870365e785982e1f101e93b906"
    }`)
		i := strings.LastIndex(s, `"signatures": [`)
		return s[:i] + remplacer(s[i:], `"signatures": [`, `"signatures": [
    {
      "participant": "p4",
      "signature": "0x00"
    },`)
	}
	etape2 := `"n": 2,
      "action": `
	executant := func(s, par, temoins string) string {
		i := strings.Index(s, etape2)
		j := i + strings.Index(s[i:], `"performed_by": "p1"`)
		k := j + strings.Index(s[j:], `]`)
		return s[:j] + `"performed_by": "` + par + `",
      "witnessed_by": [` + temoins + `]` + s[k+1:]
	}
	if !strings.Contains(string(b), etape2) {
		t.Fatalf("étape 2 introuvable dans l'exemple")
	}
	cas := []struct{ nom, texte, echecs string }{
		{"témoin supplémentaire, officiant exécutant (témoin)", executant(avecP4("temoin"), "p1", `"p4"`), ""},
		{"auditeur exécutant", executant(string(b), "p3", `"p2"`), "CR-2,CR-4"},
		{"observateur exécutant", executant(avecP4("observateur"), "p4", `"p2"`), "CR-4"},
		{"témoin exécutant, un autre témoin", executant(avecP4("temoin"), "p2", `"p4"`), "CR-4"},
	}
	for _, c := range cas {
		r := VerifierCeremonie(resigner(c.texte), sch)
		if got := strings.Join(r.Echecs(), ","); got != c.echecs {
			t.Errorf("%s : %q en échec, %q attendu (%v)", c.nom, got, c.echecs, r.Details)
		}
	}
}

// CR-5 (révision 0.5, CLE-10, CT-5 AN-31) : une clé rsa a un module d'au
// moins 3 072 bits.
func TestRevueCR5ModuleRSA(t *testing.T) {
	cle := func(bits int) *Value {
		k, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			t.Fatal(err)
		}
		spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		v, err := AnalyserJSON([]byte(`{"algorithm":"rsa","usage":"tsa_interne","public_key":"` + Hex0x(spki) + `","fingerprint":"` + Hex0x(SHA256(spki)) + `","address":null}`))
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if x := controlerEncodageCle(cle(2048)); len(x) != 1 || !strings.Contains(x[0], "module RSA de 2048 bits") {
		t.Errorf("RSA 2048 : %v, un refus du module attendu", x)
	}
	if x := controlerEncodageCle(cle(3072)); len(x) != 0 {
		t.Errorf("RSA 3072 : %v, aucun refus attendu", x)
	}
}

// monterRacineCT7 rend une racine spec/vecteurs/ct-7 faite de liens vers les
// entrées publiées (le reste de spec/ en liens), sauf celles de sans ; reels
// sont des répertoires réels.
func monterRacineCT7(t *testing.T, reels []string, sans map[string]bool) string {
	t.Helper()
	abs, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	spec := filepath.Join(dst, "spec")
	vec := filepath.Join(spec, "vecteurs")
	if err := os.MkdirAll(vec, 0o755); err != nil {
		t.Fatal(err)
	}
	specAbs := filepath.Dir(filepath.Dir(abs))
	for _, d := range []struct{ src, dst, sauf string }{{specAbs, spec, "vecteurs"}, {filepath.Dir(abs), vec, "ct-7"}} {
		es, _ := os.ReadDir(d.src)
		for _, e := range es {
			if e.Name() != d.sauf {
				if err := os.Symlink(filepath.Join(d.src, e.Name()), filepath.Join(d.dst, e.Name())); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	racine := filepath.Join(vec, "ct-7")
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

// CT-9 TA-66 : famille sans valeur, cas retiré, cas non indexé, INDEX.md
// absent : code 1 et l'erreur nommée.
func TestRevuePlancherCT7(t *testing.T) {
	if _, err := os.Stat(filepath.Join("..", "INDEX.md")); err != nil {
		t.Skip("vecteurs publiés absents")
	}
	es, _ := os.ReadDir(filepath.Join("..", "ceremonies"))
	retire := es[len(es)-1].Name()
	enTrop := monterRacineCT7(t, []string{"ceremonies"}, nil)
	if err := os.Symlink(filepath.Join(enTrop, "ceremonies", retire), filepath.Join(enTrop, "ceremonies", "copie-non-indexee")); err != nil {
		t.Fatal(err)
	}
	cas := []struct{ nom, racine, message string }{
		{"sans matrice-conformite.json ni matrice/", monterRacineCT7(t, nil, map[string]bool{"matrice-conformite.json": true, "matrice": true}), "plancher (CT-9 TA-66) : famille matrice : aucune valeur recalculée"},
		{"une cérémonie retirée", monterRacineCT7(t, []string{"ceremonies"}, map[string]bool{filepath.Join("ceremonies", retire): true}), "le cas " + retire + " est nommé mais absent de la racine"},
		{"une cérémonie non indexée", enTrop, "le cas copie-non-indexee est présent mais l'index ne le nomme pas"},
		{"sans INDEX.md", monterRacineCT7(t, nil, map[string]bool{"INDEX.md": true}), "plancher (CT-9 TA-66) : INDEX.md illisible"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			code, sortie := lancerCT7(t, c.racine)
			if code != 1 || !strings.Contains(sortie, c.message) {
				t.Errorf("code %d (attendu 1), message « %s » attendu :\n%s", code, c.message, sortie)
			}
		})
	}
}
