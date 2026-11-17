package main

// Essais de la revue de sécurité de l'étape 8 (CT-3 révision 0.8) : tickets
// avec related_to (EX-12.14, EX-12.21, table d'EX-13.32), bornes des défis
// de preparer_inscription (EX-13.13), plancher de l'oracle et cas comptés
// contre INDEX.md (CT-9 TA-66).

import (
	"bytes"
	"errors"
	"fmt"
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

func lancerCT3(t *testing.T, args ...string) (int, string) {
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

// monterRacineCT3 rend une racine spec/vecteurs/ct-3 faite de liens vers les
// entrées publiées (le reste de spec/ en liens, pour ../../schemas et le
// texte), sauf celles de sans ; reels sont des répertoires réels.
func monterRacineCT3(t *testing.T, reels []string, sans map[string]bool) string {
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
	for _, d := range []struct{ src, dst, sauf string }{{specAbs, spec, "vecteurs"}, {filepath.Dir(abs), vec, "ct-3"}} {
		es, _ := os.ReadDir(d.src)
		for _, e := range es {
			if e.Name() != d.sauf {
				if err := os.Symlink(filepath.Join(d.src, e.Name()), filepath.Join(d.dst, e.Name())); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	racine := filepath.Join(vec, "ct-3")
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

const ticketApr0001 = `{"launched_by":"u.martin@assureur-demo.example","eligible":["0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc","0x70997970c51812dc3a010c7d01b50e0d17dc79c8"]}`

// casRelated sont les cas de tickets avec related_to : l'ordre de consulter
// s'applique au ticket désigné (EX-12.14, EX-12.21, révision 0.8).
var casRelated = []struct{ id, session, related, ticket, raison string }{
	{"related-eligible", "approbateur-1", "apr-0001", ticketApr0001, ""},
	{"related-administrateur", "admin-1", "apr-0001", ticketApr0001, ""},
	{"related-non-eligible", "u.martin", "apr-0001", ticketApr0001, "session_non_autorisee"},
	{"related-ticket-inconnu", "approbateur-1", "apr-0999", "null", "ticket_inconnu"},
	{"related-ticket-inconnu-non-eligible", "u.martin", "apr-0999", "null", "ticket_inconnu"},
	{"related-hors-organisation", "approbateur-9", "apr-0001", ticketApr0001, "session_non_autorisee"},
	{"related-inconnu-hors-organisation", "approbateur-9", "apr-0999", "null", "session_non_autorisee"},
	{"related-entree-desactivee", "approbateur-2", "apr-0001", ticketApr0001, "session_non_autorisee"},
}

func casRelatedJSON(c struct{ id, session, related, ticket, raison string }) string {
	raison := "null"
	if c.raison != "" {
		raison = `"` + c.raison + `"`
	}
	return `{"id":"tickets-` + c.id + `","description":"revue","checks":["AN-10"],"method":"tickets","request":{"session_identity":"oidc https://idp.assureur-demo.example ` + c.session + `","related_to":"` + c.related + `"},"ticket":` + c.ticket + `,"expected":{"reason":` + raison + `}}`
}

func TestRevueTicketsRelatedTo(t *testing.T) {
	src := filepath.Join("..", "annuaire", "controles-canal.json")
	b, err := os.ReadFile(src)
	if err != nil {
		t.Skip("vecteurs publiés absents")
	}
	d, err := ParseJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	ab, err := os.ReadFile(filepath.Join("..", "annuaire", d.Get("annuaire").S()))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ParseJSON(ab)
	if err != nil {
		t.Fatal(err)
	}
	// ControleCanal, cas par cas.
	for _, c := range casRelated {
		cas, err := ParseJSON([]byte(casRelatedJSON(c)))
		if err != nil {
			t.Fatal(err)
		}
		if got := ControleCanal(doc, "tickets", cas.Get("request"), cas.Get("ticket")); got != c.raison {
			t.Errorf("%s : %q, attendu %q", c.id, got, c.raison)
		}
	}
	// Sans related_to : le point 1 seul (ticket nul).
	sans, _ := ParseJSON([]byte(`{"session_identity":"oidc https://idp.assureur-demo.example u.martin"}`))
	if got := ControleCanal(doc, "tickets", sans, Nul()); got != "" {
		t.Errorf("tickets sans related_to, session de l'organisation : %q", got)
	}
	// Famille : les cas ajoutés à controles-canal.json concordent (ticket
	// non nul admis avec related_to).
	racine := monterRacineCT3(t, []string{"annuaire"}, map[string]bool{filepath.Join("annuaire", "controles-canal.json"): true})
	var ajouts []string
	for _, c := range casRelated {
		ajouts = append(ajouts, casRelatedJSON(c))
	}
	texte := strings.TrimSpace(string(b))
	i := strings.LastIndex(texte, "]")
	texte = texte[:i] + "," + strings.Join(ajouts, ",") + texte[i:]
	if err := os.WriteFile(filepath.Join(racine, "annuaire", "controles-canal.json"), []byte(texte), 0o644); err != nil {
		t.Fatal(err)
	}
	rap := VerifierVecteurs(racine)
	vus := 0
	for _, c := range rap.Comparaisons {
		if strings.HasPrefix(c.Vecteur, "annuaire/controles-canal.json tickets-related-") {
			vus++
			if !c.Concorde && !c.HorsPerimetre {
				t.Errorf("%s · %s : attendu %s, obtenu %s", c.Vecteur, c.Grandeur, c.Attendu, c.Obtenu)
			}
		}
	}
	if vus < len(casRelated) {
		t.Errorf("%d comparaisons des cas related_to, au moins %d attendues", vus, len(casRelated))
	}
}

// EX-13.13 (révision 0.8) : au plus 4 défis non expirés par identité, 1 024
// au total ; au-delà, limite_annuaire sans changer les défis ; le
// remplacement du défi de la même identité et de la même adresse ne compte
// pas ; un défi expiré ne compte pas.
func TestRevueBornesDesDefis(t *testing.T) {
	ab, err := os.ReadFile(filepath.Join("..", "annuaire", "annuaires", "vide.json"))
	if err != nil {
		t.Skip("vecteurs publiés absents")
	}
	dir := filepath.Join("..", "..", "..", "schemas")
	sch, err := ChargerSchemas(filepath.Join(dir, "annuaire-approbateurs-v0.schema.json"), filepath.Join(dir, "console-approbation-v0.schema.json"), filepath.Join(dir, "console-service-v0.schema.json"), filepath.Join(dir, "evenement-v0.schema.json"), filepath.Join(dir, "ticket-v0.schema.json"), filepath.Join(dir, "politique-approbation-v0.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := ParseJSON(ab)
	e := &EtatAnnuaire{Doc: doc, Sch: sch}
	t0, _ := LireInstant("2026-11-10T12:00:00.000Z")
	n := 0
	preparer := func(identite string, adresse string, at Instant) IssueOperation {
		n++
		req, err := ParseJSON([]byte(`{"session_identity":"oidc https://idp.assureur-demo.example ` + identite + `","address":"` + adresse + `"}`))
		if err != nil {
			t.Fatal(err)
		}
		return e.Appliquer("preparer_inscription", req, at, fmt.Sprintf("%032x", n), func() string { return "" }, ModeService)
	}
	adr := func(i int) string { return fmt.Sprintf("0xabababababababababababababababababab%04d", i) }
	for i := 1; i <= 4; i++ {
		if r := preparer("approbateur-1", adr(i), t0+Instant(i*1000)); !r.Accepte {
			t.Fatalf("défi %d refusé : %s", i, r.Raison)
		}
	}
	avant := len(e.Defis)
	if r := preparer("approbateur-1", adr(5), t0+5000); r.Accepte || r.Raison != "limite_annuaire" {
		t.Errorf("cinquième défi de la même identité : accepté %v, raison %q, attendu limite_annuaire", r.Accepte, r.Raison)
	}
	if len(e.Defis) != avant {
		t.Errorf("défis changés par un refus : %d, puis %d", avant, len(e.Defis))
	}
	if r := preparer("approbateur-1", adr(2), t0+6000); !r.Accepte {
		t.Errorf("remplacement du défi de la même adresse refusé : %s", r.Raison)
	}
	if r := preparer("admin-1", adr(6), t0+7000); !r.Accepte {
		t.Errorf("défi d'une autre identité refusé : %s", r.Raison)
	}
	// Après l'expiration des quatre défis (registration_ttl_ms 600 000), un
	// nouveau est admis.
	if r := preparer("approbateur-1", adr(7), t0+700000); !r.Accepte {
		t.Errorf("défi après expiration des précédents refusé : %s", r.Raison)
	}
	// Borne totale : 1 024 défis non expirés au total.
	e = &EtatAnnuaire{Doc: doc, Sch: sch}
	for i := 0; i < MaxDefisTotalEssai; i++ {
		if r := preparer(fmt.Sprintf("approbateur-%d", 100+i/4), adr(i), t0); !r.Accepte {
			t.Fatalf("défi %d refusé : %s", i, r.Raison)
		}
	}
	if r := preparer("approbateur-99999", adr(9999), t0); r.Accepte || r.Raison != "limite_annuaire" {
		t.Errorf("défi 1 025 : accepté %v, raison %q, attendu limite_annuaire", r.Accepte, r.Raison)
	}
}

// MaxDefisTotalEssai est la borne totale d'EX-13.13, écrite ici depuis le
// texte (1 024).
const MaxDefisTotalEssai = 1024

// CT-9 TA-66 : famille sans valeur, cas retiré, cas non indexé, INDEX.md
// absent : code 1 et l'erreur nommée.
func TestRevuePlancherCT3(t *testing.T) {
	if _, err := os.Stat(filepath.Join("..", "INDEX.md")); err != nil {
		t.Skip("vecteurs publiés absents")
	}
	es, _ := os.ReadDir(filepath.Join("..", "evaluation"))
	retire := es[0].Name()
	enTrop := monterRacineCT3(t, []string{"evaluation"}, nil)
	if err := os.Symlink(filepath.Join(enTrop, "evaluation", retire), filepath.Join(enTrop, "evaluation", "copie-non-indexee.json")); err != nil {
		t.Fatal(err)
	}
	cas := []struct{ nom, racine, message string }{
		{"sans signatures/", monterRacineCT3(t, nil, map[string]bool{"signatures": true}), "plancher (CT-9 TA-66) : famille signatures : aucune valeur recalculée"},
		{"un cas d'evaluation retiré", monterRacineCT3(t, []string{"evaluation"}, map[string]bool{filepath.Join("evaluation", retire): true}), "le cas evaluation/" + retire + " est nommé mais absent de la racine"},
		{"un cas d'evaluation non indexé", enTrop, "le cas evaluation/copie-non-indexee.json est présent mais l'index ne le nomme pas"},
		{"sans INDEX.md", monterRacineCT3(t, nil, map[string]bool{"INDEX.md": true}), "plancher (CT-9 TA-66) : INDEX.md illisible"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			code, sortie := lancerCT3(t, c.racine)
			if code != 1 || !strings.Contains(sortie, c.message) {
				t.Errorf("code %d (attendu 1), message « %s » attendu :\n%s", code, c.message, sortie)
			}
		})
	}
}
