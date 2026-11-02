package schema

import (
	"bytes"
	"os"
	"regexp"
	"testing"

	"github.com/noorfinances-eng/noortrace/verificateur/jsonv"
)

// TestCopiesConformes : les schémas embarqués sont des copies octet pour
// octet de spec/schemas (le binaire n'en lit aucun sur le disque, EX-8.1).
func TestCopiesConformes(t *testing.T) {
	liste, err := Liste()
	if err != nil {
		t.Fatal(err)
	}
	if len(liste) != 10 {
		t.Fatalf("%d schémas embarqués, 10 attendus (EX-8.11)", len(liste))
	}
	for _, s := range liste {
		emb, _ := Octets(s.Fichier)
		ref, err := os.ReadFile("../../spec/schemas/" + s.Fichier)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(emb, ref) {
			t.Errorf("%s diffère de spec/schemas", s.Fichier)
		}
	}
	// Ordre et empreintes de l'exemple de CT-6 §8.6.
	attendus := []string{
		"0xcd2efffae72ebe2d00459ac643785415ad25d138325681aca6127a0a2fa0393f",
		"0x1341dd18b1cc4b570c13ed4010228b13b78d1582292ea7ecba0ce1ac7a462bf2",
		"0x124933825aae2b39e473ff186c1eefdd40dd3ba25fcc3519468b0341f544b63f",
		"0x7c40a7edba0d099f71506ea67e790b5d05f5a4f82113156ae9c83baffb4f69f2",
		"0xbe912c582c9f580cc21fe0144d370c36e94739dcd060d6d1b7b6f28b2d7ec86d",
		"0x5944ff946b06d718d0741b149d7cc43b1fb5793b4df005497ccfb65861c21e54",
		"0x233e7ee41d597119c9319382eacc673f316fe891f8e271cc1032a183972825fd",
		"0x1ab686a61d7dad8ea8e1d26b69e750e414b19e819f9a3516cb1d7c737c807d04",
		"0x77e991e484add0e308291578d8576c28a4264b5d2b2ae2c06b6832b470b6308c",
		"0xbe8494a287d2185390beb1a0515d157a53e295289342fbc127b362ce60d06019",
	}
	for i, s := range liste {
		if s.Sha256 != attendus[i] {
			t.Errorf("%s : SHA-256 %s, attendu %s", s.Fichier, s.Sha256, attendus[i])
		}
	}
}

// TestMotifs : chaque motif des schémas embarqués se compile après
// traduction.
func TestMotifs(t *testing.T) {
	liste, _ := Liste()
	n := 0
	var parcourir func(v *jsonv.Valeur)
	parcourir = func(v *jsonv.Valeur) {
		if v == nil {
			return
		}
		for _, m := range v.Membres {
			if m.Nom == "pattern" && m.Valeur.EstChaine() {
				if _, err := motif(m.Valeur.Chaine); err != nil {
					t.Errorf("motif %q : %v", m.Valeur.Chaine, err)
				}
				n++
			}
			parcourir(m.Valeur)
		}
		for _, e := range v.Elements {
			parcourir(e)
		}
	}
	for _, s := range liste {
		parcourir(s.racine)
	}
	if n == 0 {
		t.Fatal("aucun motif")
	}
}

func TestTraduireMotif(t *testing.T) {
	q := traduireMotif(`^/[^\u0000]{1,4095}$`)
	re := regexp.MustCompile(q)
	long := "/" + string(bytes.Repeat([]byte("a"), 4095))
	if !re.MatchString(long) || re.MatchString(long+"a") || re.MatchString("/") || re.MatchString("/a\x00") {
		t.Errorf("traduction incorrecte : %s", q)
	}
}

func TestValidation(t *testing.T) {
	man := `{"version":0,"org_id":"0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab","journal_id":"0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b","period_start":1793710800,"period_end":1793714400,"first_seq":1,"last_seq":5,"count":5,"root":"0x6782bad9bd4717caf61b261a0a7f86fa9263f4b5b76c1d80d4c3bfbe0512ed06","prev_period_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","recorder_key_id":"rec-test-02","nonce":"0xcfcd0a8277074d0839e4469fdced701c0fdf2855f1001e17d3fada335da05547","generated_at":"2026-11-03T14:00:00.250Z"}`
	v, err := jsonv.Analyser([]byte(man))
	if err != nil {
		t.Fatal(err)
	}
	if err := Valider(Manifeste, v); err != nil {
		t.Errorf("manifeste de CT-1 §10.1 refusé : %v", err)
	}
	for nom, mauvais := range map[string]string{
		"membre en trop":       `"extra":1`,
		"période non alignée":  `"period_start":1793710801`,
		"version 1 (EX-14.11)": `"version":1`,
		"majuscules":           `"root":"0x6782BAD9bd4717caf61b261a0a7f86fa9263f4b5b76c1d80d4c3bfbe0512ed06"`,
	} {
		// Le membre ajouté en dernier l'emporte (dernière occurrence).
		w, _ := jsonv.Analyser([]byte(man[:len(man)-1] + "," + mauvais + "}"))
		if Valider(Manifeste, w) == nil {
			t.Errorf("%s : accepté", nom)
		}
	}
}
