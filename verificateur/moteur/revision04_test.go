package moteur

// Règles de CT-6 révision 0.4 et de CT-1 révision 0.5 rejouées de bout en
// bout sur des dossiers dérivés des vecteurs : EX-4.12 (second manifeste),
// EX-4.16 (codage, profondeur, forme canonique), EX-5.15 (événement prouvé
// inexploitable avec les parties réservées), EX-6.22 (désignation membre
// par membre). Chaque règle a un cas en réussite et un cas en échec.

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noorfinances-eng/noortrace/verificateur/commun"
)

const (
	completCT6  = racineCT6 + "/valide-seq-7-complet"
	ancresTest6 = "../../spec/vecteurs/ct-6/ancres/ancres-test.json"
	entetesTest = "../../spec/vecteurs/ct-6/ots/entetes/chaine.json"
)

func lancerComplet(t *testing.T, rep string, exiger ...int) *Resultat {
	t.Helper()
	res := Verifier(Options{Repertoire: rep, Ancres: ancresTest6, Entetes: entetesTest, Langue: "fr", Version: "0.0.0", Exiger: exiger})
	rapportConforme(t, res, "fr")
	return res
}

// TestEX412SecondManifeste : un second manifeste qui est du JSON sans forme
// canonique rend l'entrée inutilisable (code 2, entree_illisible), et non
// P-5 en échec ; un second manifeste conforme est lu.
func TestEX412SecondManifeste(t *testing.T) {
	base := racineCT1 + "/valide-seq-7"
	man, err := os.ReadFile(filepath.Join(base, "manifeste.json"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	conforme := filepath.Join(dir, "conforme.json")
	os.WriteFile(conforme, man, 0o644)
	res := Verifier(Options{Repertoire: base, SecondManifeste: conforme, Langue: "fr", Version: "0.0.0"})
	if res.Code == 2 {
		t.Fatalf("second manifeste conforme refusé : %s", res.Erreur.Message.Fr)
	}
	for nom, c := range map[string]string{
		"nom en double":   strings.Replace(string(man), `"version": 0`, `"version": 0, "version": 0`, 1),
		"nombre 0.0":      strings.Replace(string(man), `"version": 0`, `"version": 0.0`, 1),
		"substitut isolé": strings.Replace(string(man), `"version": 0`, `"version": 0, "x": "\ud800"`, 1),
	} {
		f := filepath.Join(dir, "second.json")
		os.WriteFile(f, []byte(c), 0o644)
		res := Verifier(Options{Repertoire: base, SecondManifeste: f, Langue: "fr", Version: "0.0.0"})
		if res.Code != 2 || res.Erreur.Genre != "entree_illisible" || res.Erreur.Verification != "" {
			t.Errorf("%s : code %d %+v", nom, res.Code, res.Erreur)
		}
	}
}

// TestEX416Codage : marque d'ordre d'octets et UTF-8 mal formé : pas du
// JSON, E-1 en échec ; substitut écrit en octets (ED A0 80, CESU-8) : défaut
// de forme canonique, E-2 en échec et E-1 non exécutée (EX-4.16, point 1 ;
// CT-1 §3, révision 0.5).
func TestEX416Codage(t *testing.T) {
	base := racineCT1 + "/valide-seq-7"
	ev, _ := os.ReadFile(filepath.Join(base, "evenement.json"))
	cas := []struct {
		nom          string
		contenu      []byte
		echec, nonEx string
	}{
		{"marque d'ordre d'octets", append([]byte{0xEF, 0xBB, 0xBF}, ev...), "E-1", "E-2"},
		{"UTF-8 mal formé", []byte(strings.Replace(string(ev), "Régler", "R\xffgler", 1)), "E-1", "E-2"},
		{"substitut en octets (CESU-8)", []byte(strings.Replace(string(ev), "Régler", "R\xed\xa0\x80gler", 1)), "E-2", "E-1"},
		{"paire de substituts en octets", []byte(strings.Replace(string(ev), "Régler", "R\xed\xa0\xbd\xed\xb8\x80gler", 1)), "E-2", "E-1"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			if string(c.contenu) == string(ev) {
				t.Fatal("modification sans effet")
			}
			rep := copier(t, base)
			remplacer(t, rep, "evenement.json", c.contenu)
			res := lancer(t, rep)
			v := verifs(res)
			if res.Code != 1 || strings.Join(res.Rapport.FailedChecks, ",") != c.echec || v[c.nonEx].Raison != commun.PrerequisEnEchec {
				t.Errorf("code %d, échecs %v, %s %s %s", res.Code, res.Rapport.FailedChecks, c.nonEx, v[c.nonEx].Statut, v[c.nonEx].Raison)
			}
			if res.Rapport.Event != nil || res.Rapport.OrgID != nil {
				t.Error("événement inexploitable désigné")
			}
		})
	}
}

// TestEX416Profondeur : profondeur comptée sur les conteneurs, la racine
// comprise (EX-4.16, point 3 ; CT-1 §4, règle 7) : 128 admise, 129 refusée
// (partie inexploitable, E-1 en échec). Le binaire refusait 128 conteneurs
// imbriqués dont le dernier n'est pas vide.
func TestEX416Profondeur(t *testing.T) {
	base := racineCT1 + "/valide-seq-7"
	ev, _ := os.ReadFile(filepath.Join(base, "evenement.json"))
	// La racine (1) et un membre d'intent : intent = n − 1 tableaux
	// imbriqués, le dernier portant un scalaire.
	avec := func(n int) []byte {
		v := strings.Repeat("[", n-1) + "1" + strings.Repeat("]", n-1)
		s := strings.Replace(string(ev), `"intent": "`, `"intent_essai": `+v+`, "intent": "`, 1)
		if s == string(ev) {
			t.Fatal("intent introuvable")
		}
		return []byte(s)
	}
	for _, c := range []struct {
		n     int
		e1    commun.Statut
		echec bool
	}{{128, commun.Echoue, false}, {129, commun.Echoue, true}} {
		rep := copier(t, base)
		remplacer(t, rep, "evenement.json", avec(c.n))
		res := lancer(t, rep)
		v := verifs(res)
		// À 128, la partie est lue : E-1 échoue sur le membre en trop (schéma)
		// et E-7 s'exécute (hachage recalculé, différent) ; à 129, la
		// partie n'est pas du JSON : E-1 échoue et E-7 n'est pas exécutée.
		if c.echec != (v["E-7"].Raison == commun.PrerequisEnEchec) || v["E-1"].Statut != c.e1 {
			t.Errorf("profondeur %d : E-1 %s, E-7 %s %s", c.n, v["E-1"].Statut, v["E-7"].Statut, v["E-7"].Raison)
		}
		if !c.echec && (res.Rapport.Event == nil || v["E-7"].Statut != commun.Echoue) {
			t.Errorf("profondeur %d : événement non lu", c.n)
		}
	}
}

// TestEX515EvenementInexploitable : evenement.json inexploitable dans un
// dossier qui porte les parties réservées (EX-5.15, EX-A.24) : P-1, T-2,
// O-2, R-9, R-10 non exécutées, contrôles 4, 5 et 8 non exécutés
// (prerequis_en_echec), N-4 absente, D-1 non exécutée, désignation nulle.
func TestEX515EvenementInexploitable(t *testing.T) {
	cas := []struct {
		nom      string
		prep     func(t *testing.T, rep string)
		echec    string
		ctrl1    commun.Statut
		attendus []string
	}{
		{"littéral null", func(t *testing.T, rep string) { remplacer(t, rep, "evenement.json", []byte("null")) }, "E-1", commun.Echoue,
			[]string{"D-1", "P-1", "T-2", "O-2", "R-9", "R-10"}},
		{"retiré du répertoire", func(t *testing.T, rep string) { os.Remove(filepath.Join(rep, "evenement.json")) }, "D-2", commun.NonExecute,
			[]string{"D-1", "E-1", "P-1", "T-2", "O-2", "R-9", "R-10"}},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			rep := copier(t, completCT6)
			c.prep(t, rep)
			res := lancerComplet(t, rep)
			v := verifs(res)
			if res.Code != 1 || strings.Join(res.Rapport.FailedChecks, ",") != c.echec {
				t.Errorf("code %d, échecs %v", res.Code, res.Rapport.FailedChecks)
			}
			if res.Controles[1].Statut != c.ctrl1 {
				t.Errorf("contrôle 1 %s", res.Controles[1].Statut)
			}
			for n := 2; n <= 8; n++ {
				if res.Controles[n].Statut != commun.NonExecute || res.Controles[n].Raison != commun.PrerequisEnEchec {
					t.Errorf("contrôle %d : %s %s", n, res.Controles[n].Statut, res.Controles[n].Raison)
				}
			}
			for _, id := range c.attendus {
				if v[id].Statut != commun.NonExecute || v[id].Raison != commun.PrerequisEnEchec {
					t.Errorf("%s : %s %s", id, v[id].Statut, v[id].Raison)
				}
			}
			if _, ok := v["N-4"]; ok {
				t.Error("N-4 figure")
			}
			r := res.Rapport
			if r.Event != nil || r.OrgID != nil || r.JournalID != nil {
				t.Error("événement inexploitable désigné")
			}
		})
	}
	// Témoin : le dossier complet est valide.
	if res := lancerComplet(t, completCT6); res.Code != 0 {
		t.Errorf("témoin : code %d", res.Code)
	}
}

// TestEX622Designation : event, org_id et journal_id jugés chacun à part
// (EX-6.22) : un org_id hors format n'annule ni journal_id ni event ; un
// execution.tool qui n'est pas une chaîne annule event.tool seul ; un ts à
// date inexistante annule event seul.
func TestEX622Designation(t *testing.T) {
	base := racineCT1 + "/valide-seq-7"
	ev, _ := os.ReadFile(filepath.Join(base, "evenement.json"))
	res := lancer(t, base)
	r := res.Rapport
	if r.Event == nil || r.Event.Tool == nil || r.OrgID == nil || r.JournalID == nil {
		t.Fatal("témoin : désignation incomplète")
	}
	cas := []struct {
		nom                       string
		sub                       [2]string
		event, tool, org, journal bool
	}{
		{"org_id en majuscules", [2]string{`"org_id": "0xa581bb`, `"org_id": "0xA581BB`}, true, true, false, true},
		{"execution.tool nombre", [2]string{`"tool": "sap.payments.create"`, `"tool": 5`}, true, false, true, true},
		{"ts à date inexistante", [2]string{`"ts": "2026-11-05T09:31:48.006Z"`, `"ts": "2026-02-30T09:31:48.006Z"`}, false, false, true, true},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			s := strings.Replace(string(ev), c.sub[0], c.sub[1], 1)
			if s == string(ev) {
				t.Fatal("modification sans effet")
			}
			rep := copier(t, base)
			remplacer(t, rep, "evenement.json", []byte(s))
			r := lancer(t, rep).Rapport
			if (r.Event != nil) != c.event || (r.Event != nil && (r.Event.Tool != nil) != c.tool) || (r.OrgID != nil) != c.org || (r.JournalID != nil) != c.journal {
				t.Errorf("event %v, org_id %v, journal_id %v", r.Event, r.OrgID, r.JournalID)
			}
		})
	}
}

// TestE3AppelSansApprobation : la faille de E-3 de bout en bout : l'appel
// relayé seq 7, rendu « a_approuver » exécuté sans approbation (approval
// nul, approbations.json déclaré absent avec sa raison), met E-3 en échec ;
// le dossier n'est jamais valide pour ce seul motif.
func TestE3AppelSansApprobation(t *testing.T) {
	base := racineCT1 + "/valide-seq-7"
	ev, _ := os.ReadFile(filepath.Join(base, "evenement.json"))
	s := string(ev)
	i := strings.Index(s, `"approval": {`)
	j := strings.Index(s, `"execution": {`)
	if i < 0 || j < 0 {
		t.Fatal("approval introuvable")
	}
	s = s[:i] + `"approval": null,` + "\n  " + s[j:]
	rep := copier(t, base)
	remplacer(t, rep, "evenement.json", []byte(s))
	idx, _ := os.ReadFile(filepath.Join(rep, "dossier.json"))
	ap, _ := os.ReadFile(filepath.Join(rep, "approbations.json"))
	os.Remove(filepath.Join(rep, "approbations.json"))
	h := sha256Hex(ap)
	n := strings.Replace(string(idx), `"sha256": "`+h+`",
      "present": true,
      "reason_if_absent": null`, `"sha256": null,
      "present": false,
      "reason_if_absent": "aucune approbation liée"`, 1)
	if n == string(idx) {
		t.Fatal("ligne approbations de l'index introuvable")
	}
	os.WriteFile(filepath.Join(rep, "dossier.json"), []byte(n), 0o644)
	res := lancer(t, rep)
	v := verifs(res)
	if v["E-3"].Statut != commun.Echoue || !strings.Contains(v["E-3"].Detail.Fr, "appel exécuté sans policy.decision = autorise") || res.Code != 1 {
		t.Errorf("E-3 %s (%s), code %d", v["E-3"].Statut, v["E-3"].Detail.Fr, res.Code)
	}
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return "0x" + hex.EncodeToString(s[:])
}

// TestEX411PartieReserveeAbsente : partie réservée déclarée présente mais
// absente du répertoire (EX-4.11, point 1) : D-2 seule en échec ; T-1
// (R-1) non exécutée, prerequis_en_echec ; contrôle 4 (8) non exécuté,
// prerequis_en_echec, et non echoue. Le binaire était déjà conforme.
func TestEX411PartieReserveeAbsente(t *testing.T) {
	for _, c := range []struct {
		fichier, id string
		controle    int
	}{{"jeton-rfc3161.der", "T-1", 4}, {"registre.json", "R-1", 8}, {"preuve.ots", "O-1", 5}} {
		rep := copier(t, completCT6)
		os.Remove(filepath.Join(rep, c.fichier))
		res := lancerComplet(t, rep)
		v := verifs(res)
		if res.Code != 1 || strings.Join(res.Rapport.FailedChecks, ",") != "D-2" || v[c.id].Raison != commun.PrerequisEnEchec ||
			res.Controles[c.controle].Statut != commun.NonExecute || res.Controles[c.controle].Raison != commun.PrerequisEnEchec {
			t.Errorf("%s : code %d, échecs %v, %s %s, contrôle %d %s", c.fichier, res.Code, res.Rapport.FailedChecks, c.id, v[c.id].Raison, c.controle, res.Controles[c.controle].Statut)
		}
	}
}

// TestEX924DeBoutEnBout : jeton dont l'OID de signatureAlgorithm est
// remplacé par un identifiant inconnu (non signé), sous la clé RSA de
// l'unité, et dont la signature est altérée : T-5 en échec, code 1, avec ou
// sans --exiger 4 (EX-9.24, cas 1 ; essai d'EX-A.22). La version 0.3 rendait
// le code 0.
func TestEX924DeBoutEnBout(t *testing.T) {
	rep := copier(t, completCT6)
	j, _ := os.ReadFile(filepath.Join(rep, "jeton-rfc3161.der"))
	// sha256WithRSAEncryption (2a 86 48 86 f7 0d 01 01 0b) de SignerInfo,
	// la dernière occurrence ; 1.2.840.113549.1.1.127 s'écrit …01 01 7f.
	ancien := []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b}
	i := strings.LastIndex(string(j), string(ancien))
	if i < 0 {
		t.Fatal("OID introuvable")
	}
	n := append([]byte{}, j...)
	n[i+8] = 0x7f
	n[len(n)-1] ^= 0xff
	remplacer(t, rep, "jeton-rfc3161.der", n)
	for _, ex := range [][]int{nil, {4}} {
		res := lancerComplet(t, rep, ex...)
		if res.Code != 1 || strings.Join(res.Rapport.FailedChecks, ",") != "T-5" || res.Controles[4].Statut != commun.Echoue {
			t.Errorf("--exiger %v : code %d, échecs %v", ex, res.Code, res.Rapport.FailedChecks)
		}
	}
}

// TestEX910DeBoutEnBout : jeton de valide-seq-7-complet dont le numéro de
// série du sid (non signé) est remplacé (0x02 → 0x7f, octet 1469, essai
// d'annexe B.7) : T-4 en échec, T-5 à T-11 prerequis_en_echec, contrôle 4
// en échec, code 1, avec ou sans fichier d'ancres (le jeton porte des
// certificats). La version 0.3 rendait ancre_absente et le code 0.
func TestEX910DeBoutEnBout(t *testing.T) {
	rep := copier(t, completCT6)
	j, _ := os.ReadFile(filepath.Join(rep, "jeton-rfc3161.der"))
	if j[1468] != 0x01 || j[1469] != 0x02 {
		t.Fatal("octet du sid introuvable")
	}
	n := append([]byte{}, j...)
	n[1469] = 0x7f
	remplacer(t, rep, "jeton-rfc3161.der", n)
	for _, avecAncres := range []bool{true, false} {
		o := Options{Repertoire: rep, Entetes: entetesTest, Langue: "fr", Version: "0.0.0"}
		if avecAncres {
			o.Ancres = ancresTest6
		}
		res := Verifier(o)
		rapportConforme(t, res, "fr")
		v := verifs(res)
		if res.Code != 1 || strings.Join(res.Rapport.FailedChecks, ",") != "T-4" || res.Controles[4].Statut != commun.Echoue {
			t.Errorf("ancres %v : code %d, échecs %v, contrôle 4 %s", avecAncres, res.Code, res.Rapport.FailedChecks, res.Controles[4].Statut)
		}
		for _, id := range []string{"T-5", "T-6", "T-7", "T-8", "T-9", "T-10", "T-11"} {
			if v[id].Raison != commun.PrerequisEnEchec {
				t.Errorf("ancres %v : %s %s %s", avecAncres, id, v[id].Statut, v[id].Raison)
			}
		}
	}
}

// TestDecisionPoint16 : partie réservée au-delà de sa limite (EX-4.11,
// point 2) : la vérification qui la porte échoue (T-1, O-1, R-1), D-2 ne
// compare pas son SHA-256.
func TestDecisionPoint16(t *testing.T) {
	for _, c := range []struct {
		fichier, id string
		taille      int
	}{{"jeton-rfc3161.der", "T-1", 64*1024 + 1}, {"preuve.ots", "O-1", 256*1024 + 1}} {
		rep := copier(t, completCT6)
		ancien, _ := os.ReadFile(filepath.Join(rep, c.fichier))
		gros := append(append([]byte{}, ancien...), make([]byte, c.taille)...)
		remplacer(t, rep, c.fichier, gros)
		res := lancerComplet(t, rep)
		if strings.Join(res.Rapport.FailedChecks, ",") != c.id {
			t.Errorf("%s : échecs %v", c.fichier, res.Rapport.FailedChecks)
		}
	}
}
