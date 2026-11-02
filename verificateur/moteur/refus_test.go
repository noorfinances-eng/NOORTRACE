package moteur

// Refus : entrées hostiles, tailles, profondeur, versions (CT-6 §4.5,
// EX-14.11, §15).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/entree"
)

// copier copie un dossier de vecteurs dans un répertoire temporaire.
func copier(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	ents, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

// remplacer réécrit une partie et met à jour son SHA-256 dans l'index.
func remplacer(t *testing.T, rep, fichier string, contenu []byte) {
	t.Helper()
	ancien, err := os.ReadFile(filepath.Join(rep, fichier))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rep, fichier), contenu, 0o644); err != nil {
		t.Fatal(err)
	}
	reindexer(t, rep, ancien, contenu)
}

func reindexer(t *testing.T, rep string, ancien, nouveau []byte) {
	t.Helper()
	a, n := sha256.Sum256(ancien), sha256.Sum256(nouveau)
	idx, _ := os.ReadFile(filepath.Join(rep, "dossier.json"))
	s := strings.Replace(string(idx), "0x"+hex.EncodeToString(a[:]), "0x"+hex.EncodeToString(n[:]), 1)
	os.WriteFile(filepath.Join(rep, "dossier.json"), []byte(s), 0o644)
}

func verifs(res *Resultat) map[string]commun.Verification {
	m := map[string]commun.Verification{}
	for _, v := range res.Verifs {
		m[v.ID] = v
	}
	return m
}

func lancer(t *testing.T, rep string) *Resultat {
	t.Helper()
	res := Verifier(Options{Repertoire: rep, Langue: "fr", Version: "0.0.0"})
	rapportConforme(t, res, "fr")
	return res
}

func TestRefusIndex(t *testing.T) {
	// dossier.json absent, pas du JSON : code 2 (EX-4.12).
	vide := t.TempDir()
	if res := lancer(t, vide); res.Code != 2 || res.Erreur.Genre != "dossier_illisible" {
		t.Errorf("dossier.json absent : %+v", res.Erreur)
	}
	os.WriteFile(filepath.Join(vide, "dossier.json"), []byte("{"), 0o644)
	if res := lancer(t, vide); res.Code != 2 || res.Erreur.Genre != "dossier_illisible" {
		t.Errorf("dossier.json illisible : %+v", res.Erreur)
	}
	if res := lancer(t, filepath.Join(vide, "inexistant")); res.Code != 2 || res.Erreur.Genre != "dossier_illisible" {
		t.Errorf("répertoire inexistant : %+v", res.Erreur)
	}
	// Index d'une autre version : D-1 en échec, code 1 (EX-14.11).
	rep := copier(t, racineCT1+"/valide-seq-7")
	idx, _ := os.ReadFile(filepath.Join(rep, "dossier.json"))
	os.WriteFile(filepath.Join(rep, "dossier.json"), []byte(strings.Replace(string(idx), `"version": 0`, `"version": 1`, 1)), 0o644)
	res := lancer(t, rep)
	v := verifs(res)
	if res.Code != 1 || v["D-1"].Statut != commun.Echoue || v["E-1"].Raison != commun.PrerequisEnEchec {
		t.Errorf("index version 1 : code %d, D-1 %s", res.Code, v["D-1"].Statut)
	}
	// Index sans forme canonique (membre « event » en double, version 0.0) :
	// du JSON, donc pas de code 2 ; E-2 en échec, D-1 et le reste non
	// exécutés, rapport conforme à son schéma, jamais valide (CT-1 §4,
	// §11.4 ; LISEZMOI.md, « Lectures », point 20).
	for _, c := range []string{
		strings.Replace(string(idx), `"event": {`, `"event": {"seq": 99, "hash": "0x`+strings.Repeat("0", 64)+`"}, "event": {`, 1),
		strings.Replace(string(idx), `"version": 0`, `"version": 0.0`, 1),
	} {
		rep = copier(t, racineCT1+"/valide-seq-7")
		os.WriteFile(filepath.Join(rep, "dossier.json"), []byte(c), 0o644)
		res = lancer(t, rep)
		v = verifs(res)
		if res.Code != 1 || v["E-2"].Statut != commun.Echoue || v["D-1"].Raison != commun.PrerequisEnEchec || len(res.Rapport.FailedChecks) != 1 {
			t.Errorf("index sans forme canonique : code %d, E-2 %s, D-1 %s %s", res.Code, v["E-2"].Statut, v["D-1"].Statut, v["D-1"].Raison)
		}
	}
	// Index de plus de 1 Mio : inexploitable, D-1 en échec (EX-4.11).
	rep = copier(t, racineCT1+"/valide-seq-7")
	os.WriteFile(filepath.Join(rep, "dossier.json"), append(idx, []byte(strings.Repeat(" ", entree.LimiteIndex))...), 0o644)
	res = lancer(t, rep)
	if v := verifs(res); res.Code != 1 || v["D-1"].Statut != commun.Echoue {
		t.Errorf("index de plus de 1 Mio : code %d", res.Code)
	}
}

func TestRefusParties(t *testing.T) {
	base := racineCT1 + "/valide-seq-7"
	ev, _ := os.ReadFile(filepath.Join(base, "evenement.json"))
	// Événement d'une autre version : E-1 en échec (EX-14.11).
	rep := copier(t, base)
	remplacer(t, rep, "evenement.json", []byte(strings.Replace(string(ev), `"version": 0`, `"version": 1`, 1)))
	res := lancer(t, rep)
	if v := verifs(res); res.Code != 1 || v["E-1"].Statut != commun.Echoue || v["D-2"].Statut != commun.Reussi {
		t.Errorf("événement version 1 : code %d, E-1 %s", res.Code, v["E-1"].Statut)
	}
	// Imbrication de plus de 128 niveaux : pas du JSON exploitable.
	rep = copier(t, base)
	profond := strings.Replace(string(ev), `"intent": null`, `"intent": `+strings.Repeat("[", 200)+strings.Repeat("]", 200), 1)
	if profond == string(ev) {
		profond = strings.Replace(string(ev), `"effects": [`, `"effects": [`+strings.Repeat("[", 200)+strings.Repeat("]", 200)+",", 1)
	}
	remplacer(t, rep, "evenement.json", []byte(profond))
	res = lancer(t, rep)
	if v := verifs(res); res.Code != 1 || v["E-1"].Statut != commun.Echoue || v["E-7"].Raison != commun.PrerequisEnEchec {
		t.Errorf("profondeur 200 : code %d, E-1 %s, E-7 %s", res.Code, v["E-1"].Statut, v["E-7"].Raison)
	}
	// Partie de plus de 16 Mio : inexploitable (EX-4.11, EX-4.13).
	rep = copier(t, base)
	gros := append(append([]byte{}, ev...), []byte(strings.Repeat(" ", entree.LimitePartieCT1))...)
	os.WriteFile(filepath.Join(rep, "evenement.json"), gros, 0o644)
	res = lancer(t, rep)
	if v := verifs(res); res.Code != 1 || v["E-1"].Statut != commun.Echoue {
		t.Errorf("partie de plus de 16 Mio : code %d, E-1 %s", res.Code, v["E-1"].Statut)
	}
	// Partie déclarée présente mais absente du répertoire : D-2 (CT-1).
	rep = copier(t, base)
	os.Remove(filepath.Join(rep, "chemin.json"))
	res = lancer(t, rep)
	if v := verifs(res); res.Code != 1 || v["D-2"].Statut != commun.Echoue || v["M-2"].Raison != commun.PrerequisEnEchec {
		t.Errorf("partie absente du répertoire : code %d", res.Code)
	}
	// Fichier non déclaré : ignoré (EX-4.1).
	rep = copier(t, base)
	os.WriteFile(filepath.Join(rep, "ancres.json"), []byte("{"), 0o644)
	if res := lancer(t, rep); res.Code != 0 {
		t.Errorf("fichier non déclaré : code %d", res.Code)
	}
}

func TestRefusAttestation(t *testing.T) {
	base := racineCT1 + "/valide-seq-7-attestation-sans-inscription"
	// Plus de 4 Mio : AT-1 en échec, sans effet sur le verdict (EX-4.15,
	// EX-5.11), SHA-256 calculé en flux par D-2.
	rep := copier(t, base)
	at, _ := os.ReadFile(filepath.Join(rep, "attestation-perimetre.json"))
	gros := append(append([]byte{}, at...), []byte(strings.Repeat(" ", entree.LimiteAttestation))...)
	remplacer(t, rep, "attestation-perimetre.json", gros)
	res := lancer(t, rep)
	v := verifs(res)
	if res.Code != 0 || v["AT-1"].Statut != commun.Echoue || v["D-2"].Statut != commun.Reussi {
		t.Errorf("attestation de plus de 4 Mio : code %d, AT-1 %s, D-2 %s", res.Code, v["AT-1"].Statut, v["D-2"].Statut)
	}
	if len(res.Avertissements) == 0 || res.Avertissements[0].ID != "AV-AT-1" {
		t.Errorf("AV-AT-1 attendu : %+v", res.Avertissements)
	}
	// Plus de 64 Mio : entrée inutilisable (EX-4.15).
	rep = copier(t, base)
	f, _ := os.OpenFile(filepath.Join(rep, "attestation-perimetre.json"), os.O_WRONLY, 0)
	f.Truncate(entree.PlafondAttestation + 1)
	f.Close()
	if res := lancer(t, rep); res.Code != 2 || res.Erreur.Genre != "taille_depassee" {
		t.Errorf("attestation de plus de 64 Mio : code %d", res.Code)
	}
}

// TestIsolement : une panique devient une erreur interne, code 2 (EX-15.2).
func TestIsolement(t *testing.T) {
	e := isoler("un essai", func() { panic("panique d'essai") })
	if e == nil || e.Genre != "erreur_interne" || !strings.Contains(e.Message.Fr, "panique d'essai") {
		t.Errorf("panique non rattrapée : %+v", e)
	}
	if isoler("un essai", func() {}) != nil {
		t.Error("étape sans panique rendue en erreur")
	}
}

// TestDeterminisme : deux exécutions donnent le même rapport (V-8) et ne
// dépendent ni de l'horloge ni de l'environnement (EX-3.2, EX-8.3).
func TestDeterminisme(t *testing.T) {
	rep := racineCT1 + "/valide-seq-12-attestation-inscrite"
	a := lancer(t, rep)
	t.Setenv("LANG", "C")
	t.Setenv("TZ", "Pacific/Kiritimati")
	b := lancer(t, rep)
	ja, _ := json.Marshal(a.Rapport)
	jb, _ := json.Marshal(b.Rapport)
	if string(ja) != string(jb) {
		t.Error("deux rapports différents")
	}
}
