package dossier

// Non-régression des correctifs de la relecture de l'étape 2 : E-3 sur une
// décision voisine, index et points-de-controle.json sans forme canonique,
// A-2 et A-3 indépendantes de A-1, E-9 sur des signatures nulles,
// evenement.json sans forme canonique.

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noorfinances-eng/noortrace/verificateur/commun"
)

const racineCT1 = "../../spec/vecteurs/ct-1/dossiers"

// copier copie un dossier dans un répertoire temporaire.
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

func hexSha(b []byte) string {
	s := sha256.Sum256(b)
	return "0x" + hex.EncodeToString(s[:])
}

// remplacer applique une substitution à une partie (qui doit changer) et
// reporte le nouveau SHA-256 dans l'index.
func remplacer(t *testing.T, rep, fichier, ancien, nouveau string) {
	t.Helper()
	avant, err := os.ReadFile(filepath.Join(rep, fichier))
	if err != nil {
		t.Fatal(err)
	}
	apres := strings.Replace(string(avant), ancien, nouveau, 1)
	if apres == string(avant) {
		t.Fatalf("%s : « %s » introuvable", fichier, ancien)
	}
	if err := os.WriteFile(filepath.Join(rep, fichier), []byte(apres), 0o644); err != nil {
		t.Fatal(err)
	}
	idx, _ := os.ReadFile(filepath.Join(rep, "dossier.json"))
	n := strings.Replace(string(idx), hexSha(avant), hexSha([]byte(apres)), 1)
	if n == string(idx) {
		t.Fatalf("SHA-256 de %s absent de l'index", fichier)
	}
	os.WriteFile(filepath.Join(rep, "dossier.json"), []byte(n), 0o644)
}

// analyser ouvre et analyse un dossier ; un Defaut (code 2) fait échouer le
// test.
func analyser(t *testing.T, rep string) (*Analyse, map[string]commun.Verification) {
	t.Helper()
	d, def := Ouvrir(rep)
	if def != nil {
		t.Fatalf("entrée inutilisable : %s", def.Message.Fr)
	}
	a, def := Analyser(d, Options{})
	if def != nil {
		t.Fatalf("entrée inutilisable : %s", def.Message.Fr)
	}
	m := map[string]commun.Verification{}
	for _, v := range a.Verifs {
		m[v.ID] = v
	}
	return a, m
}

// echecs rend les vérifications en échec, dans l'ordre du rapport.
func echecs(a *Analyse) []string {
	var l []string
	for _, v := range a.Verifs {
		if v.Statut == commun.Echoue {
			l = append(l, v.ID)
		}
	}
	return l
}

func attendre(t *testing.T, m map[string]commun.Verification, id string, st commun.Statut, r commun.Raison) {
	t.Helper()
	v, ok := m[id]
	if !ok {
		t.Errorf("%s ne figure pas", id)
		return
	}
	if v.Statut != st || v.Raison != r {
		t.Errorf("%s : %s %s (%s), attendu %s %s", id, v.Statut, v.Raison, v.Detail.Fr, st, r)
	}
}

// TestE3DecisionVoisine : le voisin précédent est une décision rescellée
// dont arguments.value.decision (refuse) n'est pas approval.decision
// (approuve) : E-3 en échec, et seulement elle (CT-1 §5.1, §11.4 E-3).
func TestE3DecisionVoisine(t *testing.T) {
	a, m := analyser(t, "testdata/e3-voisin-decision")
	if l := echecs(a); strings.Join(l, ",") != "E-3" {
		t.Errorf("échecs %v, attendu [E-3]", l)
	}
	if !strings.Contains(m["E-3"].Detail.Fr, "voisin précédent") || !strings.Contains(m["E-3"].Detail.Fr, "arguments.value") {
		t.Errorf("détail de E-3 : %s", m["E-3"].Detail.Fr)
	}
	// Témoin : la même décision intacte (valide-seq-7) passe E-3.
	_, m = analyser(t, racineCT1+"/valide-seq-7")
	attendre(t, m, "E-3", commun.Reussi, "")
	// Décision jointe dans approbations.json : E-3 la contrôle aussi.
	rep := copier(t, racineCT1+"/valide-seq-7")
	remplacer(t, rep, "approbations.json", `"decision": "approuve",`, `"decision": "refuse",`)
	_, m = analyser(t, rep)
	if v := m["E-3"]; v.Statut != commun.Echoue || !strings.Contains(v.Detail.Fr, "approbation[0]") {
		t.Errorf("décision jointe : E-3 %s (%s)", v.Statut, v.Detail.Fr)
	}
}

// TestIndexSansFormeCanonique : dossier.json est du JSON (pas de code 2,
// EX-4.12), mais sans forme canonique : E-2 en échec ; rien n'est lu de
// l'index, D-1 et tout le reste ne sont pas exécutés (prerequis_en_echec) ;
// jamais un verdict valide (CT-1 §4, §11.4).
func TestIndexSansFormeCanonique(t *testing.T) {
	base := racineCT1 + "/valide-seq-7"
	idx, err := os.ReadFile(filepath.Join(base, "dossier.json"))
	if err != nil {
		t.Fatal(err)
	}
	cas := map[string]string{
		// Premier membre « event » faux, second juste : lu en dernière
		// occurrence, l'index passerait D-1.
		"event en double":     strings.Replace(string(idx), `"event": {`, `"event": {"seq": 99, "hash": "0x`+strings.Repeat("0", 64)+`"}, "event": {`, 1),
		"version 0.0":         strings.Replace(string(idx), `"version": 0`, `"version": 0.0`, 1),
		"substitut isolé":     strings.Replace(string(idx), `"hors périmètre CT-1"`, `"hors périmètre CT-1 \ud800"`, 1),
		"seq hors intervalle": strings.Replace(string(idx), `"seq": 7`, `"seq": 9007199254740993`, 1),
	}
	for nom, contenu := range cas {
		t.Run(nom, func(t *testing.T) {
			if contenu == string(idx) {
				t.Fatal("modification sans effet")
			}
			rep := copier(t, base)
			os.WriteFile(filepath.Join(rep, "dossier.json"), []byte(contenu), 0o644)
			a, m := analyser(t, rep)
			if l := echecs(a); strings.Join(l, ",") != "E-2" {
				t.Errorf("échecs %v, attendu [E-2]", l)
			}
			for _, id := range IDsCT1 {
				if id == "E-2" {
					continue
				}
				attendre(t, m, id, commun.NonExecute, commun.PrerequisEnEchec)
			}
			if a.Evenement != nil || len(a.Dossier.Parties) != 0 {
				t.Error("index sans forme canonique exploité")
			}
		})
	}
}

// TestPointsSansFormeCanonique : points-de-controle.json porte deux membres
// checkpoint_hash (le premier faux) : E-2 en échec, K-1 à K-6 non exécutées
// (prerequis_en_echec), rien n'est lu de la partie (CT-1 §11.4, CT-6
// EX-4.14).
func TestPointsSansFormeCanonique(t *testing.T) {
	base := racineCT1 + "/valide-seq-7-point-de-controle"
	for nom, sub := range map[string][2]string{
		"checkpoint_hash en double": {`"checkpoint_hash": "`, `"checkpoint_hash": "0x` + strings.Repeat("0", 64) + `", "checkpoint_hash": "`},
		"tree_size 8.0":             {`"tree_size": 8,`, `"tree_size": 8.0,`},
	} {
		t.Run(nom, func(t *testing.T) {
			rep := copier(t, base)
			remplacer(t, rep, "points-de-controle.json", sub[0], sub[1])
			a, m := analyser(t, rep)
			if l := echecs(a); strings.Join(l, ",") != "E-2" {
				t.Errorf("échecs %v, attendu [E-2]", l)
			}
			if !strings.Contains(m["E-2"].Detail.Fr, "points-de-controle.json") {
				t.Errorf("détail de E-2 : %s", m["E-2"].Detail.Fr)
			}
			for _, id := range []string{"K-1", "K-2", "K-3", "K-4", "K-5", "K-6"} {
				attendre(t, m, id, commun.NonExecute, commun.PrerequisEnEchec)
			}
			if a.Point == nil || a.Point.K1 || a.Point.V != nil {
				t.Error("point sans forme canonique exploité")
			}
		})
	}
	// Témoin : le dossier d'origine passe E-2 et K-1.
	_, m := analyser(t, base)
	attendre(t, m, "E-2", commun.Reussi, "")
	attendre(t, m, "K-1", commun.Reussi, "")
}

// TestA2A3SansA1 : A-1 en échec pour un ticket différent ; A-2 et A-3 ne
// dépendent pas de A-1 et s'exécutent (CT-1 §11.4, CT-6 EX-5.5, EX-5.16).
// Révision 0.5 de CT-1 (table d'alignement, ligne verificateur/) : sur une
// partie exploitable contraire au schéma de son enveloppe, A-2 et A-3
// s'exécutent aussi, sur les valeurs lues ; ce test figeait jusqu'ici
// l'ancienne lecture (A-2 et A-3 prerequis_en_echec), corrigée ici. Elles
// ne sont pas exécutées quand approbations.json est inexploitable.
func TestA2A3SansA1(t *testing.T) {
	_, m := analyser(t, racineCT1+"/invalide-ticket-approbations")
	attendre(t, m, "A-1", commun.Echoue, "")
	attendre(t, m, "A-2", commun.Reussi, "")
	attendre(t, m, "A-3", commun.Reussi, "")
	// approbations.json contraire au schéma de son enveloppe : A-1 en
	// échec, A-2 et A-3 exécutées sur les valeurs lues.
	rep := copier(t, racineCT1+"/valide-seq-7")
	remplacer(t, rep, "approbations.json", `"version": 0`, `"version": 0, "membre_en_trop": 1`)
	a, m := analyser(t, rep)
	attendre(t, m, "A-1", commun.Echoue, "")
	attendre(t, m, "A-2", commun.Reussi, "")
	attendre(t, m, "A-3", commun.Reussi, "")
	if l := echecs(a); strings.Join(l, ",") != "A-1" {
		t.Errorf("échecs %v, attendu [A-1]", l)
	}
	// approbations.json qui n'est pas un objet (inexploitable, cas (e) de
	// CT-1 §11.4) : A-1 en échec, A-2 et A-3 faute de prérequis.
	rep = copier(t, racineCT1+"/valide-seq-7")
	b, _ := os.ReadFile(filepath.Join(rep, "approbations.json"))
	remplacer(t, rep, "approbations.json", string(b), "[]")
	_, m = analyser(t, rep)
	attendre(t, m, "A-1", commun.Echoue, "")
	attendre(t, m, "A-2", commun.NonExecute, commun.PrerequisEnEchec)
	attendre(t, m, "A-3", commun.NonExecute, commun.PrerequisEnEchec)
	attendre(t, m, "A-4", commun.NonExecute, commun.PieceHorsDossier)
}

// TestE9SignaturesNulles : approval.signatures = null dans le voisin
// précédent (une décision) : E-9 en échec, jamais réussie sur zéro
// signature.
func TestE9SignaturesNulles(t *testing.T) {
	rep := copier(t, racineCT1+"/valide-seq-7")
	b, _ := os.ReadFile(filepath.Join(rep, "voisins.json"))
	s := string(b)
	i := strings.Index(s, `"signatures": [`)
	j := strings.Index(s[i:], "]")
	if i < 0 || j < 0 {
		t.Fatal("signatures introuvables dans voisins.json")
	}
	remplacer(t, rep, "voisins.json", s[i:i+j+1], `"signatures": null`)
	_, m := analyser(t, rep)
	if v := m["E-9"]; v.Statut != commun.Echoue || !strings.Contains(v.Detail.Fr, "voisin précédent") {
		t.Errorf("E-9 : %s (%s)", v.Statut, v.Detail.Fr)
	}
}

// TestEvenementSansFormeCanonique : evenement.json porte duration_ms =
// 530.0 (vecteur CT-1 invalide-nombre-non-entier) : E-2 en échec ; les
// vérifications qui dépendent de l'événement prouvé ne sont pas exécutées
// (CT-1 §11.4), et rien n'en est repris.
func TestEvenementSansFormeCanonique(t *testing.T) {
	a, m := analyser(t, racineCT1+"/invalide-nombre-non-entier")
	if l := echecs(a); strings.Join(l, ",") != "E-2" {
		t.Errorf("échecs %v, attendu [E-2]", l)
	}
	if a.Evenement != nil {
		t.Error("événement sans forme canonique exploité")
	}
	for _, id := range []string{"E-1", "E-3", "E-4", "E-5", "E-6", "E-7", "E-8", "E-9", "E-10", "E-11", "C-1", "C-2", "C-3", "M-1", "M-3", "P-1", "P-2", "P-5", "A-1", "A-2", "A-3", "A-4"} {
		attendre(t, m, id, commun.NonExecute, commun.PrerequisEnEchec)
	}
}
