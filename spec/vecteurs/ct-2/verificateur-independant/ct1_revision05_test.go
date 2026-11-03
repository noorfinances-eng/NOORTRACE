// Copié du vérificateur indépendant CT-1 (revision05_test.go) ; seule
// adaptation : les vecteurs de CT-1 sont lus dans ../../ct-1.

package main

// Tests de la révision 0.5 de CT-1 (règles tranchées dans le texte, section
// 17, ligne de ce vérificateur dans la table d'alignement) : pour chaque
// règle, un cas en réussite et un cas en échec. Les dossiers sont des copies
// altérées du dossier de référence (testdata/reference/dossier-seq-4) ou des
// dossiers publiés (../dossiers), index recalculé quand le cas le demande.

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// supprimer, rendu par une altération, retire le fichier du dossier copié.
const supprimer = "\x00supprimer"

// copierDossier copie un dossier (fichiers du premier niveau), applique les
// altérations (contenu → contenu modifié, ou supprimer) et, si demandé,
// recalcule dans l'index le SHA-256 des fichiers altérés.
func copierDossier(t *testing.T, src string, alterations map[string]func(string) string, reindexer bool) string {
	t.Helper()
	if !fichierExiste(filepath.Join(src, "dossier.json")) {
		t.Skipf("dossier %s absent", src)
	}
	dst := t.TempDir()
	entrees, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entrees {
		if e.IsDir() || e.Name() == "attendu.json" {
			continue
		}
		octets, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		contenu := string(octets)
		if f, ok := alterations[e.Name()]; ok {
			contenu = f(contenu)
		}
		if contenu == supprimer {
			continue
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), []byte(contenu), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if !reindexer {
		return dst
	}
	index, err := os.ReadFile(filepath.Join(dst, "dossier.json"))
	if err != nil {
		return dst
	}
	texte := string(index)
	idx, err := ParseJSON(index)
	if err != nil {
		return dst
	}
	for _, p := range idx.Get("parts").Arr {
		f := chaineDe(p, "file")
		ancien := chaineDe(p, "sha256")
		if _, altere := alterations[f]; !altere || ancien == "" {
			continue
		}
		octets, err := os.ReadFile(filepath.Join(dst, f))
		if err != nil {
			continue
		}
		texte = strings.Replace(texte, ancien, Hex0x(SHA256(octets)), 1)
	}
	if err := os.WriteFile(filepath.Join(dst, "dossier.json"), []byte(texte), 0o644); err != nil {
		t.Fatal(err)
	}
	return dst
}

const reference = "testdata/reference/dossier-seq-4"

// racineVecteursCT1 est la racine des vecteurs publiés de CT-1.
var racineVecteursCT1 = filepath.Join("..", "..", "ct-1")

func publie(nom string) string { return filepath.Join(racineVecteursCT1, "dossiers", nom) }

// etats rend « ID état » pour les contrôles nommés.
func etatDe(d *Dossier, id string) string {
	c := d.Resultats.parID[id]
	if c == nil {
		return "absent"
	}
	switch c.Etat {
	case EtatPasse:
		return "reussi"
	case EtatEchoue:
		return "echoue"
	case EtatNonExecute:
		if d.admis[id] && !d.refus[id] {
			return "non_execute_admis"
		}
		return "non_execute"
	}
	return "hors_perimetre"
}

type casDossier struct {
	nom        string
	src        string
	alteration map[string]func(string) string
	reindexer  bool
	echecs     []string          // liste exacte des contrôles en échec
	etats      map[string]string // états attendus de quelques contrôles
	valide     bool
}

func verifierCas(t *testing.T, cas []casDossier) {
	t.Helper()
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			d := VerifierDossier(copierDossier(t, c.src, c.alteration, c.reindexer))
			if d.Illisible != "" {
				t.Fatalf("entrée inutilisable : %s", d.Illisible)
			}
			if got := strings.Join(d.Resultats.Echecs(), ","); got != strings.Join(c.echecs, ",") {
				t.Errorf("échecs [%s], attendu [%s]\n%s", got, strings.Join(c.echecs, ","), d.Resultats.Resume("  "))
			}
			for id, e := range c.etats {
				if got := etatDe(d, id); got != e {
					t.Errorf("%s : %s, attendu %s (%v)", id, got, e, d.Resultats.parID[id])
				}
			}
			if d.Valide() != c.valide {
				t.Errorf("valide %v, attendu %v ; non exécutés sans raison admise : %v", d.Valide(), c.valide, d.NonExecutesNonAdmis())
			}
		})
	}
}

func remplacerTout(ancien, nouveau string) func(string) string {
	return func(s string) string {
		if !strings.Contains(s, ancien) {
			panic("altération sans effet : " + ancien)
		}
		return strings.ReplaceAll(s, ancien, nouveau)
	}
}

func remplacerContenu(contenu string) func(string) string {
	return func(string) string { return contenu }
}

// --------------------------------------------------------- lecture du JSON

// §3 et §4 (révision 0.5) : marque d'ordre d'octets et UTF-8 mal formé ne sont
// pas un texte JSON (erreur non canonique) ; un substitut écrit en octets est
// un défaut de forme canonique (E-2) ; profondeur 128 admise, 129 refusée ;
// une erreur de syntaxe plus loin l'emporte sur une clé en double.
func TestLectureJSONRevision05(t *testing.T) {
	canonique := func(src string) (bool, bool) {
		_, err := ParseJSONV0([]byte(src))
		if err == nil {
			return true, false
		}
		ej, ok := err.(*ErreurJSON)
		return false, ok && ej.Canonique
	}
	for _, c := range []struct {
		nom, src       string
		ok, defautE2   bool
		attenduMessage string
	}{
		{"objet simple", `{"a":"é"}`, true, false, ""},
		{"marque d'ordre d'octets", "\xEF\xBB\xBF{}", false, false, "pas un texte JSON"},
		{"UTF-8 mal formé", "{\"a\":\"\xC3\x28\"}", false, false, "pas un texte JSON"},
		{"octet de continuation seul", "{\"a\":\"\x80\"}", false, false, "pas un texte JSON"},
		{"substitut haut écrit en octets", "{\"a\":\"\xED\xA0\x80\"}", false, true, ""},
		{"paire écrite en octets (CESU-8)", "{\"a\":\"\xED\xA0\xBD\xED\xB8\x80\"}", false, true, ""},
		{"substitut échappé", `{"a":"\ud800"}`, false, true, ""},
		{"paire échappée", `{"a":"😀"}`, true, false, ""},
		{"clé en double", `{"a":1,"a":2}`, false, true, ""},
		{"clé en double puis erreur de syntaxe", `{"a":1,"a":2,`, false, false, ""},
		{"substitut en octets hors chaîne", "\xED\xA0\x80", false, false, ""},
	} {
		ok, e2 := canonique(c.src)
		if ok != c.ok || e2 != c.defautE2 {
			t.Errorf("%s : lu %v, défaut canonique %v ; attendu %v, %v", c.nom, ok, e2, c.ok, c.defautE2)
		}
	}
	imbrique := func(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }
	if _, err := ParseJSONV0([]byte(imbrique(128))); err != nil {
		t.Errorf("profondeur 128 refusée : %v", err)
	}
	if _, err := ParseJSONV0([]byte(`{"a":` + imbrique(127) + `}`)); err != nil {
		t.Errorf("objet racine et 127 tableaux imbriqués refusés : %v", err)
	}
	for _, src := range []string{imbrique(129), `{"a":` + imbrique(128) + `}`, `{"a":` + strings.Repeat("[", 127) + "[1]" + strings.Repeat("]", 127) + `}`} {
		_, err := ParseJSONV0([]byte(src))
		if ej, ok := err.(*ErreurJSON); err == nil || !ok || ej.Canonique {
			t.Errorf("profondeur 129 : %v (attendu : pas un texte JSON)", err)
		}
	}
	for src, p := range map[string]int{`1`: 0, `"a"`: 0, `[]`: 1, `{}`: 1, `[[1]]`: 2, `{"a":[]}`: 2} {
		v, _ := ParseJSON([]byte(src))
		if got := Profondeur(v); got != p {
			t.Errorf("profondeur de %s : %d, attendu %d", src, got, p)
		}
	}
	// ParseJSON (documents qui ne sont pas du format v0) garde une borne fixe plus large.
	if _, err := ParseJSON([]byte(imbrique(200))); err != nil {
		t.Errorf("ParseJSON, profondeur 200 : %v", err)
	}
}

// Chaîne non vide (§3, révision 0.5) : blancs White_Space et U+FEFF.
func TestChaineNonVide(t *testing.T) {
	for _, s := range []string{"", " ", "\t\n", "\u0085", "\u00a0", "\u2028", "\u3000", "\ufeff", " \ufeff "} {
		if ChaineNonVide(s) {
			t.Errorf("%q n'est pas une chaîne non vide", s)
		}
	}
	for _, s := range []string{"aucune approbation liée", "pii-v1", " x ", "\u200b"} {
		if !ChaineNonVide(s) {
			t.Errorf("%q est une chaîne non vide", s)
		}
	}
}

// -------------------------------------------------------- parties du dossier

func TestPartiesRevision05(t *testing.T) {
	indexPartie := func(nom string) func(string) string {
		// déclare présente la partie réservée nom avec le SHA-256 du fichier « contenu-<nom> ».
		return func(s string) string {
			ancien := fmt.Sprintf(`"name": %q,`, nom)
			i := strings.Index(s, ancien)
			if i < 0 {
				panic(nom)
			}
			j := i + strings.Index(s[i:], "}")
			bloc := s[i:j]
			sum := Hex0x(SHA256([]byte("contenu-" + nom)))
			nouveau := strings.Replace(strings.Replace(strings.Replace(bloc, `"sha256": null`, fmt.Sprintf("%q: %q", "sha256", sum), 1), `"present": false`, `"present": true`, 1), `"reason_if_absent": "hors périmètre CT-1"`, `"reason_if_absent": null`, 1)
			return s[:i] + nouveau + s[j:]
		}
	}
	verifierCas(t, []casDossier{
		// (a) partie manquante : D-2 seule (avant : M-2 en échec aussi, « illisible »).
		{nom: "partie manquante : D-2 seule", src: reference, alteration: map[string]func(string) string{"chemin.json": remplacerContenu(supprimer)},
			echecs: []string{"D-2"}, etats: map[string]string{"M-2": "non_execute", "M-1": "non_execute", "M-3": "non_execute", "K-4": "absent"}},
		{nom: "référence : toutes les parties présentes", src: reference, echecs: nil, etats: map[string]string{"D-2": "reussi", "M-2": "reussi"}, valide: true},
		// (b) au-delà de la limite (16 Mio) : contrôle porteur, SHA-256 non comparé (index non recalculé : D-2 réussit).
		{nom: "partie au-delà de 16 Mio : M-2, D-2 réussie", src: reference, alteration: map[string]func(string) string{"chemin.json": func(s string) string {
			return s + strings.Repeat(" ", LimitePartieJSON+1-len(s))
		}}, echecs: []string{"M-2"}, etats: map[string]string{"D-2": "reussi", "M-1": "non_execute", "M-3": "non_execute"}},
		{nom: "partie de 16 Mio exactement : lue", src: reference, reindexer: true, alteration: map[string]func(string) string{"chemin.json": func(s string) string {
			return s + strings.Repeat(" ", LimitePartieJSON-len(s))
		}}, echecs: nil, valide: true},
		// (c) marque d'ordre d'octets, UTF-8 mal formé : contrôle porteur, non E-2 (avant : E-2 pour l'UTF-8 mal formé).
		{nom: "marque d'ordre d'octets : E-1", src: reference, reindexer: true, alteration: map[string]func(string) string{"evenement.json": func(s string) string { return "\xEF\xBB\xBF" + s }},
			echecs: []string{"E-1"}, etats: map[string]string{"E-2": "non_execute", "D-1": "non_execute", "M-1": "non_execute", "P-1": "non_execute", "A-1": "non_execute", "M-2": "reussi", "P-4": "reussi", "P-3": "reussi"}},
		{nom: "UTF-8 mal formé : M-2", src: reference, reindexer: true, alteration: map[string]func(string) string{"chemin.json": remplacer(`"version": 0`, "\"version\": 0, \"x\": \"\xC3\x28\"")},
			echecs: []string{"M-2"}, etats: map[string]string{"E-2": "reussi"}},
		{nom: "profondeur 129 : E-1", src: reference, reindexer: true, alteration: map[string]func(string) string{"evenement.json": remplacer(`"version": 0`, `"version": 0, "x": `+strings.Repeat("[", 128)+strings.Repeat("]", 128))},
			echecs: []string{"E-1"}, etats: map[string]string{"E-2": "non_execute"}},
		// (d) substitut écrit en octets : E-2, contrôle porteur non exécuté.
		{nom: "substitut en octets : E-2", src: reference, reindexer: true, alteration: map[string]func(string) string{"chemin.json": remplacer(`"version": 0`, "\"version\": 0, \"x\": \"\xED\xA0\x80\"")},
			echecs: []string{"E-2"}, etats: map[string]string{"M-2": "non_execute", "M-1": "non_execute", "M-3": "non_execute"}},
		// (d) evenement.json sans forme canonique : E-2 seule, E-1 non exécutée
		// et tout ce qui lit l'événement (CT-1 §11.5, invalide-nombre-non-entier).
		{nom: "nombre non entier : E-2 seule", src: reference, reindexer: true, alteration: map[string]func(string) string{"evenement.json": remplacer(`"duration_ms": 412,`, `"duration_ms": 412.0,`)},
			echecs: []string{"E-2"}, etats: map[string]string{"E-1": "non_execute", "C-2": "non_execute", "M-1": "non_execute", "P-5": "non_execute", "E-8": "non_execute", "E-9": "non_execute"}},
		// Partie réservée présente : jamais « valide » pour un vérificateur de CT-1 seul.
		{nom: "partie réservée présente : invalide", src: reference, alteration: map[string]func(string) string{
			"dossier.json": indexPartie("preuve_ots"),
		}, echecs: []string{"D-2"}, etats: map[string]string{"O-*": "non_execute"}},
	})
	// Partie réservée présente et conforme à l'index : aucun échec, mais
	// non vérifiée, sans raison admise : le dossier n'est pas valide (avant :
	// raison admise, dossier valide).
	dir := copierDossier(t, reference, map[string]func(string) string{"dossier.json": indexPartie("preuve_ots")}, false)
	if err := os.WriteFile(filepath.Join(dir, "preuve.ots"), []byte("contenu-preuve_ots"), 0o644); err != nil {
		t.Fatal(err)
	}
	d := VerifierDossier(dir)
	if len(d.Resultats.Echecs()) != 0 || d.Valide() || etatDe(d, "O-*") != "non_execute" {
		t.Errorf("partie réservée présente : échecs %v, valide %v, O-* %s", d.Resultats.Echecs(), d.Valide(), etatDe(d, "O-*"))
	}
	// Lien symbolique à la place d'une partie présente : pas un fichier ordinaire, D-2.
	dir = copierDossier(t, reference, nil, false)
	os.Rename(filepath.Join(dir, "manifeste.sig"), filepath.Join(dir, "ailleurs.sig"))
	if err := os.Symlink("ailleurs.sig", filepath.Join(dir, "manifeste.sig")); err == nil {
		d = VerifierDossier(dir)
		if strings.Join(d.Resultats.Echecs(), ",") != "D-2" || etatDe(d, "P-5") != "non_execute" {
			t.Errorf("lien symbolique : échecs %v, P-5 %s", d.Resultats.Echecs(), etatDe(d, "P-5"))
		}
	}
	// Répertoire du nom d'une partie déclarée absente : compte comme absent.
	dir = copierDossier(t, reference, nil, false)
	os.Mkdir(filepath.Join(dir, "preuve.ots"), 0o755)
	if d = VerifierDossier(dir); !d.Valide() {
		t.Errorf("répertoire preuve.ots : dossier attendu valide, échecs %v", d.Resultats.Echecs())
	}
	// Fichier ordinaire du nom d'une partie déclarée absente : D-2.
	dir = copierDossier(t, reference, nil, false)
	os.WriteFile(filepath.Join(dir, "preuve.ots"), []byte("x"), 0o644)
	if d = VerifierDossier(dir); strings.Join(d.Resultats.Echecs(), ",") != "D-2" {
		t.Errorf("fichier preuve.ots déclaré absent : échecs %v", d.Resultats.Echecs())
	}
}

// dossier.json (§11.4, révision 0.5) : absent ou pas du JSON : code 2 ; sans
// forme canonique : E-2 (avant : un nombre non entier dans l'index était
// accepté) ; au-delà de 1 Mio ou pas un objet : D-1 ; aucun autre contrôle.
func TestIndexRevision05(t *testing.T) {
	for _, c := range []struct {
		nom        string
		alteration func(string) string
		illisible  bool
		echecs     string
	}{
		{"index absent", remplacerContenu(supprimer), true, ""},
		{"index qui n'est pas du JSON", remplacerContenu("{"), true, ""},
		{"index trop profond", func(s string) string { return strings.Repeat("[", 129) + strings.Repeat("]", 129) }, true, ""},
		{"index à nombre non entier", remplacer(`"version": 0,`, `"version": 0.0,`), false, "E-2"},
		{"index à clé en double", remplacer(`"version": 0,`, `"version": 0, "version": 0,`), false, "E-2"},
		{"index au-delà de 1 Mio", func(s string) string { return s + strings.Repeat(" ", LimiteIndex) }, false, "D-1"},
		{"index tableau", remplacerContenu("[]"), false, "D-1"},
		{"index contraire à son schéma", remplacer(`"version": 0,`, `"version": 0, "x": 1,`), false, "D-1"},
		{"index d'un autre journal (D-1, org_id et journal_id)", remplacer(`"journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b",
  "generated_at"`, `"journal_id": "0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164",
  "generated_at"`), false, "D-1"},
	} {
		d := VerifierDossier(copierDossier(t, reference, map[string]func(string) string{"dossier.json": c.alteration}, false))
		if (d.Illisible != "") != c.illisible || strings.Join(d.Resultats.Echecs(), ",") != c.echecs || d.Valide() {
			t.Errorf("%s : illisible %q, échecs %v, valide %v ; attendu illisible %v, échecs [%s]", c.nom, d.Illisible, d.Resultats.Echecs(), d.Valide(), c.illisible, c.echecs)
		}
		if !c.illisible && c.nom != "index d'un autre journal (D-1, org_id et journal_id)" && len(d.Resultats.Liste()) > 2 {
			t.Errorf("%s : aucun autre contrôle ne doit être exécuté : %v", c.nom, d.Resultats.Resume(""))
		}
	}
}

// Relations à terme absent, mal typé ou incalculable (§11.4, révision 0.5).
func TestRelationsRevision05(t *testing.T) {
	verifierCas(t, []casDossier{
		// Exemple de §11.4 : seq en chaîne (dossier de seq 4 de l'exemple de
		// référence, comme valide-seq-7) : D-1, E-1, E-7, E-8, C-1, C-2, M-1,
		// M-3, P-2 et A-2.
		{nom: "seq en chaîne", src: reference, reindexer: true, alteration: map[string]func(string) string{"evenement.json": remplacer(`"seq": 4,`, `"seq": "4",`)},
			echecs: []string{"D-1", "E-1", "E-7", "E-8", "C-1", "C-2", "M-1", "M-3", "P-2", "A-2"}},
		// ts qui n'est pas une date existante : C-1, P-2, E-11, A-2 en échec
		// (avant : non exécutés ou réussis) ; E-1 (date), E-7, E-8, C-2, M-1.
		{nom: "ts inexistant", src: reference, reindexer: true, alteration: map[string]func(string) string{"evenement.json": remplacer(`"ts": "2026-11-03T13:52:41.090Z"`, `"ts": "2026-02-30T13:52:41.090Z"`)},
			echecs: []string{"E-1", "E-7", "E-8", "E-11", "C-1", "C-2", "M-1", "P-2", "A-2"}},
		// chemin.json contraire à son schéma : M-1 et M-3 exécutées (avant : non exécutées).
		{nom: "chemin.json à membre en trop", src: reference, reindexer: true, alteration: map[string]func(string) string{"chemin.json": remplacer(`"version": 0,`, `"version": 0, "x": 1,`)},
			echecs: []string{"M-2"}, etats: map[string]string{"M-1": "reussi", "M-3": "reussi"}},
		{nom: "chemin.json à membre en trop et leaf_index faux", src: reference, reindexer: true, alteration: map[string]func(string) string{"chemin.json": remplacer(`"leaf_index": 3,`, `"leaf_index": 2, "x": 1,`)},
			echecs: []string{"M-2", "M-3"}, etats: map[string]string{"M-1": "reussi"}},
		// approver_set à membre en trop : A-1 en échec, A-3 exécutée sur ses valeurs (avant : A-3 en échec).
		{nom: "approver_set à membre en trop", src: reference, reindexer: true, alteration: map[string]func(string) string{"approbations.json": remplacer(`"source": "comptes Hardhat 1 à 3 (vecteurs CT-1)"`, `"source": "comptes Hardhat 1 à 3 (vecteurs CT-1)", "x": 1`)},
			echecs: []string{"A-1"}, etats: map[string]string{"A-2": "reussi", "A-3": "reussi"}},
		// cles.json contraire à la première partie de E-8 : E-11, P-5, E-10 (comparaisons) non exécutées (avant : exécutées).
		{nom: "cles.json d'un autre journal", src: reference, reindexer: true, alteration: map[string]func(string) string{"cles.json": remplacer(`"journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b"`, `"journal_id": "0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164"`)},
			echecs: []string{"E-8"}, etats: map[string]string{"E-11": "non_execute", "P-5": "non_execute", "E-10": "non_execute"}},
		{nom: "cles.json avec un membre de clés de test (seed)", src: reference, reindexer: true, alteration: map[string]func(string) string{"cles.json": remplacer(`"source": `, `"seed": "0x`+strings.Repeat("00", 32)+`", "source": `)},
			echecs: []string{"E-8"}, etats: map[string]string{"E-11": "non_execute", "P-5": "non_execute"}},
		// voisins.json inexploitable : A-4 non exécutée sans raison admise (avant : admise).
		{nom: "voisins.json inexploitable", src: reference, reindexer: true, alteration: map[string]func(string) string{"voisins.json": remplacerContenu("null\n")},
			echecs: []string{"C-1"}, etats: map[string]string{"A-4": "non_execute", "C-2": "non_execute", "P-3": "non_execute"}},
		{nom: "voisins.json exploitable : A-4 admise", src: reference, echecs: nil, etats: map[string]string{"A-4": "non_execute_admis"}, valide: true},
		// Voisin qui n'est pas un objet : E-1 pour lui ; relations non tenues.
		{nom: "voisin next qui n'est pas un objet", src: reference, reindexer: true, alteration: map[string]func(string) string{"voisins.json": func(s string) string {
			i := strings.Index(s, `"next": {`)
			return s[:i] + `"next": 5` + "\n}\n"
		}}, echecs: []string{"E-1", "C-1", "C-2", "C-3", "P-3"}},
	})
}

// A-1 (révision 0.5) : approval nul exige la partie déclarée absente avec la
// raison exacte « aucune approbation liée » ; approval non nul et partie
// déclarée absente : A-1 en échec, A-2 et A-3 non exécutées, A-4 exécutée.
func TestApprobationsRevision05(t *testing.T) {
	src := publie("valide-at6-document-autre-condense")
	verifierCas(t, []casDossier{
		{nom: "approval nul, raison exacte", src: src, echecs: nil, etats: map[string]string{"A-1": "reussi", "A-2": "non_execute_admis", "A-4": "non_execute_admis"}, valide: true},
		{nom: "approval nul, autre raison", src: src, alteration: map[string]func(string) string{"dossier.json": remplacer(`"reason_if_absent": "aucune approbation liée"`, `"reason_if_absent": "aucune approbation"`)},
			echecs: []string{"A-1"}, etats: map[string]string{"A-2": "non_execute", "A-3": "non_execute", "A-4": "non_execute"}},
		// Raison de blancs : D-2 ; U+FEFF et U+0085 sont des blancs (avant : acceptés).
		{nom: "raison faite de U+FEFF", src: src, alteration: map[string]func(string) string{"dossier.json": remplacer(`"reason_if_absent": "aucune approbation liée"`, `"reason_if_absent": "\ufeff"`)},
			echecs: []string{"D-2", "A-1"}},
		{nom: "raison faite de U+0085", src: src, alteration: map[string]func(string) string{"dossier.json": remplacer(`"hors périmètre CT-1"`, `"\u0085"`)},
			echecs: []string{"D-2"}},
		{nom: "raison vide : D-1 par le schéma", src: src, alteration: map[string]func(string) string{"dossier.json": remplacer(`"hors périmètre CT-1"`, `""`)},
			echecs: []string{"D-1"}},
	})
	verifierCas(t, []casDossier{
		{nom: "approval non nul, partie déclarée absente : A-4 exécutée", src: reference, alteration: map[string]func(string) string{
			"dossier.json": remplacer(`"sha256": "0xa9b7effadb2793db2a5bc0ae8e4f9f7181aadcd9510860ef69071437da4341ba",
      "present": true,
      "reason_if_absent": null`, `"sha256": null,
      "present": false,
      "reason_if_absent": "aucune approbation liée"`),
			"approbations.json": remplacerContenu(supprimer),
		}, echecs: []string{"A-1"}, etats: map[string]string{"A-2": "non_execute", "A-3": "non_execute", "A-4": "non_execute_admis"}},
	})
}

// E-3, règle exacte de §5.3 (révision 0.5), E-4 (chaîne non vide), E-5 et E-9.
func TestEvenementRevision05(t *testing.T) {
	journal := lireTest(t, "testdata/reference/journal.json").Arr
	cles := clesReference(t)
	etat := func(ev *Value, id string) string {
		res := ControlerEvenement(ev, cles)
		c := res.parID[id]
		if c == nil {
			return "absent"
		}
		return c.Etat.String()
	}
	copie := func(i int, f func(string) string) *Value {
		c, _ := Canonique(journal[i])
		v, err := ParseJSON([]byte(f(string(c))))
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	for i := range journal {
		for _, x := range []string{"E-3", "E-4", "E-5", "E-9"} {
			if e := etat(journal[i], x); e != "passé" && e != "absent" {
				t.Errorf("seq %d : %s %s", i+1, x, e)
			}
		}
	}
	// seq 3 est la décision, seq 4 l'appel relayé (a_approuver, approuve), seq 5 la rotation.
	for _, c := range []struct {
		nom string
		i   int
		f   func(string) string
		id  string
	}{
		{"décision à effets non vides", 2, remplacer(`"effects":[]`, `"effects":[{"action":"lecture","amount":null,"currency":null,"object":"x","system":"y"}]`), "E-3"},
		{"appel a_approuver exécuté sans approbation", 3, func(s string) string {
			i := strings.Index(s, `"approval":{`)
			j := i + strings.Index(s[i:], `},"code"`) + 1
			return s[:i] + `"approval":null` + s[j:]
		}, "E-3"},
		{"appel retenu à effets", 3, func(s string) string {
			s = remplacer(`"status":"executee"`, `"status":"retenue"`)(s)
			i := strings.Index(s, `"approval":{`)
			j := i + strings.Index(s[i:], `},"code"`) + 1
			s = s[:i] + `"approval":null` + s[j:]
			i = strings.Index(s, `"duration_ms":`)
			j = i + strings.Index(s[i:], `,"is_error"`)
			s = s[:i] + `"duration_ms":null` + s[j:]
			s = remplacer(`"is_error":false`, `"is_error":null`)(s)
			i = strings.Index(s, `"result":{`)
			j = i + strings.Index(s[i:], `},"status"`) + 1
			return s[:i] + `"result":null` + s[j:]
		}, "E-3"},
		{"rotation lancée par un autre", 4, remplacer(`"launched_by":"noortrace-enregistreur"`, `"launched_by":"u.martin"`), "E-3"},
		{"nom réservé inconnu", 3, remplacer(`"tool":"sap.payments.create"`, `"tool":"noortrace.autre"`), "E-3"},
		{"redaction vide", 3, remplacer(`"redaction":"pii-v1"`, `"redaction":""`), "E-4"},
		{"redaction de blancs", 3, remplacer(`"redaction":"pii-v1"`, `"redaction":" \u00a0"`), "E-4"},
		{"signature en trop", 3, func(s string) string {
			i := strings.Index(s, `"signatures":[`) + len(`"signatures":[`)
			j := i + strings.Index(s[i:], `"`) + 1
			k := j + strings.Index(s[j:], `"`)
			sig := s[j:k]
			return s[:i] + `"` + sig + `",` + s[i:]
		}, "E-9"},
		{"signature non canonique (v = 29)", 3, func(s string) string {
			i := strings.Index(s, `"signatures":["`) + len(`"signatures":["`) + 130
			return s[:i] + "1d" + s[i+2:]
		}, "E-9"},
		{"signatures null", 3, func(s string) string {
			i := strings.Index(s, `"signatures":[`)
			j := i + strings.Index(s[i:], `]`) + 1
			return s[:i] + `"signatures":null` + s[j:]
		}, "E-9"},
	} {
		ev := copie(c.i, c.f)
		if e := etat(ev, c.id); e != "ÉCHOUÉ" {
			t.Errorf("%s : %s %s, attendu en échec\n%s", c.nom, c.id, e, ControlerEvenement(ev, cles).Resume("  "))
		}
	}
	// Signature attribuée à un autre approbateur : l'adresse recouvrée diffère,
	// E-9 en échec (révision 0.5 de ce vérificateur ; avant : hors périmètre).
	if e := etat(copie(3, remplacer(`"approvers":["0x70997970c51812dc3a010c7d01b50e0d17dc79c8"`, `"approvers":["0x90f79bf6eb2c4f870365e785982e1f101e93b906"`)), "E-9"); e != "ÉCHOUÉ" {
		t.Errorf("signature attribuée à un autre : E-9 %s", e)
	}
	// Signature en trop : E-5 et E-9 ; approbateur sans signature : E-5 seule.
	ev := copie(3, remplacer(`"0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc"]`, `"0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc","0x90f79bf6eb2c4f870365e785982e1f101e93b906"]`))
	if etat(ev, "E-5") != "ÉCHOUÉ" || etat(ev, "E-9") != "passé" {
		t.Errorf("approbateur sans signature : E-5 %s, E-9 %s (E-5 seule attendue)", etat(ev, "E-5"), etat(ev, "E-9"))
	}
	// Changement de politique : policy_version de 128 caractères admis, 129 et "" refusés.
	pol := func(v string) *Value {
		return &Value{Kind: KindObject, Obj: []Member{
			{Key: "version", Val: &Value{Kind: KindNumber, Num: "0"}},
			{Key: "seq", Val: &Value{Kind: KindNumber, Num: "1"}},
			{Key: "delegation", Val: objetDe(t, `{"launched_by":"noortrace-enregistreur","on_behalf_of":null,"scope":"x","run_id":null}`)},
			{Key: "intent", Val: &Value{Kind: KindNull}},
			{Key: "policy", Val: objetDe(t, `{"rule":null,"decision":"sans_objet","ticket":null,"redaction":null}`)},
			{Key: "approval", Val: &Value{Kind: KindNull}},
			{Key: "execution", Val: objetDe(t, `{"tool":"noortrace.journal.politique","arguments":{"sha256":"0x00","length":0,"redacted":false,"value":{"policy_version":"`+v+`","policy_sha256":"0x`+strings.Repeat("ab", 32)+`"}},"status":"executee","result":null,"duration_ms":null,"is_error":null}`)},
			{Key: "effects", Val: &Value{Kind: KindArray}},
		}}
	}
	for v, echec := range map[string]bool{strings.Repeat("é", 128): false, "v1": false, strings.Repeat("a", 129): true, "": true} {
		r := NouveauxResultats()
		controlerSorte(r, pol(v))
		if (r.parID["E-3"].Etat == EtatEchoue) != echec {
			t.Errorf("policy_version de %d caractères : E-3 %s", longueurChaine(v), r.parID["E-3"].Etat)
		}
	}
}

func objetDe(t *testing.T, s string) *Value {
	t.Helper()
	v, err := ParseJSON([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// K-1 à K-9 (précisions de la révision 0.5).
func TestPointsDeControleRevision05(t *testing.T) {
	src := publie("valide-seq-7-point-de-controle")
	pc, err := os.ReadFile(filepath.Join(src, "points-de-controle.json"))
	if err != nil {
		t.Skip("vecteurs publiés absents")
	}
	point := objetDe(t, string(pc)).Get("checkpoint")
	ckh, _, _ := CheckpointHash(point)
	org, _ := hex.DecodeString(strings.TrimPrefix(chaineDe(point, "org_id"), "0x"))
	jr, _ := hex.DecodeString(strings.TrimPrefix(chaineDe(point, "journal_id"), "0x"))
	empreinte := Hex0x(Keccak256(append(append(append([]byte{}, org...), jr...), ckh...)))
	docType := Hex0x(Keccak256([]byte(LibelleDocTypePoint)))
	if docType != "0x72c486c933f8fb8fef2c726539023e8fd80113cc0ca89e3fdf1314d553932178" {
		t.Errorf("docType de %s : %s (CT-4 §6.4, CT-1 annexe B)", LibelleDocTypePoint, docType)
	}
	registre := func(fp, dt string) func(string) string {
		return remplacer(`"registry": null`, fmt.Sprintf(`"registry": {"chain_id": 1, "contract": "0x%s", "fingerprint": %q, "doc_type": %q, "block_number": 1, "block_hash": "0x%s", "transaction_hash": "0x%s", "log_index": 0}`, strings.Repeat("11", 20), fp, dt, strings.Repeat("22", 32), strings.Repeat("33", 32)))
	}
	verifierCas(t, []casDossier{
		{nom: "point publié", src: src, echecs: nil, etats: map[string]string{"K-1": "reussi", "K-6": "reussi", "K-7": "non_execute_admis", "K-8": "non_execute_admis"}, valide: true},
		// Ancre non nulle : K-8 recalcule fingerprint et doc_type, puis n'est pas exécutée, sans raison admise.
		{nom: "ancre au registre conforme : K-8 non exécutée, dossier invalide", src: src, reindexer: true, alteration: map[string]func(string) string{"points-de-controle.json": registre(empreinte, docType)},
			echecs: nil, etats: map[string]string{"K-8": "non_execute", "K-7": "non_execute_admis"}},
		{nom: "ancre au registre, fingerprint faux : K-8", src: src, reindexer: true, alteration: map[string]func(string) string{"points-de-controle.json": registre(Hex0x(make([]byte, 31))+"01", docType)},
			echecs: []string{"K-8"}},
		{nom: "ancre au registre, doc_type de la période : K-8", src: src, reindexer: true, alteration: map[string]func(string) string{"points-de-controle.json": registre(empreinte, Hex0x(Keccak256([]byte("noortrace/periode/v0"))))},
			echecs: []string{"K-8"}},
		// K-1 non exécutée quand P-1 n'a pas réussi (avant : exécutée).
		{nom: "P-1 en échec : K-1 non exécutée", src: src, reindexer: true, alteration: map[string]func(string) string{"manifeste.json": remplacer(`"version": 0,`, `"version": 0, "x": 1,`)},
			echecs: []string{"P-1", "P-5"}, etats: map[string]string{"K-1": "non_execute", "K-2": "non_execute", "K-6": "non_execute"}},
		// K-6 avec voisins.json inexploitable : sans raison admise ; ici last_seq = 8 est le voisin next.
		{nom: "voisins.json inexploitable : K-6 non exécutée", src: src, reindexer: true, alteration: map[string]func(string) string{"voisins.json": remplacerContenu("[]\n")},
			echecs: []string{"C-1"}, etats: map[string]string{"K-6": "non_execute", "A-4": "non_execute"}},
		// Partie sans forme canonique : E-2, K-1 non exécutée (révision 0.5).
		{nom: "points-de-controle.json à clé en double : E-2", src: src, reindexer: true, alteration: map[string]func(string) string{"points-de-controle.json": remplacer(`"version": 0,`, `"version": 0, "version": 0,`)},
			echecs: []string{"E-2"}, etats: map[string]string{"K-1": "non_execute", "K-2": "non_execute"}},
		{nom: "points-de-controle.json au-delà de 1 Mio : K-1", src: src, alteration: map[string]func(string) string{"points-de-controle.json": func(s string) string { return s + strings.Repeat(" ", LimitePointsDeControle) }},
			echecs: []string{"K-1"}, etats: map[string]string{"D-2": "reussi", "K-2": "non_execute"}},
		// M-3 sans réussite : K-4 non exécutée.
		{nom: "M-3 en échec : K-4 non exécutée", src: src, reindexer: true, alteration: map[string]func(string) string{"chemin.json": remplacer(`"tree_size": 9,`, `"tree_size": 10,`)},
			echecs: []string{"M-3"}, etats: map[string]string{"K-4": "non_execute"}},
	})
}

// Attestation de périmètre sans forme canonique hors de signed.attestation :
// AT-1 en échec (révision 0.5), sans effet sur le verdict.
func TestAttestationFormeCanonique(t *testing.T) {
	src := publie("valide-seq-7-attestation-sans-inscription")
	for _, c := range []struct {
		nom string
		f   func(string) string
		at1 string
	}{
		{"publiée", func(s string) string { return s }, "reussi"},
		{"nombre non entier dans approver_set", remplacer(`"required": 2,`, `"required": 2.0,`), "echoue"},
	} {
		d := VerifierDossier(copierDossier(t, src, map[string]func(string) string{"attestation-perimetre.json": c.f}, true))
		if len(d.Perimetre) == 0 || d.Perimetre[0].Statut != c.at1 || !d.Valide() {
			t.Errorf("%s : AT-1 %v, valide %v ; attendu %s et dossier valide", c.nom, d.PerimetreTexte(), d.Valide(), c.at1)
		}
	}
	// Date inexistante de l'inscription : AT-1 (révision 0.5).
	src = publie("valide-seq-12-attestation-inscrite")
	d := VerifierDossier(copierDossier(t, src, map[string]func(string) string{"attestation-perimetre.json": func(s string) string {
		i := strings.Index(s, `"inscription"`)
		j := i + strings.Index(s[i:], `"ts": "2026-11-05T`)
		return s[:j] + `"ts": "2026-02-30T` + s[j+len(`"ts": "2026-11-05T`):]
	}}, true))
	if len(d.Perimetre) == 0 || d.Perimetre[0].Statut != "echoue" || !strings.Contains(strings.Join(d.Perimetre[0].Details, " "), "ts") {
		t.Errorf("date inexistante de l'inscription : %v", d.PerimetreTexte())
	}
}

// ------------------------------------------------------------- journal

// Règle exacte de §7.2 (révision 0.5) : symptômes typés, dans l'ordre des
// trois temps ; seq lus sur tout le fichier ; cles.json comparé à chaque
// événement ; cles.json défectueux : un symptôme E-8 de type cles en tête.
func TestJournalRevision05(t *testing.T) {
	racine := filepath.Join(racineVecteursCT1, "journal-valide")
	if !fichierExiste(filepath.Join(racine, "evenements.json")) {
		t.Skip("vecteurs publiés absents")
	}
	evs := lireTest(t, filepath.Join(racine, "evenements.json")).Arr
	jeu, mq := ChargerClesDossier(lireTest(t, filepath.Join(racine, "cles.json")))
	if len(mq) > 0 {
		t.Fatal(mq)
	}
	textes := func(s []Symptome) string {
		var out []string
		for _, x := range s {
			out = append(out, x.Texte())
		}
		return strings.Join(out, " ")
	}
	if _, s := ControlerJournal(evs, jeu, nil); len(s) != 0 {
		t.Fatalf("journal valide : %s", textes(s))
	}
	// Réordonnancement : seq 6 avant seq 5 ; aucun trou rapporté.
	reord := append([]*Value{}, evs...)
	reord[4], reord[5] = reord[5], reord[4]
	if _, s := ControlerJournal(reord, jeu, nil); textes(s) != "reordonnancement/C-1/5 rupture/C-2/6 rupture/C-2/5 horodatage/C-1/5 rupture/C-2/7" {
		t.Errorf("réordonnancement : %s", textes(s))
	}
	// Deux suppressions (seq 4 et seq 8) : un trou chacune, dans l'ordre croissant.
	var supp []*Value
	for _, ev := range evs {
		if s, _ := SeqTypee(ev); s != 4 && s != 8 {
			supp = append(supp, ev)
		}
	}
	if _, s := ControlerJournal(supp, jeu, nil); textes(s) != "suppression/C-1/5 suppression/C-1/9 rupture/C-2/5 rupture/C-2/9" {
		t.Errorf("suppressions : %s", textes(s))
	}
	// cles.json d'une autre organisation : E-8 pour chaque événement (un premier
	// événement en écart ne masque pas les autres).
	autre := *jeu
	autre.OrgID = Hex0x(Keccak256([]byte("autre-organisation")))
	res, s := ControlerJournal(evs, &autre, nil)
	if len(s) != len(evs) || strings.Join(res.Echecs(), ",") != "E-8" {
		t.Errorf("cles.json d'une autre organisation : %s", textes(s))
	}
	// cles.json défectueux : un symptôme E-8 de type cles et de seq nul, en tête ; E-8 pour aucun événement.
	res, s = ControlerJournal(evs, jeu, []string{"cles.keys[0].valid_from : horodatage attendu"})
	if textes(s) != "cles/E-8/null" || strings.Join(res.Echecs(), ",") != "E-8" {
		t.Errorf("cles.json défectueux : %s", textes(s))
	}
	// Origine contrôlée pour chaque événement : prev_hash nul en seq 7.
	c, _ := Canonique(evs[6])
	origine := objetDe(t, strings.Replace(string(c), chaineDe(evs[6], "prev_hash"), Zero32, 1))
	alt := append(append(append([]*Value{}, evs[:6]...), origine), evs[7:]...)
	if _, s := ControlerJournal(alt, jeu, nil); !strings.Contains(textes(s), "origine/C-2/7") || !strings.HasPrefix(textes(s), "modification/E-7/7 signature/E-8/7 origine/C-2/7") {
		t.Errorf("prev_hash nul en seq 7 : %s", textes(s))
	}
	// Profondeur d'un événement de journal : au-delà de 128 depuis l'objet, E-1.
	profond := func(n int) *Value {
		c, _ := Canonique(evs[1])
		return objetDe(t, strings.Replace(string(c), `"version":0}`, `"version":0,"x":`+strings.Repeat("[", n)+strings.Repeat("]", n)+`}`, 1))
	}
	for n, attendu := range map[int]bool{127: false, 128: true} {
		_, s := ControlerJournal([]*Value{evs[0], profond(n)}, jeu, nil)
		trouve := false
		for _, x := range s {
			trouve = trouve || (x.Controle == "E-1" && strings.Contains(x.Message, "profondeur"))
		}
		if trouve != attendu {
			t.Errorf("événement de profondeur %d : symptôme de profondeur %v, attendu %v", n+1, trouve, attendu)
		}
	}
}

// ------------------------------------------------- série de points (§10.5)

func TestSerieRevision05(t *testing.T) {
	racine := racineVecteursCT1
	f := filepath.Join(racine, "points-de-controle", "periode-1.json")
	if !fichierExiste(f) {
		t.Skip("vecteurs publiés absents")
	}
	points := lireTest(t, f).Arr
	m1 := LireManifeste(lireTest(t, filepath.Join(racine, "manifestes", "periode-1.json")))
	m3 := LireManifeste(lireTest(t, filepath.Join(racine, "manifestes", "periode-3.json")))
	p3 := lireTest(t, filepath.Join(racine, "points-de-controle", "periode-3.json")).Arr
	evs := lireTest(t, filepath.Join(racine, "journal-valide", "evenements.json")).Arr
	jeu, _ := ChargerCles(lireTest(t, filepath.Join(racine, "cles", "cles.json")))
	texte := func(regles []string, ne []RegleNonEvaluee) string {
		return strings.Join(regles, ",") + " | " + texteNonEvaluees(ne)
	}
	if regles, _, ne := ControlerSerie(points, m1, evs, jeu, false); texte(regles, ne) != " | aucune" {
		t.Errorf("série complète : %s", texte(regles, ne))
	}
	// Sans les événements 5 à 9 : root et last_hash non évaluées
	// (piece_hors_dossier), aucune règle violée (avant : toutes deux sautées
	// pour toute la série, sans rien rapporter).
	var partiels []*Value
	for _, ev := range evs {
		if s, _ := SeqTypee(ev); s < 5 || s > 9 {
			partiels = append(partiels, ev)
		}
	}
	if regles, _, ne := ControlerSerie(points, m1, partiels, jeu, false); texte(regles, ne) != " | root:piece_hors_dossier,last_hash:piece_hors_dossier" {
		t.Errorf("sans les événements 5 à 9 : %s", texte(regles, ne))
	}
	// Avec un événement altéré (seq 8, last_seq de points de la série) : root
	// et last_hash violées.
	c, _ := Canonique(evs[7])
	altere := objetDe(t, strings.Replace(string(c), `"seq":8`, `"seq":8,"x":1`, 1))
	modifies := append(append(append([]*Value{}, evs[:7]...), altere), evs[8:]...)
	if regles, _, ne := ControlerSerie(points, m1, modifies, jeu, false); texte(regles, ne) != "root,last_hash | aucune" {
		t.Errorf("événement 8 altéré : %s", texte(regles, ne))
	}
	// Événement fourni sans forme canonique : prerequis_en_echec.
	nonCanon := objetDe(t, strings.Replace(string(c), `"seq":8`, `"seq":8,"x":1.5`, 1))
	modifies[7] = nonCanon
	if regles, _, ne := ControlerSerie(points, m1, modifies, jeu, false); texte(regles, ne) != " | root:prerequis_en_echec,last_hash:prerequis_en_echec" {
		t.Errorf("événement 8 sans forme canonique : %s", texte(regles, ne))
	}
	// Période vide (n = 0, last_seq = 12) vérifiée sans l'événement 12 : last_hash
	// non évaluée ; 32 octets nuls ne le remplacent jamais (avant : last_hash violée).
	sans12 := evs[:11]
	if regles, _, ne := ControlerSerie(p3, m3, sans12, jeu, false); texte(regles, ne) != " | last_hash:piece_hors_dossier" {
		t.Errorf("période vide sans l'événement 12 : %s", texte(regles, ne))
	}
	// Clé en vigueur d'un point de last_seq = 0 : règle de cles.json ; une autre clé viole la règle.
	var p0 *Point
	for _, p := range points {
		if lp := LirePoint(p); lp.LastSeq == 0 {
			p0 = lp
			break
		}
	}
	if p0 == nil {
		t.Fatal("aucun point de last_seq = 0 dans la période 1")
	}
	if k, ok := CleEnVigueurPoint(evs, jeu, 0, p0.CheckpointTs, true); !ok || k != "rec-test-01" {
		t.Errorf("last_seq = 0 : clé en vigueur %q", k)
	}
	if k, ok := CleEnVigueurPoint(partiels, jeu, 9, m1.GeneratedAt, true); !ok || k != "rec-test-02" {
		t.Errorf("événement 9 non fourni, clôture : clé en vigueur %q (rec-test-02 par cles.json)", k)
	}
	avant, _ := ParseHorodatage("2026-10-01T00:00:00.000Z")
	if _, ok := CleEnVigueurPoint(evs, jeu, 0, avant, true); ok {
		t.Error("aucune clé de valid_from ≤ checkpoint_ts : la règle doit être violée")
	}
	// Un événement de seq inférieur ne remplace pas l'événement last_seq manquant.
	if k, ok := CleEnVigueurPoint([]*Value{evs[0]}, nil, 5, p0.CheckpointTs, true); ok {
		t.Errorf("événement 5 manquant, sans cles.json : %q", k)
	}
	// Série dont un point de last_seq = 0 porte une autre clé : cle_en_vigueur.
	cp, _ := Canonique(p0.V)
	autre := objetDe(t, strings.Replace(string(cp), `"key_id":"rec-test-01"`, `"key_id":"rec-test-02"`, 1))
	var serie []*Value
	for _, p := range points {
		if p == p0.V {
			serie = append(serie, autre)
		} else {
			serie = append(serie, p)
		}
	}
	regles, _, _ := ControlerSerie(serie, m1, evs, jeu, false)
	sort.Strings(regles)
	if !dansEnum("cle_en_vigueur", regles) {
		t.Errorf("point de last_seq = 0 sous une autre clé : %v", regles)
	}
}

// ------------------------------------- compléments de la révision 0.5
// (passages tranchés le 2026-11-03 : CT-1 §7.2, §10.5, §11.4, §11.5)

func TestComplementsDossierRevision05(t *testing.T) {
	seq7 := publie("valide-seq-7")
	seq6 := publie("valide-seq-6")
	nul := publie("valide-at6-document-autre-condense")
	verifierCas(t, []casDossier{
		// « sauf s'il échoue sur ce qu'il lit des autres parties » (§11.4) :
		// evenement.json = null, période de 7 200 s, key_id en double.
		{nom: "événement nul et autres échecs", src: seq7, reindexer: true, alteration: map[string]func(string) string{
			"evenement.json": remplacerContenu("null\n"),
			"manifeste.json": remplacer(`"period_end": 1793872800`, `"period_end": 1793876400`),
			"cles.json":      remplacer(`"key_id": "rec-test-02"`, `"key_id": "rec-test-01"`),
		}, echecs: []string{"E-1", "E-8", "P-1", "P-5"}, etats: map[string]string{"D-1": "non_execute", "P-2": "non_execute", "M-1": "non_execute", "M-2": "reussi", "P-4": "reussi"}},
		// approval nul et approbations.json déclarée présente, sans fichier : A-1 et D-2.
		{nom: "approbations.json déclarée présente, absente", src: nul, alteration: map[string]func(string) string{
			"dossier.json": remplacer(`"sha256": null,
      "present": false,
      "reason_if_absent": "aucune approbation liée"`, `"sha256": "0x`+strings.Repeat("ab", 32)+`",
      "present": true,
      "reason_if_absent": null`),
		}, echecs: []string{"D-2", "A-1"}, etats: map[string]string{"A-2": "non_execute", "A-4": "non_execute"}},
		// Voisin absent (règle unique) : C-1, C-2, C-3, P-3 ; pas de E-1.
		{nom: "membre previous absent", src: seq7, reindexer: true, alteration: map[string]func(string) string{"voisins.json": func(s string) string {
			i := strings.Index(s, `"previous": {`)
			j := strings.Index(s, `"next": {`)
			return s[:i] + s[j:]
		}}, echecs: []string{"C-1", "C-2", "C-3", "P-3"}},
		// Voisin non objet candidat à la demande : pas trouvé, A-4 admise.
		{nom: "previous = \"x\" pour une décision", src: seq6, reindexer: true, alteration: map[string]func(string) string{"voisins.json": func(s string) string {
			i := strings.Index(s, `"previous": {`)
			j := strings.Index(s, `"next": `)
			return s[:i] + `"previous": "x",` + "\n  " + s[j:]
		}}, echecs: []string{"E-1", "C-1", "C-2", "C-3", "P-3"}, etats: map[string]string{"A-4": "non_execute_admis", "E-2": "non_execute", "E-11": "non_execute"}},
		// approval ni nul ni objet : A-1 à A-4 en échec (A-4 : request_hash ne se lit pas).
		{nom: "approval = 5", src: seq7, reindexer: true, alteration: map[string]func(string) string{"evenement.json": func(s string) string {
			i := strings.Index(s, `"approval": {`)
			j := i + strings.Index(s[i:], "\n  },") + len("\n  }")
			return s[:i] + `"approval": 5` + s[j:]
		}}, echecs: []string{"E-1", "E-3", "E-5", "E-7", "E-8", "E-9", "C-2", "M-1", "A-1", "A-2", "A-3", "A-4"}},
		// execution.tool qui n'est pas une chaîne : E-1 et E-3.
		{nom: "execution.tool = 5", src: seq7, reindexer: true, alteration: map[string]func(string) string{"evenement.json": func(s string) string {
			i := strings.Index(s, `"tool": "`)
			j := i + len(`"tool": "`) + strings.Index(s[i+len(`"tool": "`):], `"`) + 1
			return s[:i] + `"tool": 5` + s[j:]
		}}, echecs: []string{"E-1", "E-3", "E-7", "E-8", "C-2", "M-1"}},
	})
	// Raison d'une partie réservée présente : prerequis_en_echec, détail imposé.
	dir := copierDossier(t, reference, map[string]func(string) string{"dossier.json": func(s string) string {
		i := strings.Index(s, `"name": "preuve_ots",`)
		j := i + strings.Index(s[i:], "}")
		bloc := strings.NewReplacer(`"sha256": null`, `"sha256": "`+Hex0x(SHA256([]byte("x")))+`"`, `"present": false`, `"present": true`, `"reason_if_absent": "hors périmètre CT-1"`, `"reason_if_absent": null`).Replace(s[i:j])
		return s[:i] + bloc + s[j:]
	}}, false)
	os.WriteFile(filepath.Join(dir, "preuve.ots"), []byte("x"), 0o644)
	d := VerifierDossier(dir)
	if d.RaisonNonExecution("O-*") != RaisonNEPrerequis || !strings.Contains(strings.Join(d.Resultats.parID["O-*"].Details, " "), "vérification de CT-6 non exécutée par ce vérificateur") {
		t.Errorf("partie réservée : raison %q, détail %v", d.RaisonNonExecution("O-*"), d.Resultats.parID["O-*"].Details)
	}
}

// Attestation au-delà de 64 Mio : entrée inutilisable, code 2, taille_depassee.
func TestAttestationPlafond(t *testing.T) {
	src := publie("valide-seq-7-attestation-sans-inscription")
	dir := copierDossier(t, src, nil, false)
	f := filepath.Join(dir, "attestation-perimetre.json")
	if err := os.Truncate(f, PlafondAttestation+1); err != nil {
		t.Fatal(err)
	}
	if d := VerifierDossier(dir); d.Illisible == "" || d.TypeErreur != "taille_depassee" || d.Valide() {
		t.Errorf("attestation de 64 Mio + 1 : illisible %q, type %q", d.Illisible, d.TypeErreur)
	}
	if err := os.Truncate(f, TailleMaxPartieAttestation+1); err != nil {
		t.Fatal(err)
	}
	if d := VerifierDossier(dir); d.Illisible != "" || len(d.Perimetre) == 0 || d.Perimetre[0].Statut != "echoue" {
		t.Errorf("attestation de 4 Mio + 1 : illisible %q, AT %v", d.Illisible, d.PerimetreTexte())
	}
	if d := VerifierDossier(copierDossier(t, reference, map[string]func(string) string{"dossier.json": remplacerContenu("{")}, false)); d.TypeErreur != "dossier_illisible" {
		t.Errorf("index illisible : type %q", d.TypeErreur)
	}
}

// Forme de attendu.json pour le code 2 (§11.5) : exit_code et error_kind ;
// code et code_retour ne sont pas des noms reconnus.
func TestAttenduCode2(t *testing.T) {
	if v := objetDe(t, `{"valide":null,"controle":null,"controles_en_echec":[],"exit_code":2,"error_kind":"dossier_illisible"}`); !attenduCode2(v) || verdictAttenduTexte(v, true, nil) != "code 2, dossier_illisible" {
		t.Error("exit_code 2 non reconnu")
	}
	for _, s := range []string{`{"code":2}`, `{"code_retour":2}`, `{"exit_code":1}`} {
		if attenduCode2(objetDe(t, s)) {
			t.Errorf("%s ne déclare pas le code 2", s)
		}
	}
	rap := &Rapport{}
	comparerExiger4(rap, "v", objetDe(t, `{"exit_code_exiger_4":4}`))
	if len(rap.Comparaisons) != 1 || !rap.Comparaisons[0].HorsPerimetre {
		t.Error("exit_code_exiger_4 doit être rapporté hors périmètre")
	}
}

// Série (§10.5, compléments) : noms fermés, ordre des listes, raisons.
func TestSerieComplementsRevision05(t *testing.T) {
	racine := racineVecteursCT1
	f := filepath.Join(racine, "points-de-controle", "periode-1.json")
	if !fichierExiste(f) {
		t.Skip("vecteurs publiés absents")
	}
	points := lireTest(t, f).Arr
	m1 := LireManifeste(lireTest(t, filepath.Join(racine, "manifestes", "periode-1.json")))
	evs := lireTest(t, filepath.Join(racine, "journal-valide", "evenements.json")).Arr
	jeu, _ := ChargerCles(lireTest(t, filepath.Join(racine, "cles", "cles.json")))
	texte := func(regles []string, ne []RegleNonEvaluee) string {
		return strings.Join(regles, ",") + " | " + texteNonEvaluees(ne)
	}
	// Seq 5 manquant et seq 6 sans forme canonique : prerequis_en_echec avant
	// piece_hors_dossier, dans l'ordre des noms de règle.
	var partiels []*Value
	for _, ev := range evs {
		switch s, _ := SeqTypee(ev); s {
		case 5:
		case 6:
			c, _ := Canonique(ev)
			partiels = append(partiels, objetDe(t, strings.Replace(string(c), `"seq":6`, `"seq":6,"x":1.5`, 1)))
		default:
			partiels = append(partiels, ev)
		}
	}
	if regles, _, ne := ControlerSerie(points, m1, partiels, jeu, false); texte(regles, ne) != " | root:prerequis_en_echec,root:piece_hors_dossier,last_hash:piece_hors_dossier" {
		t.Errorf("seq 5 manquant, seq 6 non canonique : %s", texte(regles, ne))
	}
	// Sans cles.json ni événements : signature, validite_cle et cle_en_vigueur non évaluées.
	if regles, _, ne := ControlerSerie(points, m1, nil, nil, false); texte(regles, ne) != " | root:piece_hors_dossier,last_hash:piece_hors_dossier,cle_en_vigueur:piece_hors_dossier,signature:piece_hors_dossier,validite_cle:piece_hors_dossier" {
		t.Errorf("sans cles.json ni événements : %s", texte(regles, ne))
	}
	// cles.json défectueux : prerequis_en_echec.
	if regles, _, ne := ControlerSerie(points, m1, evs, jeu, true); texte(regles, ne) != " | cle_en_vigueur:prerequis_en_echec,signature:prerequis_en_echec,validite_cle:prerequis_en_echec" {
		t.Errorf("cles.json défectueux : %s", texte(regles, ne))
	}
	// Noms fermés : tree_size > count → last_seq ; clé inconnue → signature
	// (et cle_en_vigueur) ; point hors schéma → period_start.
	modifier := func(i int, f func(string) string) []*Value {
		c, _ := Canonique(points[i])
		out := append([]*Value{}, points...)
		out[i] = objetDe(t, f(string(c)))
		return out
	}
	der := len(points) - 1
	cas := map[string]struct {
		serie  []*Value
		regles string
	}{
		"tree_size > count": {modifier(der, remplacer(`"tree_size":9`, `"tree_size":10`)), "root,last_seq,dernier_point,signature"},
		"clé inconnue":      {modifier(0, remplacer(`"key_id":"rec-test-01"`, `"key_id":"rec-test-09"`)), "chainage,cle_en_vigueur,signature"},
		"point hors schéma": {modifier(0, remplacer(`"version":0`, `"version":0,"x":1`)), "chainage,period_start"},
	}
	for nom, c := range cas {
		regles, _, _ := ControlerSerie(c.serie, m1, evs, jeu, false)
		if got := strings.Join(regles, ","); got != c.regles {
			t.Errorf("%s : %s, attendu %s", nom, got, c.regles)
		}
		for _, r := range regles {
			if rangRegle(r) == len(ordreRegles) {
				t.Errorf("%s : nom de règle hors de la liste fermée : %s", nom, r)
			}
		}
	}
}

// Journal (§7.2, temps 3) : ts qui n'est pas une date existante, E-1 et
// horodatage sur les couples dont il est un terme.
func TestJournalTsInexistant(t *testing.T) {
	f := filepath.Join(racineVecteursCT1, "journal-valide", "evenements.json")
	if !fichierExiste(f) {
		t.Skip("vecteurs publiés absents")
	}
	evs := lireTest(t, f).Arr
	c, _ := Canonique(evs[4])
	ts := chaineDe(evs[4], "ts")
	alt := append(append(append([]*Value{}, evs[:4]...), objetDe(t, strings.Replace(string(c), ts, "2026-02-30"+ts[10:], 1))), evs[5:]...)
	_, s := ControlerJournal(alt, nil, nil)
	var out []string
	for _, x := range s {
		if x.Type == "schema" || x.Type == "horodatage" {
			out = append(out, x.Texte())
		}
	}
	if strings.Join(out, " ") != "schema/E-1/5 horodatage/C-1/5 horodatage/C-1/6" {
		t.Errorf("ts inexistant : %v", out)
	}
}

// Règle d'origine (prev_hash nul si et seulement si seq = 1) : évaluée
// seulement pour un seq entier ; sinon ni tenue ni violée, E-1 seule porte le
// défaut (CT-1 §7.2 temps 1, §11.4 « Autres termes mal typés », CT-6
// EX-5.13 ; vecteur journal-seq-chaine). Journal, puis dossier.
func TestOrigineSeqNonEntier(t *testing.T) {
	f := filepath.Join(racineVecteursCT1, "journal-valide", "evenements.json")
	if !fichierExiste(f) {
		t.Skip("vecteurs publiés absents")
	}
	evs := lireTest(t, f).Arr
	symptomes := func(evs []*Value) string {
		_, s := ControlerJournal(evs, nil, nil)
		var out []string
		for _, x := range s {
			out = append(out, x.Texte())
		}
		return strings.Join(out, " ")
	}
	// seq en chaîne, prev_hash nul : aucun symptôme origine.
	c, _ := Canonique(evs[6])
	enChaine := objetDe(t, strings.Replace(strings.Replace(string(c), `"seq":7`, `"seq":"7"`, 1), chaineDe(evs[6], "prev_hash"), Zero32, 1))
	if got := symptomes([]*Value{evs[5], enChaine}); strings.Contains(got, "origine") || !strings.Contains(got, "schema/E-1/null") {
		t.Errorf("journal, seq en chaîne : %s", got)
	}
	// seq entier, prev_hash nul hors seq 1 : la règle est évaluée et violée.
	entier := objetDe(t, strings.Replace(string(c), chaineDe(evs[6], "prev_hash"), Zero32, 1))
	if got := symptomes([]*Value{evs[5], entier}); !strings.Contains(got, "origine/C-2/7") {
		t.Errorf("journal, seq entier : %s", got)
	}
	// Dossier : evenement.json dont seq est une chaîne (avant : C-2 en échec
	// aussi par la règle d'origine) ; C-2 n'échoue que par next.prev_hash.
	d := VerifierDossier(copierDossier(t, reference, map[string]func(string) string{"evenement.json": remplacer(`"seq": 4,`, `"seq": "4",`)}, true))
	for _, x := range d.Resultats.parID["C-2"].Details {
		if strings.Contains(x, "seq = 1") || strings.Contains(x, "origine") {
			t.Errorf("dossier, seq en chaîne : C-2 par la règle d'origine : %s", x)
		}
	}
	r := NouveauxResultats()
	ControlerPremier(r, enChaine, "seq en chaîne")
	if r.parID["C-2"].Etat != EtatPasse {
		t.Errorf("ControlerPremier, seq en chaîne : %v", r.parID["C-2"])
	}
	r = NouveauxResultats()
	ControlerPremier(r, entier, "seq 7")
	if r.parID["C-2"].Etat != EtatEchoue {
		t.Errorf("ControlerPremier, seq 7 et prev_hash nul : %v", r.parID["C-2"])
	}
}
