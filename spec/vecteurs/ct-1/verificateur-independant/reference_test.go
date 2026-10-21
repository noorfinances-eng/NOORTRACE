package main

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// L'exemple de référence de CT-1 (annexe A, §5.5, §6.4, §9.4, §10, §11) est
// repris dans testdata/reference : cinq événements, deux manifestes, le
// dossier de seq 4. Chaque valeur imprimée par la spécification est
// recalculée ici.

func lireTest(t *testing.T, chemin string) *Value {
	t.Helper()
	octets, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatal(err)
	}
	v, err := ParseJSON(octets)
	if err != nil {
		t.Fatalf("%s : %v", chemin, err)
	}
	return v
}

func clesReference(t *testing.T) *JeuCles {
	t.Helper()
	jeu, mq := ChargerCles(lireTest(t, "testdata/reference/dossier-seq-4/cles.json"))
	if len(mq) > 0 {
		t.Fatalf("cles.json : %v", mq)
	}
	return jeu
}

var hashesReference = []string{
	"0x64994cc38adf2e7532b2f02fae0e78086b1970c5ffd36a37dc3c78143cfe8179",
	"0xdd3b7036baeca6426596377870f5982e00ac1e4de7fb344cd1b2c5fa4bbefce0",
	"0xadeb42cb3a4557effbf1bf2dd0a973a1e74563cd39fbb747202d6a4a0f5ad832",
	"0x471dab56146ae2e4c678120af7faf5eed7b1f8e5db3657226de97614bde4dc00",
	"0x506e54e1ec35a6432114fc06947b23c753ce6d5cf4260354b7fdbed011b04f05",
}

func TestReferenceJournal(t *testing.T) {
	evs := lireTest(t, "testdata/reference/journal.json").Arr
	cles := clesReference(t)
	if len(evs) != 5 {
		t.Fatalf("%d événements", len(evs))
	}
	for i, ev := range evs {
		h, c, err := HashEvenement(ev)
		if err != nil {
			t.Fatal(err)
		}
		if Hex0x(h) != hashesReference[i] {
			t.Errorf("seq %d : hash %s ≠ %s", i+1, Hex0x(h), hashesReference[i])
		}
		if i == 3 && len(c) != 2188 {
			t.Errorf("seq 4 : forme canonique de %d octets, 2188 attendus (§6.4)", len(c))
		}
		res := ControlerEvenement(ev, cles)
		if !res.Valide() {
			t.Errorf("seq %d : %v\n%s", i+1, res.Echecs(), res.Resume("  "))
		}
	}
	res := ControlerChaine(evs, cles)
	if !res.Valide() {
		t.Fatalf("chaîne : %v\n%s", res.Echecs(), res.Resume("  "))
	}
	if c := res.parID["E-9"]; c == nil || c.Etat != EtatHorsPerimetre {
		t.Error("E-9 doit être déclaré hors périmètre")
	}
	// Forme canonique de seq 4 (§6.4), début et fin.
	_, c, _ := HashEvenement(evs[3])
	if !strings.HasPrefix(string(c), `{"approval":{"approvers":["0x70997970c51812dc3a010c7d01b50e0d17dc79c8"`) ||
		!strings.HasSuffix(string(c), `"seq":4,"ts":"2026-11-03T13:52:41.090Z","version":0}`) {
		t.Errorf("forme canonique de seq 4 : %s", c)
	}
}

func TestReferenceApprobation(t *testing.T) {
	evs := lireTest(t, "testdata/reference/journal.json").Arr
	A := ObjetSigneApprobation(evs[2])
	c, err := Canonique(A)
	if err != nil {
		t.Fatal(err)
	}
	attendu := `{"decision":"approuve","journal_id":"0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b","org_id":"0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab","request_hash":"0xdd3b7036baeca6426596377870f5982e00ac1e4de7fb344cd1b2c5fa4bbefce0","ticket":"apr-1192"}`
	if string(c) != attendu {
		t.Errorf("JCS(A) = %s", c)
	}
	d, _ := CondenseApprobation(A)
	if Hex0x(d) != "0x59b49949b9e97d7e3fd9d46a3992476dd2cc27c48e25ef77b467816d144f37a7" {
		t.Errorf("D_A = %s", Hex0x(d))
	}
	// La valeur en ligne de seq 3 est A, et sa référence (E-6) est juste.
	if !memeCanonique(evs[2].Get("execution").Get("arguments").Get("value"), A) {
		t.Error("execution.arguments.value de seq 3 ≠ A")
	}
}

func TestReferenceRotation(t *testing.T) {
	evs := lireTest(t, "testdata/reference/journal.json").Arr
	r := NouveauxResultats()
	controlerRotation(r, evs[4], clesReference(t))
	if !r.Valide() {
		t.Fatalf("rotation : %s", r.Resume("  "))
	}
	// Une contresignature altérée est refusée (E-10).
	val := evs[4].Get("execution").Get("arguments").Get("value")
	cs := val.Get("counter_sig")
	cs.Str = "0x" + strings.Repeat("00", 64)
	r = NouveauxResultats()
	controlerRotation(r, evs[4], clesReference(t))
	if r.Valide() {
		t.Fatal("contresignature nulle acceptée")
	}
}

func TestReferenceManifestes(t *testing.T) {
	cles := clesReference(t)
	m1 := lireTest(t, "testdata/reference/dossier-seq-4/manifeste.json")
	s1 := lireTest(t, "testdata/reference/dossier-seq-4/manifeste.sig")
	m2 := lireTest(t, "testdata/reference/manifeste-2.json")
	s2 := lireTest(t, "testdata/reference/manifeste-2.sig")
	ph1, c1, _ := PeriodHash(m1)
	if Hex0x(ph1) != "0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1" {
		t.Errorf("periodHash période 1 = %s", Hex0x(ph1))
	}
	if !strings.HasPrefix(string(c1), `{"count":5,"first_seq":1,"generated_at":"2026-11-03T14:00:00.250Z"`) {
		t.Errorf("C_M = %s", c1)
	}
	ph2, _, _ := PeriodHash(m2)
	if Hex0x(ph2) != "0x3ed80e52f0d52f184986da64ba009947998cfd41624899ad5137594c58f9be4b" {
		t.Errorf("periodHash période 2 = %s", Hex0x(ph2))
	}
	for _, c := range []struct {
		m, s *Value
		nom  string
	}{{m1, s1, "période 1"}, {m2, s2, "période 2 (vide)"}} {
		res := ControlerManifeste(c.m, c.s, cles)
		if !res.Valide() {
			t.Errorf("%s : %s", c.nom, res.Resume("  "))
		}
	}
	r := NouveauxResultats()
	ControlerContinuite(r, m1, m2)
	if !r.Valide() {
		t.Errorf("continuité : %s", r.Resume("  "))
	}
	// Racine recalculée depuis le journal, et période vide.
	evs := lireTest(t, "testdata/reference/journal.json").Arr
	r = NouveauxResultats()
	racine := ControlerManifesteContreJournal(r, m1, evs)
	if !r.Valide() || Hex0x(racine) != "0x6782bad9bd4717caf61b261a0a7f86fa9263f4b5b76c1d80d4c3bfbe0512ed06" {
		t.Errorf("racine période 1 : %s\n%s", Hex0x(racine), r.Resume("  "))
	}
	r = NouveauxResultats()
	racine = ControlerManifesteContreJournal(r, m2, evs)
	if !r.Valide() || Hex0x(racine) != Zero32 {
		t.Errorf("racine période 2 : %s\n%s", Hex0x(racine), r.Resume("  "))
	}
	fp, err := AnchorFingerprintManifeste(m1)
	if err != nil || Hex0x(fp) != "0x3200e496c555b46459191c852a7f79b1e0b4156802cac2f2df7b80b0aa9d823b" {
		t.Errorf("anchorFingerprint = %s (%v)", Hex0x(fp), err)
	}
	// Une signature sous la mauvaise clé est refusée (P-5).
	s1.Get("recorder_key_id").Str = "rec-test-01"
	m1.Get("recorder_key_id").Str = "rec-test-01"
	if ControlerManifeste(m1, s1, cles).Valide() {
		t.Error("signature de manifeste acceptée sous une autre clé")
	}
}

// Les SHA-256 que dossier.json de la spécification (§11.1) déclare pour les
// fichiers écrits par JSON.stringify(objet, null, 2) suivi d'un saut de
// ligne : les sept fichiers sont reproduits ici octet pour octet
// (approbations.json est imprimé par §11.2, source du jeu comprise).
func TestReferenceEmpreintesDossier(t *testing.T) {
	attendus := map[string]string{
		"evenement.json":    "0x389595f49b2f8576ac9c6784f5cdb4f4cfc5ff6841d154c36f0457246bd11115",
		"voisins.json":      "0xe8f1b441393b1c743d162d69dc5406a240ed43431644321653d33e3bf78bb7b8",
		"chemin.json":       "0x128b24e022caccbfb5398e8dc6cbe2d4488fca71bfd066a358ccebcc5f85900b",
		"manifeste.json":    "0x2ba05975e6ce3c0dce6f44107a1406bc4389fdaddeb5d7ad2787c175b0baae2a",
		"manifeste.sig":     "0xc65e38f9dd1853e0989934335095ef543163e61c46da8b54b6986420de5d9251",
		"cles.json":         "0xd3832a43940191a60512937c61900c0b1a00299e5bb7177765d744bfd25c377f",
		"approbations.json": "0xa9b7effadb2793db2a5bc0ae8e4f9f7181aadcd9510860ef69071437da4341ba",
	}
	for f, a := range attendus {
		octets, err := os.ReadFile(filepath.Join("testdata/reference/dossier-seq-4", f))
		if err != nil {
			t.Fatal(err)
		}
		if got := Hex0x(SHA256(octets)); got != a {
			t.Errorf("%s : %s ≠ %s", f, got, a)
		}
	}
}

// dossierTemporaire copie le dossier de référence, applique des altérations
// (contenu de fichier → contenu modifié) et, si demandé, recalcule les
// empreintes de l'index pour que D-2 passe.
func dossierTemporaire(t *testing.T, alterations map[string]func(string) string, reindexer bool) string {
	t.Helper()
	src := "testdata/reference/dossier-seq-4"
	dst := t.TempDir()
	entrees, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entrees {
		octets, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		contenu := string(octets)
		if f, ok := alterations[e.Name()]; ok {
			contenu = f(contenu)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), []byte(contenu), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	aReindexer := map[string]bool{}
	if reindexer {
		for f := range alterations {
			aReindexer[f] = true
		}
	}
	index, err := os.ReadFile(filepath.Join(dst, "dossier.json"))
	if err != nil {
		t.Fatal(err)
	}
	texte := string(index)
	idx, err := ParseJSON(index)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range idx.Get("parts").Arr {
		f := chaineDe(p, "file")
		ancien := chaineDe(p, "sha256")
		if !aReindexer[f] || ancien == "" {
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

func remplacer(ancien, nouveau string) func(string) string {
	return func(s string) string {
		if !strings.Contains(s, ancien) {
			panic("altération sans effet : " + ancien)
		}
		return strings.Replace(s, ancien, nouveau, 1)
	}
}

func TestReferenceDossierValide(t *testing.T) {
	d := VerifierDossier(dossierTemporaire(t, nil, true))
	if !d.Resultats.Valide() {
		t.Fatalf("dossier de référence invalide :\n%s", d.Resultats.Resume("  "))
	}
	for id, etat := range map[string]Etat{"E-9": EtatHorsPerimetre, "A-4": EtatNonExecute, "D-1": EtatPasse, "D-2": EtatPasse,
		"E-7": EtatPasse, "E-8": EtatPasse, "E-10": EtatPasse, "E-11": EtatPasse, "C-1": EtatPasse, "C-2": EtatPasse, "C-3": EtatPasse,
		"M-1": EtatPasse, "M-2": EtatPasse, "M-3": EtatPasse, "P-1": EtatPasse, "P-2": EtatPasse, "P-3": EtatPasse, "P-4": EtatPasse, "P-5": EtatPasse,
		"A-1": EtatPasse, "A-2": EtatPasse, "A-3": EtatPasse} {
		c := d.Resultats.parID[id]
		if c == nil {
			t.Errorf("%s : contrôle absent du résultat", id)
		} else if c.Etat != etat {
			t.Errorf("%s : %s, attendu %s (%v)", id, c.Etat, etat, c.Details)
		}
	}
	if len(d.Bornes) == 0 || !strings.Contains(d.Bornes[0], "verdict borné") {
		t.Error("la borne du verdict (§11.3) doit être énoncée quand des parties sont absentes")
	}
	if !d.Valide() || len(d.NonExecutesNonAdmis()) != 0 {
		t.Errorf("le dossier de référence doit être valide au sens de §11.4 (A-4 non exécuté est admis) ; non admis : %v", d.NonExecutesNonAdmis())
	}
}

// Une partie présente réduite au littéral null (ou à un tableau) met en échec
// le seul contrôle qui la porte (§11.4) et rend le dossier invalide : rien n'est
// « non exécuté » en silence.
func TestReferencePartiesNulles(t *testing.T) {
	cas := map[string]string{"evenement.json": "E-1", "voisins.json": "C-1", "chemin.json": "M-2", "manifeste.json": "P-1", "manifeste.sig": "P-5", "cles.json": "E-8", "approbations.json": "A-1"}
	for _, contenu := range []string{"null\n", "[]\n"} {
		for f, ctrl := range cas {
			dir := dossierTemporaire(t, map[string]func(string) string{f: func(string) string { return contenu }}, true)
			d := VerifierDossier(dir)
			echecs := d.Resultats.Echecs()
			if len(echecs) != 1 || echecs[0] != ctrl {
				t.Errorf("%s = %q : échecs %v, attendu [%s]\n%s", f, strings.TrimSpace(contenu), echecs, ctrl, d.Resultats.Resume("  "))
			}
			if d.Valide() {
				t.Errorf("%s = %q : dossier déclaré valide", f, strings.TrimSpace(contenu))
			}
		}
	}
	// Un contrôle non exécuté sans raison admise rend le dossier invalide même sans échec.
	d := &Dossier{Resultats: NouveauxResultats(), Parties: map[string]*Partie{}}
	d.Resultats.Passe("E-1")
	d.Resultats.NonExecute("E-11", "clé absente")
	if d.Valide() || len(d.NonExecutesNonAdmis()) != 1 {
		t.Errorf("E-11 non exécuté doit rendre le dossier invalide : %v", d.NonExecutesNonAdmis())
	}
	d.Resultats.NonExecute("A-4", "demande hors dossier")
	if nonAdmis := d.NonExecutesNonAdmis(); len(nonAdmis) != 1 || nonAdmis[0] != "E-11" {
		t.Errorf("A-4 non exécuté est admis : %v", nonAdmis)
	}
}

// Table 5.3 : un échange avec le modèle sans result, duration_ms ni is_error
// est refusé par le schéma (E-1) et par la cohérence de sorte (E-3).
func TestReferenceEchangeSansReponse(t *testing.T) {
	ev := lireTest(t, "testdata/reference/journal.json").Arr[0]
	x := ev.Get("execution")
	for i := range x.Obj {
		switch x.Obj[i].Key {
		case "result", "duration_ms", "is_error":
			x.Obj[i].Val = &Value{Kind: KindNull}
		}
	}
	res := ControlerEvenement(ev, clesReference(t))
	echecs := res.Echecs()
	for _, id := range []string{"E-1", "E-3"} {
		if !dansEnum(id, echecs) {
			t.Errorf("%s attendu en échec, obtenu %v\n%s", id, echecs, res.Resume("  "))
		}
	}
}

// P-3 : le manifeste de la période 1 refait sur quatre feuilles (last_seq = 4)
// et re-signé par rec-test-02 ; le dossier de seq 4 porte alors un voisin
// suivant (seq 5, 13:59:59.999Z) hors de l'intervalle de seq mais horodaté
// dans la période : la troncature est détectée, et par P-3 seul.
func TestReferencePeriodeTronquee(t *testing.T) {
	evs := lireTest(t, "testdata/reference/journal.json").Arr
	var D [][]byte
	for _, ev := range evs[:4] {
		h, _, err := HashEvenement(ev)
		if err != nil {
			t.Fatal(err)
		}
		D = append(D, h)
	}
	m := lireTest(t, "testdata/reference/dossier-seq-4/manifeste.json")
	m.Get("last_seq").Num = "4"
	m.Get("count").Num = "4"
	m.Get("root").Str = Hex0x(Racine(D))
	cm, err := Canonique(m)
	if err != nil {
		t.Fatal(err)
	}
	ph := SHA256Prefixe(PrefixeManifeste, cm)
	priv := ed25519.NewKeyFromSeed(GraineCleTest("rec-test-02"))
	sig := ed25519.Sign(priv, append(append([]byte{}, PrefixeSignatureManifeste...), cm...))
	sigTexte := fmt.Sprintf("{\"version\":0,\"period_hash\":%q,\"recorder_key_id\":\"rec-test-02\",\"sig\":%q}\n", Hex0x(ph), Hex0x(sig))
	var chemin []string
	for _, h := range Chemin(3, D) {
		chemin = append(chemin, fmt.Sprintf("%q", Hex0x(h)))
	}
	cheminTexte := fmt.Sprintf("{\"version\":0,\"tree_size\":4,\"leaf_index\":3,\"leaf_hash\":%q,\"path\":[%s],\"root\":%q}\n", Hex0x(Feuille(D[3])), strings.Join(chemin, ","), Hex0x(Racine(D)))
	dir := dossierTemporaire(t, map[string]func(string) string{
		"manifeste.json": func(string) string { return string(cm) + "\n" },
		"manifeste.sig":  func(string) string { return sigTexte },
		"chemin.json":    func(string) string { return cheminTexte },
	}, true)
	d := VerifierDossier(dir)
	if echecs := d.Resultats.Echecs(); len(echecs) != 1 || echecs[0] != "P-3" {
		t.Fatalf("échecs %v, attendu [P-3]\n%s", echecs, d.Resultats.Resume("  "))
	}
}

// Dossiers invalides de §11.5 : chaque altération minimale doit faire échouer
// le contrôle visé (et, parfois, ses conséquences inévitables).
func TestReferenceDossiersAlteres(t *testing.T) {
	cas := []struct {
		nom         string
		fichier     string
		alteration  func(string) string
		reindexer   bool
		attendus    []string
		nonAttendus []string
	}{
		{"intent modifié", "evenement.json", remplacer("2026-77812 après", "2026-77813 après"), true, []string{"E-7", "E-8", "C-2", "M-1"}, []string{"D-1", "D-2"}},
		{"hash réécrit (contenu intact)", "evenement.json", remplacer(`"hash": "0x471dab56`, `"hash": "0x571dab56`), true, []string{"E-7"}, []string{"E-8", "C-2", "M-1"}},
		{"seq du voisin décalé", "voisins.json", remplacer(`"seq": 5,`, `"seq": 6,`), true, []string{"C-1"}, nil},
		{"path permuté", "chemin.json", func(s string) string {
			a, b := "0x8380b74438d71a5fb81aa3b62f1c7e0b06cb0e9c73f5d5a42f44372e203fbf3e", "0xa5b5b030de6510a06da18b109b73e7b85c4afe3e6d0fb89b4bd9b53b3d42f79e"
			return strings.Replace(strings.Replace(strings.Replace(s, a, "X", 1), b, a, 1), "X", b, 1)
		}, true, []string{"M-2"}, []string{"M-1", "M-3"}},
		{"path tronqué", "chemin.json", remplacer(",\n    \"0xa93b6b900d821b68a351fb3e8e986f8298a21254f1c348f108843f7ede2f1ec0\"", ""), true, []string{"M-2"}, []string{"M-1", "M-3"}},
		{"leaf_index décalé", "chemin.json", remplacer(`"leaf_index": 3`, `"leaf_index": 2`), true, []string{"M-2", "M-3"}, []string{"M-1"}},
		{"racine nulle avec count = 5", "manifeste.json", remplacer("0x6782bad9bd4717caf61b261a0a7f86fa9263f4b5b76c1d80d4c3bfbe0512ed06", Zero32), true, []string{"P-1", "P-4", "M-3"}, nil},
		{"un seul approbateur pour un seuil de 2", "evenement.json", func(s string) string {
			s = remplacer(",\n      \"0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc\"", "")(s)
			return remplacer(",\n      \"0xed53b07b60869c24a79d2f3db4729bdbc7ff581b1540e19e188f15ffed99d73f1f69b4e247299dcaecf9d69ad3487c313cd48fc1a7d7874f0a55a27330c074151b\"", "")(s)
		}, true, []string{"A-3"}, nil},
		{"même approbateur deux fois", "evenement.json", remplacer("0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc", "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"), true, []string{"E-1", "A-3"}, nil},
		{"nombre 412.0 dans duration_ms", "evenement.json", remplacer(`"duration_ms": 412,`, `"duration_ms": 412.0,`), true, []string{"E-2"}, nil},
		{"clé en majuscules dans un hex", "evenement.json", remplacer(`"prompt_version": "0xb715`, `"prompt_version": "0xB715`), true, []string{"E-1"}, nil},
		{"ts avant celui du voisin précédent", "voisins.json", remplacer(`"ts": "2026-11-03T13:52:40.511Z",
    "org_id"`, `"ts": "2026-11-03T13:52:42.000Z",
    "org_id"`), true, []string{"C-1"}, nil},
		{"rotation sans contresignature valide", "voisins.json", remplacer("0xe107f72204e19597866fb4967e8c30285027f5f87af7fe865a7360c640a8926d", "0xe107f72204e19597866fb4967e8c30285027f5f87af7fe865a7360c640a8926e"), true, []string{"E-10"}, nil},
		{"clé hors de sa période annoncée", "cles.json", remplacer(`"valid_from": "2026-11-01T00:00:00.000Z"`, `"valid_from": "2026-11-03T13:52:41.500Z"`), true, []string{"E-11"}, nil},
		{"signature de manifeste sous une autre clé", "manifeste.sig", remplacer(`"recorder_key_id": "rec-test-02"`, `"recorder_key_id": "rec-test-01"`), true, []string{"P-5"}, nil},
		{"fichier modifié après l'index", "chemin.json", remplacer(`"leaf_index": 3`, `"leaf_index":  3`), false, []string{"D-2"}, []string{"M-1", "M-2", "M-3"}},
		{"validité annoncée de l'ancienne clé différente du ts de la rotation (§8 règle 3)", "cles.json", remplacer(`"valid_to": "2026-11-03T13:59:59.999Z"`, `"valid_to": "2026-11-03T14:30:00.000Z"`), true, []string{"E-10"}, []string{"E-8", "E-11"}},
		{"validité annoncée de la nouvelle clé différente du ts de la rotation", "cles.json", remplacer(`"valid_from": "2026-11-03T13:59:59.999Z"`, `"valid_from": "2026-11-03T13:00:00.000Z"`), true, []string{"E-10"}, []string{"E-8", "E-11"}},
		{"key_id en double dans cles.json", "cles.json", remplacer(`"key_id": "rec-test-02"`, `"key_id": "rec-test-01"`), true, []string{"E-8"}, nil},
		{"cles.json d'un autre journal", "cles.json", remplacer(`"journal_id": "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b"`, `"journal_id": "0x41c240366d993e0f2a4031f7177f26cb33a68f87652b51e0979dd863f21c5164"`), true, []string{"E-8"}, []string{"E-11", "P-5"}},
		{"approval.at postérieur au ts de l'appel relayé (A-2)", "evenement.json", remplacer(`"at": "2026-11-03T13:52:40.511Z"`, `"at": "2026-11-03T13:52:41.500Z"`), true, []string{"E-7", "A-2"}, nil},
		{"approbations.json absent alors que approval ≠ null", "dossier.json", func(s string) string {
			s = remplacer(`"sha256": "0xa9b7effadb2793db2a5bc0ae8e4f9f7181aadcd9510860ef69071437da4341ba",
      "present": true,
      "reason_if_absent": null`, `"sha256": null,
      "present": false,
      "reason_if_absent": "aucune approbation liée"`)(s)
			return s
		}, true, []string{"A-1", "D-2"}, nil},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			dir := dossierTemporaire(t, map[string]func(string) string{c.fichier: c.alteration}, c.reindexer)
			d := VerifierDossier(dir)
			echecs := d.Resultats.Echecs()
			for _, a := range c.attendus {
				if !dansEnum(a, echecs) {
					t.Errorf("%s attendu en échec, obtenu %v\n%s", a, echecs, d.Resultats.Resume("  "))
				}
			}
			for _, n := range c.nonAttendus {
				if dansEnum(n, echecs) {
					t.Errorf("%s ne devrait pas échouer, obtenu %v\n%s", n, echecs, d.Resultats.Resume("  "))
				}
			}
		})
	}
}

func TestComparerVerdictSemantique(t *testing.T) {
	r := NouveauxResultats()
	r.Echec("E-7", "x")
	r.Echec("C-2", "y")
	r.HorsPerimetre("E-9", "z")
	rap := &Rapport{}
	if !comparerVerdict(rap, "t", "v", false, []string{"E-7"}, r, false) {
		t.Error("inclusion : E-7 ⊆ {E-7, C-2} doit concorder")
	}
	if comparerVerdict(rap, "t", "v", false, []string{"E-7"}, r, true) {
		t.Error("strict : {E-7} ≠ {E-7, C-2} ne doit pas concorder")
	}
	if comparerVerdict(rap, "t", "v", true, nil, r, false) {
		t.Error("attendu valide avec des échecs ne doit pas concorder")
	}
	comparerVerdict(rap, "t", "v", false, []string{"E-9"}, NouveauxResultats(), false)
	if last := rap.Comparaisons[len(rap.Comparaisons)-1]; !last.HorsPerimetre {
		t.Error("E-9 attendu seul doit être hors périmètre")
	}
	_, c, d, hp := rap.Comptes()
	if c != 1 || d != 2 || hp != 1 {
		t.Errorf("comptes %d %d %d", c, d, hp)
	}
	va, ids, present := lireAttendu(&Value{Kind: KindObject, Obj: []Member{
		{"valide", &Value{Kind: KindBool}},
		{"diagnostics", &Value{Kind: KindArray, Arr: []*Value{{Kind: KindObject, Obj: []Member{{"controle", &Value{Kind: KindString, Str: "C-1"}}}}}}},
	}})
	if va || !present || len(ids) != 1 || ids[0] != "C-1" {
		t.Errorf("lireAttendu : %v %v %v", va, ids, present)
	}
}

// Les vecteurs publiés (spec/vecteurs/ct-1), s'ils sont présents à côté du
// module, doivent tous concorder (les valeurs hors périmètre exceptées).
func TestVecteursPublies(t *testing.T) {
	racine := ".."
	if !fichierExiste(filepath.Join(racine, "cles")) && !fichierExiste(filepath.Join(racine, "dossiers")) {
		t.Skip("vecteurs publiés absents")
	}
	rap := VerifierVecteurs(racine, false)
	n, c, d, hp := rap.Comptes()
	t.Logf("%d valeur(s) recalculée(s), %d concordante(s), %d discordante(s), %d hors périmètre, %d erreur(s)", n, c, d, hp, len(rap.Erreurs))
	if !rap.ToutConcorde() {
		var sb strings.Builder
		rap.EcrireTexte(&sb, false)
		t.Fatal(sb.String())
	}
	if n < 100 {
		t.Errorf("trop peu de valeurs recalculées : %d", n)
	}
}
