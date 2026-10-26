package main

import (
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// Point K2 de l'exemple de référence de CT-1 §10.6 : forme canonique C_K,
// checkpointHash et signature sous rec-test-01.
const pointK2 = `{"version":0,"org_id":"0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab","journal_id":"0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b","period_start":1793710800,"tree_size":4,"root":"0x22264c23c7f8fea323dd1998376576e0fa4d14c67dc577dc7a01e5ae9c2e4cf6","last_seq":4,"last_hash":"0x471dab56146ae2e4c678120af7faf5eed7b1f8e5db3657226de97614bde4dc00","checkpoint_ts":"2026-11-03T13:53:00.000Z","prev_checkpoint_hash":"0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4","key_id":"rec-test-01","sig":"0x29f6f3f6463ecba15185a160d923033e48d4c15f97f747105894b0dd49a3e021b489a9b6591416fcc71f68e174a251d9cf790fcbac39b6fdc74fd6a61f49870f"}`

const canoniqueK2 = `{"checkpoint_ts":"2026-11-03T13:53:00.000Z","journal_id":"0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b","key_id":"rec-test-01","last_hash":"0x471dab56146ae2e4c678120af7faf5eed7b1f8e5db3657226de97614bde4dc00","last_seq":4,"org_id":"0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab","period_start":1793710800,"prev_checkpoint_hash":"0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4","root":"0x22264c23c7f8fea323dd1998376576e0fa4d14c67dc577dc7a01e5ae9c2e4cf6","tree_size":4,"version":0}`

func TestPointK2Reference(t *testing.T) {
	v, err := ParseJSON([]byte(pointK2))
	if err != nil {
		t.Fatal(err)
	}
	if mq := ValiderSchemaPoint(v); len(mq) > 0 {
		t.Fatalf("schéma : %v", mq)
	}
	hash, c, err := CheckpointHash(v)
	if err != nil {
		t.Fatal(err)
	}
	if string(c) != canoniqueK2 {
		t.Errorf("C_K :\n%s", c)
	}
	if got := Hex0x(hash); got != "0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff" {
		t.Errorf("checkpointHash %s", got)
	}
	cles := clesReference(t)
	if err := VerifierSignaturePoint(v, cles.Trouver("rec-test-01")); err != nil {
		t.Errorf("signature sous rec-test-01 : %v", err)
	}
	if err := VerifierSignaturePoint(v, cles.Trouver("rec-test-02")); err == nil {
		t.Error("la signature ne doit pas vérifier sous rec-test-02")
	}
	// Racine nulle si et seulement si tree_size = 0.
	altere := strings.Replace(pointK2, `"tree_size":4`, `"tree_size":0`, 1)
	va, _ := ParseJSON([]byte(altere))
	if mq := ValiderSchemaPoint(va); len(mq) == 0 {
		t.Error("tree_size = 0 avec une racine non nulle doit être refusé")
	}
	// Clé en vigueur sur le journal de référence : seq 4 est signé par rec-test-01 ; seq 5 est la rotation vers rec-test-02.
	evs := lireTest(t, "testdata/reference/journal.json").Arr
	if got := CleEnVigueur(evs, 4); got != "rec-test-01" {
		t.Errorf("clé en vigueur à seq 4 : %q", got)
	}
	if got := CleEnVigueur(evs, 5); got != "rec-test-02" {
		t.Errorf("clé en vigueur après la rotation de seq 5 : %q", got)
	}
	if got := CleEnVigueur(evs, 0); got != "" {
		t.Errorf("aucun événement avant seq 1 : %q", got)
	}
}

// Preuves de cohérence des vecteurs historiques de Certificate Transparency
// (RFC 9162 §2.1.4, feuilles et nœuds de merkle_test.go) : (1, 8), (6, 8),
// (2, 5), (6, 7), et les sondes de corruption de CT-1 §10.7.
func TestPreuveCoherenceRFC9162(t *testing.T) {
	n0, n1, n2 := noeudsRFC6962[0], noeudsRFC6962[1], noeudsRFC6962[2]
	cas := []struct {
		m, n   int
		preuve [][]byte
	}{
		{1, 8, [][]byte{n0[1], n1[1], n2[1]}},
		{6, 8, [][]byte{n1[2], n1[3], n2[0]}},
		{2, 5, [][]byte{n1[1], n0[4]}},
		{6, 7, [][]byte{n1[2], n0[6], n2[0]}},
		{1, 1, [][]byte{}},
		{8, 8, [][]byte{}},
	}
	for _, c := range cas {
		got, err := PreuveCoherence(c.m, entreesRFC6962[:c.n])
		if err != nil {
			t.Fatalf("PROOF(%d, %d) : %v", c.m, c.n, err)
		}
		if len(got) != len(c.preuve) {
			t.Fatalf("PROOF(%d, %d) : %d nœuds, %d attendus", c.m, c.n, len(got), len(c.preuve))
		}
		for i := range got {
			if !bytes.Equal(got[i], c.preuve[i]) {
				t.Errorf("PROOF(%d, %d)[%d] = %s", c.m, c.n, i, Hex0x(got[i]))
			}
		}
		if err := VerifierCoherence(uint64(c.m), uint64(c.n), racinesRFC6962[c.m], racinesRFC6962[c.n], got); err != nil {
			t.Errorf("vérification (%d, %d) : %v", c.m, c.n, err)
		}
	}
	// Toutes les paires (m, n) jusqu'à 8 se génèrent et se vérifient ; les sondes sont refusées.
	for n := 1; n <= 8; n++ {
		for m := 1; m <= n; m++ {
			p, err := PreuveCoherence(m, entreesRFC6962[:n])
			if err != nil {
				t.Fatal(err)
			}
			if len(p) > 4 {
				t.Errorf("(%d, %d) : %d nœuds, au plus ceil(log2 n) + 1 = 4", m, n, len(p))
			}
			fr, sr := racinesRFC6962[m], racinesRFC6962[n]
			if err := VerifierCoherence(uint64(m), uint64(n), fr, sr, p); err != nil {
				t.Errorf("(%d, %d) : %v", m, n, err)
			}
			if m == n {
				if err := VerifierCoherence(uint64(m), uint64(n), fr, sr, [][]byte{fr}); err != ErrCoherenceCheminNonVide {
					t.Errorf("(%d, %d) chemin non vide : %v", m, n, err)
				}
				continue
			}
			if err := VerifierCoherence(uint64(m), uint64(n), sr, fr, p); err == nil {
				t.Errorf("(%d, %d) racines échangées acceptées", m, n)
			}
			if err := VerifierCoherence(uint64(m), uint64(n), fr, sr, p[:len(p)-1]); err == nil {
				t.Errorf("(%d, %d) chemin tronqué accepté", m, n)
			}
			if err := VerifierCoherence(uint64(m), uint64(n), fr, sr, append(append([][]byte{}, p...), p[0])); err == nil {
				t.Errorf("(%d, %d) nœud en trop accepté", m, n)
			}
			if len(p) > 1 {
				permute := append([][]byte{p[1], p[0]}, p[2:]...)
				if err := VerifierCoherence(uint64(m), uint64(n), fr, sr, permute); err == nil {
					t.Errorf("(%d, %d) chemin permuté accepté", m, n)
				}
			}
		}
	}
	if _, err := PreuveCoherence(0, entreesRFC6962[:5]); err != ErrCoherenceHorsDefinition {
		t.Errorf("m = 0 : %v", err)
	}
	if _, err := PreuveCoherence(5, entreesRFC6962[:3]); err != ErrCoherenceHorsDefinition {
		t.Errorf("m > n : %v", err)
	}
	if err := VerifierCoherence(0, 5, nil, nil, nil); err != ErrCoherenceHorsDefinition {
		t.Errorf("vérification m = 0 : %v", err)
	}
	if err := VerifierCoherence(3, 5, racinesRFC6962[3], racinesRFC6962[5], nil); err != ErrCoherenceCheminVide {
		t.Errorf("chemin vide : %v", err)
	}
	// m puissance de deux : la racine de l'ancien arbre est préposée (4 → 8 : un seul nœud).
	p, _ := PreuveCoherence(4, entreesRFC6962[:8])
	if len(p) != 1 || !bytes.Equal(p[0], n2[1]) {
		t.Errorf("PROOF(4, 8) = %d nœud(s)", len(p))
	}
}

// Les dossiers publiés qui portent la treizième partie : K-1 à K-6 exécutées,
// K-7 à K-9 non exécutées pour une raison admise (ancres nulles).
func TestVecteursPubliesPointsDeControle(t *testing.T) {
	dir := filepath.Join("..", "dossiers", "valide-seq-7-point-de-controle")
	if !fichierExiste(filepath.Join(dir, "dossier.json")) {
		t.Skip("vecteurs publiés absents")
	}
	d := VerifierDossier(dir)
	if !d.Valide() {
		t.Fatalf("dossier attendu valide :\n%s", d.Resultats.Resume("  "))
	}
	for _, id := range []string{"K-1", "K-2", "K-3", "K-4", "K-5", "K-6"} {
		if c := d.Resultats.parID[id]; c == nil || c.Etat != EtatPasse {
			t.Errorf("%s : %v", id, c)
		}
	}
	for _, id := range []string{"K-7", "K-8", "K-9"} {
		if c := d.Resultats.parID[id]; c == nil || c.Etat != EtatNonExecute || !d.admis[id] {
			t.Errorf("%s doit être non exécuté pour une raison admise : %v", id, c)
		}
	}
	absent := VerifierDossier(filepath.Join("..", "dossiers", "valide-seq-7-partie-declaree-absente"))
	if !absent.Valide() {
		t.Fatalf("partie déclarée absente : dossier attendu valide :\n%s", absent.Resultats.Resume("  "))
	}
	// Index à douze parties ou partie déclarée absente (§11.1, §11.4, alignés
	// sur CT-6 EX-5.7) : verdict inchangé, aucune K- au rapport.
	douze := VerifierDossier(filepath.Join("..", "dossiers", "valide-seq-7"))
	if !douze.Valide() {
		t.Fatalf("valide-seq-7 attendu valide :\n%s", douze.Resultats.Resume("  "))
	}
	for _, r := range []*Dossier{douze, absent} {
		for _, id := range idsK {
			if c := r.Resultats.parID[id]; c != nil {
				t.Errorf("partie points-de-controle.json absente : %s ne doit pas figurer au rapport : %v", id, c)
			}
		}
	}
	for _, c := range []struct{ nom, controle string }{{"invalide-k1-point-autre-periode", "K-1"}, {"invalide-k2-checkpoint-hash", "K-2"}, {"invalide-k3-signature-point", "K-3"}, {"invalide-k4-point-trop-court", "K-4"}, {"invalide-k5-coherence-tronquee", "K-5"}, {"invalide-k6-last-hash", "K-6"}} {
		r := VerifierDossier(filepath.Join("..", "dossiers", c.nom))
		if e := r.Resultats.Echecs(); len(e) != 1 || e[0] != c.controle {
			t.Errorf("%s : échecs %v, attendu [%s]", c.nom, e, c.controle)
		}
	}
}

// Forme canonique du premier point de la période vide (K5), imprimée par
// CT-1 §10.8.
const canoniqueK5 = `{"checkpoint_ts":"2026-11-03T14:01:00.000Z","journal_id":"0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b","key_id":"rec-test-02","last_hash":"0x506e54e1ec35a6432114fc06947b23c753ce6d5cf4260354b7fdbed011b04f05","last_seq":5,"org_id":"0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab","period_start":1793714400,"prev_checkpoint_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","root":"0x0000000000000000000000000000000000000000000000000000000000000000","tree_size":0,"version":0}`

// Série des points de l'exemple de référence (CT-1 §10.8) : les six points K1
// à K6 reconstruits depuis la table (racines et last_hash recalculés depuis le
// journal de l'annexe A), checkpointHash et signature de chacun, règles de
// série de §10.5 sur les deux périodes (dont la période vide), forme canonique
// de K5, racines des préfixes et preuves de cohérence PROOF(m, D[5]) ; enfin
// la partie points-de-controle.json de §11.2 (K2, PROOF(4, D[5]) = [L(4)]).
func TestExempleCT1Section108(t *testing.T) {
	evs := lireTest(t, "testdata/reference/journal.json").Arr
	cles := clesReference(t)
	var D [][]byte
	for _, ev := range evs {
		h, _, err := HashEvenement(ev)
		if err != nil {
			t.Fatal(err)
		}
		D = append(D, h)
	}
	const org = "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab"
	const journal = "0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b"
	table := []struct {
		periodStart, treeSize, lastSeq int64
		root, ts, prev, key, hash, sig string
	}{
		{1793710800, 2, 2, "0xa5b5b030de6510a06da18b109b73e7b85c4afe3e6d0fb89b4bd9b53b3d42f79e", "2026-11-03T13:42:00.000Z", Zero32, "rec-test-01", "0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4", "0x96c006c0f2be56f834413b6ee08961badd810c893bbdd9d40bb5d48bd498f7d66b89cb29979e0907e48b4ec33250e7f0b89f89447f0d4f57d78b11cf6675c409"},
		{1793710800, 4, 4, "0x22264c23c7f8fea323dd1998376576e0fa4d14c67dc577dc7a01e5ae9c2e4cf6", "2026-11-03T13:53:00.000Z", "0xfbc4715789d5bfeec5b3a0b44e26d13236a726950e92e03a2fce8c6f7b4284f4", "rec-test-01", "0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff", "0x29f6f3f6463ecba15185a160d923033e48d4c15f97f747105894b0dd49a3e021b489a9b6591416fcc71f68e174a251d9cf790fcbac39b6fdc74fd6a61f49870f"},
		{1793710800, 4, 4, "0x22264c23c7f8fea323dd1998376576e0fa4d14c67dc577dc7a01e5ae9c2e4cf6", "2026-11-03T13:54:00.000Z", "0x6a8e035ab9b90937a5b0d41118567c952f3ce49c895b81636ab70b516253e6ff", "rec-test-01", "0x3feb86ac4d6d8c054bef224f131f0276d2f1c9c9db2a6ce06adec173378d8867", "0x8e37a2cf042ceacaab8d81df08591802228330d76e398a2fe1813ec10b6d2bb9c68282f3e6a481a4723ec76fd48179f76568cfec12e7c1ba32d2120cbf2a4c0a"},
		{1793710800, 5, 5, "0x6782bad9bd4717caf61b261a0a7f86fa9263f4b5b76c1d80d4c3bfbe0512ed06", "2026-11-03T14:00:00.250Z", "0x3feb86ac4d6d8c054bef224f131f0276d2f1c9c9db2a6ce06adec173378d8867", "rec-test-02", "0x804585ae4e9601a9405fdff8d7d01988d5071999e70c6092f4137f0669ac7107", "0xe2dd1ae0b182e6da7d34a6ebb611dc8a628297a09b03e987e921f8c71659c572fcf70b428f678380fb4c05d73bf6118a41d5e25ffb7d10eb8e689a426c63e80e"},
		{1793714400, 0, 5, Zero32, "2026-11-03T14:01:00.000Z", Zero32, "rec-test-02", "0x3c4bd86148138e52a1ef6912c7ab4fa98ffdaf90879900887833e726b5a9e153", "0x7bd3835f0f686cdd5141f0d0d590b293a09724cd1bce9b6ffd3e337f3dfa189f77945264ca4a0743d6e5e35c164dc7f81f64b877974b497a567094b6a130730f"},
		{1793714400, 0, 5, Zero32, "2026-11-03T15:00:00.112Z", "0x3c4bd86148138e52a1ef6912c7ab4fa98ffdaf90879900887833e726b5a9e153", "rec-test-02", "0xd6e22871885b68962dadee69f9fa2ff3a76949d23550d1682d3564bcc705474d", "0x4993daaf14482da9001d4eb6123dab4720cfa62f8da39e8ecc9a7cdd547d67c520acaaddddfa6684e6a1a368ae0f4e982c019c254ecf2e64f8aff26a591c0d02"},
	}
	var points []*Value
	for i, k := range table {
		nom := fmt.Sprintf("K%d", i+1)
		// Règle 2 de §10.5 : racine des n premières feuilles de la période (nulle
		// pour n = 0), last_hash = hash de l'événement last_seq.
		racine := Zero32
		if k.treeSize > 0 {
			racine = Hex0x(Racine(D[:k.treeSize]))
		}
		if racine != k.root {
			t.Errorf("%s : racine recalculée %s ≠ %s", nom, racine, k.root)
		}
		lastHash := Hex0x(D[k.lastSeq-1])
		texte := fmt.Sprintf(`{"version":0,"org_id":%q,"journal_id":%q,"period_start":%d,"tree_size":%d,"root":%q,"last_seq":%d,"last_hash":%q,"checkpoint_ts":%q,"prev_checkpoint_hash":%q,"key_id":%q,"sig":%q}`,
			org, journal, k.periodStart, k.treeSize, k.root, k.lastSeq, lastHash, k.ts, k.prev, k.key, k.sig)
		v, err := ParseJSON([]byte(texte))
		if err != nil {
			t.Fatal(err)
		}
		if mq := ValiderSchemaPoint(v); len(mq) > 0 {
			t.Errorf("%s : schéma : %v", nom, mq)
		}
		hash, _, err := CheckpointHash(v)
		if err != nil {
			t.Fatal(err)
		}
		if got := Hex0x(hash); got != k.hash {
			t.Errorf("%s : checkpointHash %s ≠ %s", nom, got, k.hash)
		}
		if err := VerifierSignaturePoint(v, cles.Trouver(k.key)); err != nil {
			t.Errorf("%s : signature sous %s : %v", nom, k.key, err)
		}
		if en := CleEnVigueur(evs, k.lastSeq); en != k.key {
			t.Errorf("%s : clé en vigueur %s ≠ %s", nom, en, k.key)
		}
		points = append(points, v)
	}
	// Règles de série (§10.5, règles 2 à 5) : K1 à K4 contre le manifeste de la
	// période 1, K5 et K6 contre celui de la période vide.
	m1 := LireManifeste(lireTest(t, "testdata/reference/dossier-seq-4/manifeste.json"))
	m2 := LireManifeste(lireTest(t, "testdata/reference/manifeste-2.json"))
	if regles, erreurs := ControlerSerie(points[:4], m1, evs, cles); len(regles) > 0 {
		t.Errorf("période 1 : règles violées %v : %v", regles, erreurs)
	}
	if regles, erreurs := ControlerSerie(points[4:], m2, evs, cles); len(regles) > 0 {
		t.Errorf("période vide : règles violées %v : %v", regles, erreurs)
	}
	// Sondes sur la série : K4 retiré (règle 4), K3 avant K2 (règle 3), K2 signé
	// par la mauvaise clé (règle 5), last_hash de K6 faux (règle 2).
	if regles, _ := ControlerSerie(points[:3], m1, evs, cles); strings.Join(regles, ",") != "dernier_point" {
		t.Errorf("sans point de clôture : %v", regles)
	}
	if regles, _ := ControlerSerie([]*Value{points[0], points[2], points[1], points[3]}, m1, evs, cles); !strings.Contains(strings.Join(regles, ","), "chainage") {
		t.Errorf("points permutés : %v", regles)
	}
	k2Autre, _ := ParseJSON([]byte(strings.Replace(pointK2, `"key_id":"rec-test-01"`, `"key_id":"rec-test-02"`, 1)))
	if regles, _ := ControlerSerie([]*Value{points[0], k2Autre, points[2], points[3]}, m1, evs, cles); !strings.Contains(strings.Join(regles, ","), "signature") || !strings.Contains(strings.Join(regles, ","), "cle_en_vigueur") {
		t.Errorf("K2 attribué à rec-test-02 : %v", regles)
	}
	k6Faux, _ := ParseJSON([]byte(strings.Replace(strings.Replace(canoniqueK5, `"last_hash":"0x506e`, `"last_hash":"0x506f`, 1), `,"version":0}`, `,"version":0,"sig":"0x`+strings.Repeat("00", 64)+`"}`, 1)))
	if regles, _ := ControlerSerie([]*Value{k6Faux}, m2, evs, nil); strings.Join(regles, ",") != "last_hash" {
		t.Errorf("période vide, last_hash faux : %v", regles)
	}
	// K5 complet : forme canonique de §10.8.
	if _, c, _ := CheckpointHash(points[4]); string(c) != canoniqueK5 {
		t.Errorf("C_K de K5 :\n%s", c)
	}
	// Racines des préfixes MTH(D[0..m-1]) et preuves PROOF(m, D[5]).
	prefixes := []string{
		"0xd5e2098df5be8721f7343aab8ad414a5bea5b55bb0fb0e72eb8fb9bb6c3f5a8b",
		"0xa5b5b030de6510a06da18b109b73e7b85c4afe3e6d0fb89b4bd9b53b3d42f79e",
		"0x3f18df046e3c8dbff1ec006b9533cb0be82d756c347c8838a25f03bfda5cd399",
		"0x22264c23c7f8fea323dd1998376576e0fa4d14c67dc577dc7a01e5ae9c2e4cf6",
		"0x6782bad9bd4717caf61b261a0a7f86fa9263f4b5b76c1d80d4c3bfbe0512ed06",
	}
	preuves := [][]string{
		{"0x3ef9fdf53c5fd27d37c20efdce9d0d8bfcfd459d491e5cb66dd3f384540d270c", "0x2fb61705d23c09d71bebc1a297940ce119c3bda5b3357d39d76043cb554cfea8", "0xa93b6b900d821b68a351fb3e8e986f8298a21254f1c348f108843f7ede2f1ec0"},
		{"0x2fb61705d23c09d71bebc1a297940ce119c3bda5b3357d39d76043cb554cfea8", "0xa93b6b900d821b68a351fb3e8e986f8298a21254f1c348f108843f7ede2f1ec0"},
		{"0x8380b74438d71a5fb81aa3b62f1c7e0b06cb0e9c73f5d5a42f44372e203fbf3e", "0x3617a8c28e38e476cc671a109baf783cd70e1f24eca0278280a215b28f1c55db", "0xa5b5b030de6510a06da18b109b73e7b85c4afe3e6d0fb89b4bd9b53b3d42f79e", "0xa93b6b900d821b68a351fb3e8e986f8298a21254f1c348f108843f7ede2f1ec0"},
		{"0xa93b6b900d821b68a351fb3e8e986f8298a21254f1c348f108843f7ede2f1ec0"},
	}
	for m := 1; m <= 5; m++ {
		if got := Hex0x(MTH(D[:m])); got != prefixes[m-1] {
			t.Errorf("MTH(D[0..%d]) = %s ≠ %s", m-1, got, prefixes[m-1])
		}
	}
	for m := 1; m <= 4; m++ {
		p, err := PreuveCoherence(m, D)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, b := range p {
			got = append(got, Hex0x(b))
		}
		if strings.Join(got, " ") != strings.Join(preuves[m-1], " ") {
			t.Errorf("PROOF(%d, D[5]) = %v", m, got)
		}
		if err := VerifierCoherence(uint64(m), 5, MTH(D[:m]), MTH(D), p); err != nil {
			t.Errorf("vérification de PROOF(%d, D[5]) : %v", m, err)
		}
	}
	// §10.8, dernier paragraphe : sans la préposition de first_root pour m = 4,
	// le chemin [L(4)] seul est refusé.
	if err := VerifierCoherence(5, 5, MTH(D[:4]), MTH(D), [][]byte{Feuille(D[4])}); err == nil {
		t.Error("(5, 5) avec un chemin non vide doit être refusé")
	}
	if err := VerifierCoherence(4, 5, MTH(D), MTH(D[:4]), [][]byte{Feuille(D[4])}); err == nil {
		t.Error("racines échangées acceptées")
	}
}
