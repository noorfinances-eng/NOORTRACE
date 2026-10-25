// Tests du module : briques confrontées à des valeurs publiques ou imprimées
// par les spécifications (CT-1, CT-4, CT-6), refus attendus, raisons
// d'échec des variantes, et vecteurs publiés du répertoire parent.

package main

import (
	"crypto/sha3"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func h2b(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(strings.Join(strings.Fields(s), ""), "0x"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestKeccak(t *testing.T) {
	if got := Hex0x(Keccak256(nil)); got != "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" {
		t.Fatalf("keccak256(\"\") = %s", got)
	}
	for _, n := range []int{0, 1, 135, 136, 137, 272, 1000} {
		d := make([]byte, n)
		for i := range d {
			d[i] = byte(i * 7)
		}
		ref := sha3.Sum256(d)
		if got := eponge256(d, 0x06); Hex0x(got) != Hex0x(ref[:]) {
			t.Fatalf("SHA3-256 de %d octets : %x au lieu de %x", n, got, ref)
		}
	}
	// CT-4 6.2 et 6.3.
	if Hex0x(Keccak256([]byte("assureur-demo"))) != "0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab" {
		t.Fatal("org_id de assureur-demo")
	}
}

func TestRLP(t *testing.T) {
	cas := map[string][]byte{
		"0x83646f67":           RLPChaine([]byte("dog")),
		"0x80":                 RLPEntierU(0),
		"0x01":                 RLPEntierU(1),
		"0x820400":             RLPEntierU(1024),
		"0xc0":                 RLPListe(),
		"0xc88363617483646f67": RLPListe(RLPChaine([]byte("cat")), RLPChaine([]byte("dog"))),
	}
	for att, b := range cas {
		if Hex0x(b) != att {
			t.Errorf("RLP %s au lieu de %s", Hex0x(b), att)
		}
		if _, err := DecoderRLP(b); err != nil {
			t.Errorf("décodage de %s : %v", att, err)
		}
	}
	long := RLPChaine(make([]byte, 60))
	if long[0] != 0xb8 || long[1] != 60 {
		t.Fatalf("chaîne longue %x", long[:2])
	}
	for _, mauvais := range []string{"8100", "b80101", "c3", "81"} {
		b, _ := hex.DecodeString(mauvais)
		if _, err := DecoderRLP(b); err == nil {
			t.Errorf("encodage non minimal ou tronqué %s accepté", mauvais)
		}
	}
	if e, _ := DecoderRLP([]byte{0x82, 0x00, 0x01}); e.Octets != nil {
		if _, err := EntierRLP(e); err == nil {
			t.Error("entier à zéro de tête accepté")
		}
	}
}

func TestTrieEtBloc(t *testing.T) {
	if got := Hex0x(RacineIndexee(nil)); got != "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421" {
		t.Fatalf("racine vide %s", got)
	}
	// CT-6 EX-11.4 : bloc 8316.
	e := EnTete{
		ParentHash: h2b(t, "293cde1df216315a74cfa45851f246fd1e32f6d92734c26ac567be95968f1bc2"),
		Number:     big.NewInt(0x207c), Timestamp: big.NewInt(0x6ad8b09f),
		StateRoot: h2b(t, "6d3c48fd05042b6c6c65bec56affb2db5d7b1571a4f4df22b81f8410246de64a"),
		TxRoot:    h2b(t, "2b733fd11b9a29ec7ee2135b50c9e4b8e878088c95d613fbe287f9a22d91612b"),
		RcptRoot:  h2b(t, "9a980c5c887bb493cffb54eb12dbbabfcaa6f27bedbbadd166797b91b4c75220"),
		GasUsed:   big.NewInt(0x6a8d2), GasLimit: big.NewInt(0x1c9c380), BaseFee: big.NewInt(1),
	}
	h, err := BFTBlockHash(e)
	if err != nil || Hex0x(h) != "0x8d74ec1247ecaa63a37d374b5757ef22b532577c4bd8145e2cc13f282cf2410c" {
		t.Fatalf("BFTBlockHash %x (%v)", h, err)
	}
}

func TestComptesEtSignatures(t *testing.T) {
	k, err := cleHardhat(0)
	if err != nil || Hex0x(k) != "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" {
		t.Fatalf("compte Hardhat 0 : %x (%v)", k, err)
	}
	a, _ := AdresseDePrivee(k)
	if Hex0x(a) != "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266" {
		t.Fatalf("adresse %x", a)
	}
	// CT-4 5.3 : CREATE(Hardhat 0, 79) = AttestationRegistry.
	if got := Hex0x(AdresseCreation(a, big.NewInt(79))); got != "0xf4b146fba71f41e0592668ffbf264f1d186b2ca8" {
		t.Fatalf("CREATE %s", got)
	}
	h := HachageSigne(Keccak256([]byte("message")))
	s, err := SignerEVM(k, h)
	if err != nil || !s.Canonique() {
		t.Fatalf("signature %v %v", s, err)
	}
	if r, _ := s.Recouvrir(h); r != Hex0x(a) {
		t.Fatalf("recouvrement %s", r)
	}
	haut := SignatureEVM{V: 55 - s.V, R: s.R, S: new(big.Int).Sub(secpN, s.S)}
	if haut.Canonique() {
		t.Fatal("s haut accepté")
	}
	if r, _ := haut.Recouvrir(h); r != Hex0x(a) {
		t.Fatal("la forme malléable recouvre le même signataire")
	}
	// CT-4 6.6.4 : la seconde signature de la clôture du bloc 16668 est de
	// Hardhat 2.
	pd := h2b(t, "21c3fd75e15d573638a5c3ec46e986cffec31b2c7b359e1f586da03022491674")
	s2 := SignatureEVM{V: 27, R: new(big.Int).SetBytes(h2b(t, "612963407511b7d05170e3e6b9dd2ef850d0f5ea7f5a29d7d1c8d1945ddee5cc")), S: new(big.Int).SetBytes(h2b(t, "39f64d25f34d9594adccb389562f49791c39f8806748a0551878fdfc7e1f9dfa"))}
	if r, _ := s2.Recouvrir(HachageSigne(pd)); r != "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc" {
		t.Fatalf("signataire %s", r)
	}
}

func TestJCSEtPeriodHash(t *testing.T) {
	// CT-1 §10.1 et §10.2.
	m, err := ParseJSON([]byte(`{"version":0,"org_id":"0xa581bb78871a286f5e48b72433a4440c04303db610387e877d730ddb0366daab","journal_id":"0x0e276f6ddd536cf34002bcf73a87e04f09c91ac66839399253a0a78ce9b0c64b","period_start":1793710800,"period_end":1793714400,"first_seq":1,"last_seq":5,"count":5,"root":"0x6782bad9bd4717caf61b261a0a7f86fa9263f4b5b76c1d80d4c3bfbe0512ed06","prev_period_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","recorder_key_id":"rec-test-02","nonce":"0xcfcd0a8277074d0839e4469fdced701c0fdf2855f1001e17d3fada335da05547","generated_at":"2026-11-03T14:00:00.250Z"}`))
	if err != nil {
		t.Fatal(err)
	}
	ph, err := PeriodHash(m)
	if err != nil || Hex0x(ph) != "0xa864281e05663ee5b6feaf22b65d0375d0ad41e10018e1e89d39acecddd4c9f1" {
		t.Fatalf("periodHash %x (%v)", ph, err)
	}
	org, _ := DecoderHexN(m.Get("org_id").S(), 32)
	jou, _ := DecoderHexN(m.Get("journal_id").S(), 32)
	if _, fp, _ := RG4(org, jou, ph); Hex0x(fp) != "0x3200e496c555b46459191c852a7f79b1e0b4156802cac2f2df7b80b0aa9d823b" {
		t.Fatalf("anchorFingerprint %x", fp)
	}
	for _, c := range [][2]string{{`{"b":1,"a":2}`, `{"a":2,"b":1}`}, {`{"é":1,"z":2,"Z":3}`, `{"Z":3,"z":2,"é":1}`}, {`{"a":"x\u0001y"}`, `{"a":"x\u0001y"}`}} {
		v, _ := ParseJSON([]byte(c[0]))
		if s, _ := JCS(v); s != c[1] {
			t.Errorf("JCS(%s) = %s", c[0], s)
		}
	}
	v, _ := ParseJSON([]byte(`{"a":1.0}`))
	if _, err := JCS(v); err == nil {
		t.Error("nombre non entier accepté par JCS v0")
	}
}

func TestStringify(t *testing.T) {
	v, _ := ParseJSON([]byte(`{"a":[],"b":{},"c":[1,"x\n"],"d":null}`))
	s, err := Stringify2(v)
	want := "{\n  \"a\": [],\n  \"b\": {},\n  \"c\": [\n    1,\n    \"x\\n\"\n  ],\n  \"d\": null\n}"
	if err != nil || s != want {
		t.Fatalf("%q", s)
	}
}

func TestConventions(t *testing.T) {
	if _, e := RG1("assureur-demo", true); e == nil {
		t.Error("slug lisible admis en production")
	}
	if _, e := RG1("o-290bfab6e6d002b0fd047e778b2c8898", true); e != nil {
		t.Error(e)
	}
	if _, e := RG3Libelle("noortrace/periode/v1"); e == nil {
		t.Error("libellé hors table admis")
	}
	if e := RG13([]string{"0x70", "0x3c"}, nil, 2); e == nil {
		t.Error("ordre décroissant admis")
	}
	if e := RG13([]string{"0x3c", "0x70"}, []string{"0x70", "0x3c"}, 2); e != nil {
		t.Error(e)
	}
	// 6.7.2 : longueurs.
	if LongueurAttendue("submitPeriod", 2, 0) != 644 || LongueurAttendue("registerRecorder", 2, 0) != 388 {
		t.Error("longueurs de la table de 6.7.2")
	}
	if Quorum(4) != 3 || Quorum(7) != 5 || Quorum(10) != 7 {
		t.Error("quorum")
	}
}

func TestSchema(t *testing.T) {
	ss := NouveauxSchemas(filepath.Join("..", "..", "..", "schemas"))
	v, _ := ParseJSON([]byte(`{"signer":"0x70997970c51812dc3a010c7d01b50e0d17dc79c8","v":29,"r":"0x00","s":"0x00"}`))
	if errs := ss.Valider("operations-registre-v0.schema.json#/$defs/signature", v); len(errs) == 0 {
		t.Error("signature non conforme admise")
	}
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "x.schema.json"), []byte(`{"type":"object","patternProperties":{}}`), 0o600)
	if errs := NouveauxSchemas(dir).Valider("x.schema.json", Objet()); len(errs) == 0 {
		t.Error("mot-clé inconnu admis")
	}
}

func contexteVecteurs(t *testing.T) *Ctx {
	t.Helper()
	c := NouveauCtx("..")
	b, err := os.ReadFile(filepath.Join(c.Spec, "CT-4-registre.md"))
	if err != nil {
		t.Fatal(err)
	}
	c.Texte = string(b)
	if err := c.chargerJeuDev(); err != nil {
		t.Fatal(err)
	}
	if err := c.chargerCapture(); err != nil {
		t.Fatal(err)
	}
	c.FamilleConstantes()
	return c
}

func TestEnveloppeTolerance(t *testing.T) {
	c := contexteVecteurs(t)
	bc := c.Capture[16648]
	cert := bc.Cert
	if _, _, err := VerifierCertificat(cert, *c.JeuDev); err != nil {
		t.Fatal(err)
	}
	// Nom de membre dans une autre casse : admis (scripts/verify/README.md).
	cert.Precommits = append([]string{}, bc.Cert.Precommits...)
	cert.Precommits[0] = strings.Replace(cert.Precommits[0], `"domain":`, `"DOMAIN":`, 1)
	if _, _, err := VerifierCertificat(cert, *c.JeuDev); err != nil {
		t.Fatalf("casse tolérée refusée : %v", err)
	}
	// Nom de membre différent : refusé.
	cert.Precommits[0] = strings.Replace(bc.Cert.Precommits[0], `"domain":`, `"domaine":`, 1)
	if _, _, err := VerifierCertificat(cert, *c.JeuDev); err == nil {
		t.Fatal("membre domaine admis")
	}
	// Precommit en double : refusé ; quorum manquant : refusé.
	cert.Precommits = []string{bc.Cert.Precommits[0], bc.Cert.Precommits[0], bc.Cert.Precommits[1]}
	if _, _, err := VerifierCertificat(cert, *c.JeuDev); err == nil {
		t.Fatal("signataire en double admis")
	}
	cert.Precommits = bc.Cert.Precommits[:2]
	if _, _, err := VerifierCertificat(cert, *c.JeuDev); err == nil {
		t.Fatal("quorum manquant admis")
	}
	// Autre jeu : refusé.
	if _, _, err := VerifierCertificat(bc.Cert, *c.JeuEssai); err == nil {
		t.Fatal("certificat vérifié contre un autre jeu")
	}
}

// TestRaisons : chaque variante échoue pour la raison que décrit son cas.
func TestRaisons(t *testing.T) {
	c := contexteVecteurs(t)
	attendus := map[string]string{
		"schema":                        "fees",
		"revision-mal-chainee":          "previous_sha256",
		"genese-sha256":                 "SHA-256 du document de genèse",
		"ligne-regles":                  "ligne de règles",
		"valset-hash":                   "valset_hash",
		"domaine-de-panne":              "opérateur",
		"arguments-constructeur":        "arguments du constructeur",
		"adresse-creation":              "CREATE",
		"preuve-autre-role":             "rôle",
		"deploiement-avec-destinataire": "destinataire",
		"ancre-differente":              "ancre registry",
		"genese-invalide":               "en double",
		"regles-absentes":               "section rules absente",
		"identifiants-incoherents":      "bft_chain_id",
		"offre-differente":              "alloc_total_wei",
		"jeu-invalide":                  "secp256k1",
		"operateurs-incoherents":        "operators",
		"intervalles-incoherents":       "recouvrent",
		"contrats-en-service":           "to_height nul",
		"preuve-absente":                "index de capture absent",
		"cp2-entete-modifie":            "BFTBlockHash",
		"cp2-hash-index":                "block_hash de l'index",
		"cp2-recu-autre-bloc":           "blockHash du reçu",
		"cp3-recu-falsifie":             "racine des reçus",
		"cp3-recu-autre-transaction":    "transactionHash",
		"cp3-recu-autre-nom":            "recu-autre.json",
		"cp4-autre-jeu":                 "valsetHash",
		"cp4-valset-hash-index":         "validator_set_hash",
		"cp4-certificat-autre-bloc":     "height",
		"cp5-autre-role":                "journal émis",
		"cp5-journal-absent":            "log_index",
		"cp6-sha256-faux":               "SHA-256",
		"cp6-nom-hors-convention":       "bloc-16648-copie.json",
	}
	vus := map[string]bool{}
	man, _, _ := LireJSON(filepath.Join(c.Racine, "manifestes", "manifestes.json"))
	for _, k := range man.Get("cases").Arr {
		id := k.Get("id").S()
		in := k.Get("input")
		res := c.VerifierManifeste(filepath.Join(c.Racine, in.Get("directory").S()), in.Get("manifest").S(), in.Get("previous"), in.Get("genesis").S(), in.Get("registry"))
		for _, rg := range ordreRGManifeste {
			if e := res.Verdicts[rg]; e != nil {
				if !strings.Contains(e.Raison, attendus[id]) || attendus[id] == "" {
					t.Errorf("%s %s : raison %q", id, rg, e.Raison)
				}
				vus[id] = true
				break
			}
		}
	}
	cap, _, _ := LireJSON(filepath.Join(c.Racine, "capture", "capture.json"))
	for _, k := range cap.Get("cases").Arr {
		id := k.Get("id").S()
		in := k.Get("input")
		if in.Get("index") == nil {
			continue
		}
		jeu, _ := c.jeuDe(in.Get("validators").S())
		res := c.VerifierCapture(filepath.Join(c.Racine, in.Get("directory").S()), in.Get("index").S(), jeu, in.Get("bft_chain_id").S())
		for _, cp := range ordreCP {
			if e := res.Verdicts[cp]; e != nil {
				if attendus[id] == "" || !strings.Contains(e.Raison, attendus[id]) {
					t.Errorf("%s %s : raison %q", id, cp, e.Raison)
				}
				vus[id] = true
				break
			}
		}
	}
	for id := range attendus {
		if !vus[id] {
			t.Errorf("%s : aucun échec recalculé", id)
		}
	}
}

// TestVecteurs rejoue les vecteurs publiés : aucune discordance, aucune
// tolérance (EX-A.5, EX-A.7).
func TestVecteurs(t *testing.T) {
	r := VerifierVecteurs("..")
	rec, _, _, _, _ := r.Totaux()
	if rec < 1500 {
		t.Fatalf("%d valeurs recalculées seulement", rec)
	}
	for _, f := range r.Familles {
		for _, d := range f.Discordances {
			t.Errorf("[%s] %s, %s : attendu %s, recalculé %s", d.Famille, d.Cas, d.Valeur, d.Attendu, d.Recalcule)
		}
	}
}

// copierArbre recopie src dans dst (fichiers ordinaires).
func copierArbre(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			if d.Name() == "verificateur-independant" {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestAlteration : une valeur attendue altérée d'un octet dans une copie des
// vecteurs est relevée comme discordance, avec la règle qui la fonde.
func TestAlteration(t *testing.T) {
	abs, _ := filepath.Abs("..")
	spec := filepath.Dir(filepath.Dir(abs))
	tmp := t.TempDir()
	vec := filepath.Join(tmp, "spec", "vecteurs")
	copierArbre(t, abs, filepath.Join(vec, "ct-4"))
	for _, l := range [][2]string{
		{filepath.Join(spec, "vecteurs", "ct-1"), filepath.Join(vec, "ct-1")},
		{filepath.Join(spec, "vecteurs", "ct-6"), filepath.Join(vec, "ct-6")},
		{filepath.Join(spec, "schemas"), filepath.Join(tmp, "spec", "schemas")},
		{filepath.Join(spec, "CT-4-registre.md"), filepath.Join(tmp, "spec", "CT-4-registre.md")},
		{filepath.Join(filepath.Dir(spec), "chain"), filepath.Join(tmp, "chain")},
	} {
		if err := os.Symlink(l[0], l[1]); err != nil {
			t.Fatal(err)
		}
	}
	p := filepath.Join(vec, "ct-4", "condenses.json")
	b, _ := os.ReadFile(p)
	alt := strings.Replace(string(b), "0x21c3fd75e15d573638a5c3ec46e986cffec31b2c7b359e1f586da03022491674", "0x21c3fd75e15d573638a5c3ec46e986cffec31b2c7b359e1f586da03022491675", 1)
	if alt == string(b) {
		t.Fatal("valeur à altérer introuvable")
	}
	os.WriteFile(p, []byte(alt), 0o644)
	r := VerifierVecteurs(filepath.Join(vec, "ct-4"))
	trouve := false
	for _, f := range r.Familles {
		for _, d := range f.Discordances {
			if d.Famille == "condenses" && d.Cas == "period-digest-periode-1" && d.Valeur == "digest" && strings.Contains(d.Regle, "RG-6") {
				trouve = true
			}
		}
	}
	if !trouve || r.ToutConcorde() {
		t.Fatal("altération non relevée")
	}
}
