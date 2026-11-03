package main

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"strings"
	"testing"
)

// TestVecteurs exige « tout concorde » sur spec/vecteurs/ct-8.
func TestVecteurs(t *testing.T) {
	r := VerifierVecteurs("..")
	if !r.ToutConcorde() {
		var b bytes.Buffer
		r.EcrireTexte(&b, false)
		t.Fatal(b.String())
	}
	tot, _, _, _ := r.Comptes()
	if tot < 1000 {
		t.Fatalf("seulement %d valeurs recalculées", tot)
	}
}

// entete construit un en-tête ustar selon la table d'EX-13.14.
func entete(nom string, taille int64, mtime int64, mode string, typeflag byte, lien string) []byte {
	h := make([]byte, 512)
	p, n, ok := Decouper(nom)
	if !ok {
		panic("nom indécoupable : " + nom)
	}
	copy(h[0:100], n)
	copy(h[100:108], mode+"\x00")
	copy(h[108:116], "0000000\x00")
	copy(h[116:124], "0000000\x00")
	copy(h[124:136], fmt.Sprintf("%011o\x00", taille))
	copy(h[136:148], fmt.Sprintf("%011o\x00", mtime))
	h[156] = typeflag
	copy(h[157:257], lien)
	copy(h[257:263], "ustar\x00")
	copy(h[263:265], "00")
	copy(h[345:500], p)
	copy(h[148:156], fmt.Sprintf("%06o\x00 ", SommeControle(h)))
	return h
}

type fichierTest struct {
	nom     string
	donnees []byte
}

// archive construit une archive d'EX-13.14 (entrées dans l'ordre donné).
func archive(fs []fichierTest, modif func(i int, h []byte)) []byte {
	var b bytes.Buffer
	var tailles []int64
	for i, f := range fs {
		h := entete(f.nom, int64(len(f.donnees)), 1793059200, "0000644", '0', "")
		if modif != nil {
			modif(i, h)
			for k := 148; k < 156; k++ {
				h[k] = 0
			}
			copy(h[148:156], fmt.Sprintf("%06o\x00 ", SommeControle(h)))
		}
		b.Write(h)
		b.Write(f.donnees)
		b.Write(make([]byte, (512-len(f.donnees)%512)%512))
		tailles = append(tailles, int64(len(f.donnees)))
	}
	L := LongueurArchive(tailles)
	b.Write(make([]byte, int(L)-b.Len()))
	return b.Bytes()
}

func schemaPaquet(t *testing.T) *Schema {
	b, err := os.ReadFile("../../../schemas/paquet-reviseur-v0.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := ChargerSchema("paquet-reviseur-v0", b)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// paquetMinimal rend les fichiers d'un paquet allégé d'un dossier.
func paquetMinimal() []fichierTest {
	lis, rea, dos := []byte("lisez-moi\n"), []byte("read me\n"), []byte("{}\n")
	m := fmt.Sprintf(`{"format":"noortrace/paquet-reviseur","version":0,"label":"essai","created_at":"2026-10-27T00:00:00.000Z","prepared_by":"essai",`+
		`"dossiers":[{"path":"dossiers/d","anchors":null,"bitcoin_headers":null}],"attestation":null,"verifier":null,"instructions":{"fr":"LISEZMOI.md","en":"README.md"},`+
		`"files":[{"path":"LISEZMOI.md","size":%d,"sha256":"%s","role":"instructions"},{"path":"README.md","size":%d,"sha256":"%s","role":"instructions"},`+
		`{"path":"dossiers/d/dossier.json","size":%d,"sha256":"%s","role":"dossier"}]}`,
		len(lis), SHA256Hex(lis), len(rea), SHA256Hex(rea), len(dos), SHA256Hex(dos))
	return []fichierTest{
		{"paquet-reviseur/LISEZMOI.md", lis},
		{"paquet-reviseur/MANIFESTE.json", []byte(m)},
		{"paquet-reviseur/README.md", rea},
		{"paquet-reviseur/dossiers/d/dossier.json", dos},
	}
}

func premierEchec(r ResultatPaquet) string {
	for _, c := range r.Checks {
		if c.Status == "echoue" {
			return c.ID
		}
	}
	return ""
}

func TestPaquetMinimal(t *testing.T) {
	s := schemaPaquet(t)
	a := archive(paquetMinimal(), nil)
	r := EvaluerPaquet(a, "", s)
	if r.Etat != "intact" || premierEchec(r) != "" {
		t.Fatalf("paquet minimal : %s, %+v", r.Etat, r.Checks)
	}
	if w := Avertissements(r, false, "non_execute", "non_execute"); strings.Join(w, ",") != "AV-PR-4" {
		t.Fatalf("avertissements %v, AV-PR-4 attendu (dossier sans ancres)", w)
	}
	lib, err := LireLib(a)
	if err != nil || len(AccordLectures(r.Entrees, lib)) != 0 {
		t.Fatalf("lectures discordantes : %v %v", err, AccordLectures(r.Entrees, lib))
	}
	// PR-2 : bonne et mauvaise empreinte, avec ou sans 0x.
	if r := EvaluerPaquet(a, strings.TrimPrefix(SHA256Hex(a), "0x"), s); r.Checks[1].Status != "reussi" {
		t.Fatal("PR-2 sans 0x")
	}
	r = EvaluerPaquet(a, "0x"+strings.Repeat("00", 32), s)
	if premierEchec(r) != "PR-2" || r.Checks[2].Reason != "prerequis_en_echec" {
		t.Fatalf("PR-2 : %+v", r.Checks[:3])
	}
}

func TestPaquetDefauts(t *testing.T) {
	s := schemaPaquet(t)
	cas := []struct {
		nom     string
		attendu string
		a       func() []byte
	}{
		{"gzip", "PR-1", func() []byte { return []byte{0x1f, 0x8b, 8, 0} }},
		{"gzip complet", "PR-3", func() []byte { b := archive(paquetMinimal(), nil); b[0], b[1] = 0x1f, 0x8b; return b }},
		{"octets après la fin", "PR-3", func() []byte { b := archive(paquetMinimal(), nil); b[len(b)-1] = 1; return b }},
		{"lien symbolique", "PR-4", func() []byte {
			return archive(paquetMinimal(), func(i int, h []byte) {
				if i == 3 {
					h[156] = '2'
				}
			})
		}},
		{"nom absolu", "PR-5", func() []byte {
			f := paquetMinimal()
			f = append([]fichierTest{{"/paquet-reviseur/x", []byte("x")}}, f...)
			return archive(f, nil)
		}},
		{"casse", "PR-5", func() []byte {
			f := paquetMinimal()
			f = append(f[:1], append([]fichierTest{{"paquet-reviseur/LisezMoi.md", []byte("x")}}, f[1:]...)...)
			return archive(f, nil)
		}},
		{"répertoire d'un autre nom", "PR-5", func() []byte {
			f := paquetMinimal()
			f = append(f, fichierTest{"paquet-reviseur/dossiers/d/dossier.json/x", []byte("x")})
			return archive(f, nil)
		}},
		{"mode 0600", "PR-6", func() []byte {
			return archive(paquetMinimal(), func(i int, h []byte) {
				if i == 2 {
					copy(h[100:108], "0000600\x00")
				}
			})
		}},
		{"ordre", "PR-6", func() []byte {
			f := paquetMinimal()
			f[0], f[2] = f[2], f[0]
			return archive(f, nil)
		}},
		{"fichier en trop", "PR-8", func() []byte {
			f := paquetMinimal()
			return archive(append(f, fichierTest{"paquet-reviseur/pieces/x.json", []byte("{}")}), nil)
		}},
		{"rôle hors emplacement", "PR-9", func() []byte {
			f := paquetMinimal()
			f[1].donnees = bytes.Replace(f[1].donnees, []byte(`"role":"dossier"`), []byte(`"role":"pieces"`), 1)
			return archive(f, nil)
		}},
	}
	for _, c := range cas {
		r := EvaluerPaquet(c.a(), "", s)
		if got := premierEchec(r); got != c.attendu {
			t.Errorf("%s : premier échec %q, %q attendu (%+v)", c.nom, got, c.attendu, r.Checks)
		}
		if r.Etat != "non_conforme" || CodeRetour(r.Etat, nil) != 4 {
			t.Errorf("%s : état %s", c.nom, r.Etat)
		}
	}
}

func TestDecouper(t *testing.T) {
	court := "paquet-reviseur/" + strings.Repeat("a", 84)
	if p, n, ok := Decouper(court); !ok || p != "" || n != court {
		t.Fatal("nom de 100 octets")
	}
	long := "paquet-reviseur/" + strings.Repeat("b", 90) + "/" + strings.Repeat("c", 90)
	p, n, ok := Decouper(long)
	if !ok || p != "paquet-reviseur/"+strings.Repeat("b", 90) || n != strings.Repeat("c", 90) {
		t.Fatalf("découpage %q %q", p, n)
	}
	if _, _, ok := Decouper(strings.Repeat("x", 120)); ok {
		t.Fatal("nom sans / découpé")
	}
	// Plus long préfixe (règle de GNU tar), et non le plus court.
	d := "paquet-reviseur/dossiers/" + strings.Repeat("d", 60) + "/jeton-rfc3161.der"
	if p, n, ok := Decouper(d); !ok || p != "paquet-reviseur/dossiers/"+strings.Repeat("d", 60) || n != "jeton-rfc3161.der" {
		t.Fatalf("plus long préfixe : %q %q", p, n)
	}
}

func TestCodeRetour(t *testing.T) {
	for _, c := range []struct {
		codes []int64
		code  int64
	}{{nil, 0}, {[]int64{0, 3}, 3}, {[]int64{3, 2}, 2}, {[]int64{2, 1}, 1}, {[]int64{0, 0}, 0}} {
		if got := CodeRetour("intact", c.codes); got != c.code {
			t.Errorf("%v : %d au lieu de %d", c.codes, got, c.code)
		}
	}
}

func TestArrondis(t *testing.T) {
	if arr3(1200.0/3600*4) != 1.333 || arr3(0.0005) != 0.001 || arr6(63.0/253440) != 0.000249 {
		t.Fatal("arrondis")
	}
	if math.Ceil(1200.0/3600*4*9216) != 12288 {
		t.Fatal("W_pic de 9.5")
	}
	for f, s := range map[float64]string{0.000249: "0.000249", 1e21: "1e+21", 253440: "253440", 1.467: "1.467", 1e-7: "1e-7"} {
		if NombreES6(f) != s {
			t.Errorf("NombreES6(%v) = %s", f, NombreES6(f))
		}
	}
}

// entreesTest rend l'exemple de 9.5 lu dans le texte.
func entreesTest(t *testing.T) (*Value, Coefficients) {
	tx, err := LireTexte("../../../CT-8-deploiement-et-exploitation.md")
	if err != nil {
		t.Fatal(err)
	}
	k, err := LireCoefficients(tx)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := tx.Section("### 9.5 ")
	b, _ := BlocApres(s, "<!-- schema: dimensionnement -->")
	v, err := AnalyserJSON([]byte(b))
	if err != nil {
		t.Fatal(err)
	}
	return v, k
}

func TestDimensionnementRefus(t *testing.T) {
	v, k := entreesTest(t)
	j := v.Get("journals").Arr[0]
	j.Get("storage").Get("worm").Get("retain_days").Num = "3649"
	j.Get("anchoring").Get("retention_years").Num = "9"
	s := Dimensionner(v, k)
	var codes []string
	for _, e := range s.Erreurs {
		codes = append(codes, e.Code)
	}
	if s.Valide || strings.Join(codes, ",") != "retention_years_inferieure_a_10,retain_days_insuffisant" {
		t.Fatalf("refus : %v", codes)
	}
}

func TestDimensionnementCoefficients(t *testing.T) {
	v, k := entreesTest(t)
	if k["blocs_par_s"] != 1.1 || k["gaz_cloture"] != 314256 || k["b_der"] != 3114 || k["b_cap"] != 123761 {
		t.Fatalf("table de 9.2 : %v", k)
	}
	// Un coefficient remplacé par l'exploitant (EX-9.1) change la sortie.
	v.Get("coefficients").Obj = append(v.Get("coefficients").Obj, Membre{Cle: "b_cap", Val: VNum(0)})
	s := Dimensionner(v, k)
	if journalDim(s, 0, "capture_bytes_per_year") != 0 {
		t.Fatal("coefficient b_cap remplacé ignoré")
	}
}

func TestControle(t *testing.T) {
	tx, err := LireTexte("../../../CT-8-deploiement-et-exploitation.md")
	if err != nil {
		t.Fatal(err)
	}
	s, _ := tx.Section("### 6.3 ")
	b, _ := BlocApres(s, "<!-- schema: controle-prealable/observations -->")
	obs, err := AnalyserJSON([]byte(b))
	if err != nil {
		t.Fatal(err)
	}
	if r := EvaluerIP("rapide", obs, nil, nil); r.Verdict != "pret_avec_avertissements" || r.ExitCode != 0 {
		t.Fatalf("exemple de 6.3 : %s", r.Verdict)
	}
	// Production sans seuil : IP-3 non exécutée, bloquante ; IP-13 en échec.
	r := EvaluerIP("production", obs, nil, nil)
	if r.Verdict != "non_pret" || r.Checks[2].Reason != "dimensionnement_absent" || r.Checks[12].Status != "echoue" {
		t.Fatalf("production : %+v", r.Checks)
	}
	// --seulement IP-1 : les autres non demandées, non bloquantes.
	r = EvaluerIP("production", obs, nil, []string{"IP-1"})
	if r.Verdict != "pret_avec_avertissements" || r.Checks[12].Blocking || r.Checks[12].Reason != "non_demandee" {
		t.Fatalf("--seulement : %s %+v", r.Verdict, r.Checks[12])
	}
	// Moteur absent avant Compose ; plate-forme non Linux.
	obs.Get("engine").Get("engine_ok").Bool = false
	obs.Get("platform").Str = "darwin"
	r = EvaluerIP("rapide", obs, nil, nil)
	if r.Checks[0].Reason != "systeme_non_pris_en_charge" || r.Checks[10].Reason != "moteur_absent" || r.ExitCode != 1 {
		t.Fatalf("moteur, plate-forme : %+v %+v", r.Checks[0], r.Checks[10])
	}
}

func TestMotifChemin(t *testing.T) {
	s := schemaPaquet(t)
	sch, _ := s.Sous("#/$defs/chemin")
	for p, ok := range map[string]bool{
		"dossiers/a/b.json":            true,
		".cache/x":                     false,
		strings.Repeat("a/", 16) + "b": false,
		strings.Repeat("a/", 15) + "b": true,
	} {
		if got := len(s.ValiderContre(sch, VStr(p))) == 0; got != ok {
			t.Errorf("%q : %v", p, got)
		}
	}
}
