package horodatage

// N-1 (ControleurAncres, EX-12.2), entrées hostiles (DER tronqué, longueurs
// absurdes, profondeur, tailles) et cibles de fuzzing (EX-15.3).

import (
	"bytes"
	"crypto/rsa"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	casn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/noorfinances-eng/noortrace/verificateur/ancres"
	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/entree"
)

func TestControleurAncresCertificats(t *testing.T) {
	m := mat(t)
	dir := filepath.Join(racineCT6, "rfc3161/cles")
	for nom, ok := range map[string]bool{
		"ac-test.pem": true, "tsa-test.pem": true, "tsa-expiree.pem": true, "tsa-eku-non-critique.pem": true, "tsa-sans-cn.pem": true,
		"tsa-critique-faux.pem": false, "tsa-cn-utf8-invalide.pem": false,
	} {
		err := ControleurAncres{}.Certificat(lirePEM(t, filepath.Join(dir, nom)))
		if (err == nil) != ok {
			t.Errorf("%s : %v", nom, err)
		}
	}
	for _, c := range []struct {
		nom   string
		f     func(c *modeleCert)
		motif string
	}{
		{"version v1 encodée", func(c *modeleCert) { c.version = elem(ctx(0, true), entierDER(0)) }, "EX-9.21"},
		{"cA encodé FALSE", func(c *modeleCert) { c.exts = append(c.exts, extBC(1, boolDER(false))) }, "EX-9.21"},
		{"critical encodé FALSE", func(c *modeleCert) { c.exts[0].critique = 2 }, "EX-9.21"},
		{"BMPString impaire", func(c *modeleCert) { c.sujet = nomDER(attrNom{oidCommonName, tagBMPString, []byte{0, 'a', 0}}) }, "EX-9.4"},
		{"UTF8String invalide dans l'émetteur", func(c *modeleCert) { c.emetteur = nomDER(attrNom{oidOrg, casn1.UTF8String, []byte{0xc3}}) }, "EX-9.4"},
		{"extension en double", func(c *modeleCert) { c.exts = append(c.exts, c.exts[0]) }, "double"},
		{"version 4", func(c *modeleCert) { c.version = elem(ctx(0, true), entierDER(3)) }, "version"},
		{"extensions en v1", func(c *modeleCert) { c.version = []byte{} }, "extensions"},
	} {
		mc := m.modeleTSA()
		c.f(&mc)
		err := ControleurAncres{}.Certificat(fabriquerCert(t, mc))
		if err == nil || !strings.Contains(err.Error(), c.motif) {
			t.Errorf("%s : %v", c.nom, err)
		}
	}
	// Certificat v1 sans extension : lisible (la version absente n'est pas
	// une valeur DEFAULT encodée).
	mc := m.modeleTSA()
	mc.version, mc.exts = []byte{}, nil
	if err := (ControleurAncres{}).Certificat(fabriquerCert(t, mc)); err != nil {
		t.Errorf("certificat v1 : %v", err)
	}
	// BMPString paire et chaîne d'un autre type : lisibles ; CN BMP décodé.
	mc = m.modeleTSA()
	mc.sujet = nomDER(attrNom{oidCommonName, tagBMPString, []byte{0, 'O', 0, 'K'}}, attrNom{oidOrg, casn1.Tag(28), []byte{0, 0, 0, 'x'}})
	c, d := lireCertificat(fabriquerCert(t, mc))
	if d != nil || c.cn == nil || *c.cn != "OK" {
		t.Errorf("BMPString paire : %v", d)
	}
	if err := (ControleurAncres{}).Certificat(append(append([]byte{}, m.certAC...), 0)); err == nil {
		t.Errorf("octet en trop accepté")
	}
}

func TestControleurAncresCRL(t *testing.T) {
	m := mat(t)
	for _, b := range [][]byte{m.crlVide, m.crlRevoquee} {
		if err := (ControleurAncres{}).CRL(b); err != nil {
			t.Errorf("CRL de test : %v", err)
		}
	}
	base := modeleCRL{emetteur: m.ac.sujet, thisUpdate: time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC), sign: signeurRSA(m.cleAC)}
	c := base
	c.exts = []extTest{{asn1OID(2, 5, 29, 20), 2, entierDER(1)}}
	if err := (ControleurAncres{}).CRL(fabriquerCRL(t, c)); err == nil || !strings.Contains(err.Error(), "EX-9.21") {
		t.Errorf("CRL à critical FALSE : %v", err)
	}
	c = base
	c.emetteur = nomDER(attrNom{oidCommonName, casn1.UTF8String, []byte{0xff}})
	if err := (ControleurAncres{}).CRL(fabriquerCRL(t, c)); err == nil {
		t.Errorf("CRL à émetteur UTF-8 invalide acceptée")
	}
	// Entrée à extension critical FALSE.
	entreeFausse := seq(entierDER(5), temps(base.thisUpdate), seq(extDER(extTest{oidCRLReason, 2, []byte{0x0a, 0x01, 0x01}})))
	tbs := seq(entierDER(1), base.sign.algo, base.emetteur, temps(base.thisUpdate), seq(entreeFausse))
	crlFausse := seq(tbs, base.sign.algo, bitsDER(base.sign.signer(t, tbs)))
	if err := (ControleurAncres{}).CRL(crlFausse); err == nil || !strings.Contains(err.Error(), "EX-9.21") {
		t.Errorf("entrée à critical FALSE : %v", err)
	}
	if err := (ControleurAncres{}).CRL(m.certAC); err == nil {
		t.Errorf("certificat accepté comme CRL")
	}
}

// TestN1FichierAncres : le profil strict, appliqué par le paquet ancres,
// rend inutilisable un fichier d'ancres qui porte un certificat à valeur
// DEFAULT encodée (EX-12.2, EX-9.21).
func TestN1FichierAncres(t *testing.T) {
	brut := string(lire(t, filepath.Join(racineCT6, "ancres/ancres-test.json")))
	faux := lire(t, filepath.Join(racineCT6, "rfc3161/cles/tsa-critique-faux.pem"))
	ac := lire(t, filepath.Join(racineCT6, "rfc3161/cles/ac-test.pem"))
	echappe := func(b []byte) string { return strings.ReplaceAll(strings.TrimSpace(string(b)), "\n", `\n`) }
	if !strings.Contains(brut, echappe(ac)) {
		t.Fatal("certificat de l'AC introuvable dans ancres-test.json")
	}
	modifie := strings.Replace(brut, echappe(ac), echappe(faux), 1)
	_, d := ancres.AnalyserAncres([]byte(modifie), ControleurAncres{})
	if d == nil || d.Verification != "N-1" || d.Genre != "ancres_inutilisables" || !strings.Contains(d.Message.Fr, "EX-9.21") {
		t.Fatalf("défaut attendu : %+v", d)
	}
	if _, d := ancres.AnalyserAncres([]byte(brut), ControleurAncres{}); d != nil {
		t.Fatalf("ancres-test.json : %s", d.Message.Fr)
	}
}

func asn1OID(c ...int) []int { return c }

// --- Entrées hostiles ---

func periode1(t testing.TB) []byte {
	return lire(t, filepath.Join(racineCT6, "rfc3161/jetons/periode-1.der"))
}

// TestJetonTronque : toute troncature fait échouer T-1, sans panique.
func TestJetonTronque(t *testing.T) {
	m := mat(t)
	j := periode1(t)
	for n := 0; n < len(j); n++ {
		r := Verifier(m.entree(t, j[:n], m.ancresTest()))
		if r.Verifications[0].Statut != commun.Echoue || r.Statut != commun.Echoue {
			t.Fatalf("troncature à %d octets : T-1 %s", n, r.Verifications[0].Statut)
		}
	}
}

// TestJetonAltere : chaque octet inversé ne fait jamais paniquer et ne
// laisse jamais le contrôle réussi, sauf dans digestAlgorithms de
// SignedData, ni signé ni contrôlé par CT-6 (EX-9.7 ne le nomme pas).
func TestJetonAltere(t *testing.T) {
	m := mat(t)
	j := periode1(t)
	a := m.ancresTest()
	libres := set(algoDER(oidSHA256, false))
	debutLibre := bytes.Index(j, libres) + 2
	if debutLibre < 2 {
		t.Fatal("digestAlgorithms introuvable")
	}
	for i := range j {
		if i >= debutLibre && i < debutLibre+len(libres)-2 {
			continue
		}
		for _, x := range []byte{0xff, 0x01, 0x80} {
			k := append([]byte{}, j...)
			k[i] ^= x
			r := Verifier(m.entree(t, k, a))
			if len(r.Verifications) != 11 {
				t.Fatalf("octet %d : %d vérifications", i, len(r.Verifications))
			}
			if r.Statut == commun.Reussi {
				t.Errorf("octet %d ^ %02x : contrôle réussi sur un jeton altéré", i, x)
			}
		}
	}
}

func TestDERHostile(t *testing.T) {
	profond := func(n int) []byte {
		b := []byte{0x05, 0x00}
		for i := 0; i < n; i++ {
			b = seq(b)
		}
		return b
	}
	cas := map[string]struct {
		der []byte
		ok  bool
	}{
		"profondeur 32":           {profond(31), true},
		"profondeur 33":           {profond(32), false},
		"profondeur 10 000":       {profond(10000), false},
		"longueur non minimale":   {[]byte{0x30, 0x81, 0x02, 0x05, 0x00}, false},
		"longueur longue inutile": {[]byte{0x04, 0x81, 0x01, 0x00}, false},
		"longueur indéfinie":      {[]byte{0x30, 0x80, 0x05, 0x00, 0x00, 0x00}, false},
		"longueur absurde":        {[]byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff, 0x00}, false},
		"longueur sur 5 octets":   {[]byte{0x30, 0x85, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00}, false},
		"étiquette 31":            {[]byte{0x1f, 0x1f, 0x01, 0x00}, false},
		"BOOLEAN 01":              {[]byte{0x30, 0x03, 0x01, 0x01, 0x01}, false},
		"BOOLEAN long":            {[]byte{0x30, 0x04, 0x01, 0x02, 0xff, 0xff}, false},
		"BOOLEAN ff":              {[]byte{0x30, 0x03, 0x01, 0x01, 0xff}, true},
		"contenu tronqué":         {[]byte{0x30, 0x05, 0x05, 0x00}, false},
		"élément partiel":         {[]byte{0x30, 0x01, 0x05}, false},
		"octet après":             {[]byte{0x05, 0x00, 0x00}, false},
		"vide":                    {[]byte{}, false},
	}
	for nom, c := range cas {
		if d := verifierProfil(c.der, 0); (d == nil) != c.ok {
			t.Errorf("%s : %v", nom, d)
		}
	}
	m := mat(t)
	for nom, b := range map[string][]byte{
		"profondeur 40":       profond(40),
		"longueur absurde":    {0x30, 0x84, 0x7f, 0xff, 0xff, 0xff},
		"zéros":               make([]byte, entree.LimiteJeton),
		"SEQUENCE géante":     seq(make([]byte, entree.LimiteJeton-8)),
		"OID immense":         seq(elem(casn1.OBJECT_IDENTIFIER, bytes.Repeat([]byte{0xff}, 200))),
		"INTEGER vide":        seq(elem(casn1.INTEGER)),
		"mille certificats ∅": seq(oidDER(oidSignedData), elem(ctx(0, true), seq(entierDER(3), set(), seq(oidDER(oidTSTInfo), elem(ctx(0, true), oct(nil))), elem(ctx(0, true), bytes.Repeat(seq(), 1000))))),
	} {
		r := Verifier(m.entree(t, b, m.ancresTest()))
		if r.Verifications[0].Statut != commun.Echoue {
			t.Errorf("%s : T-1 %s", nom, r.Verifications[0].Statut)
		}
	}
}

// TestCheminBorne : quinze AC d'un même nom, toutes signées par la même
// clé, font de chaque niveau un ensemble de quinze candidats ; la recherche
// (n ≤ 4, niveaux calculés en largeur, signatures en cache) reste bornée et
// échoue faute d'atteindre l'autorité.
func TestCheminBorne(t *testing.T) {
	m := mat(t)
	mj := m.modeleJeton(t)
	x := nomSimple("X")
	c := m.modeleTSA()
	c.emetteur, c.sign = x, signeurRSA(m.cleTSA)
	s := fabriquerCert(t, c)
	mj.certs, mj.certESS, mj.sidEmetteur = [][]byte{s}, s, x
	for i := 0; i < 15; i++ {
		mj.certs = append(mj.certs, fabriquerCert(t, modeleCert{serie: int64(100 + i), emetteur: x, sujet: x,
			debut: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), fin: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
			pub: m.cleTSA.Public(), exts: []extTest{extBC(1, boolDER(true))}, sign: signeurRSA(m.cleTSA)}))
	}
	debut := time.Now()
	r := Verifier(m.entree(t, fabriquerJeton(t, mj), m.ancresTest()))
	if d := time.Since(debut); d > 30*time.Second {
		t.Errorf("recherche de chemin trop longue : %v", d)
	}
	if abrege(r) != "re re re re re re ec re re ne:pe ne:pe" {
		t.Errorf("statuts %s : %s", abrege(r), r.Verifications[6].Detail.Fr)
	}
}

// TestClesHostiles : une clé RSA de plus de 2048 bits mais invalide (module
// pair, exposant pair) et un attribut signé sans valeur ne font pas
// paniquer ; le contrôle échoue.
func TestClesHostiles(t *testing.T) {
	m := mat(t)
	n := new(big.Int).Lsh(big.NewInt(1), 3071)
	for _, cle := range []*rsa.PublicKey{{N: n, E: 65537}, {N: m.cleTSA.N, E: 4}} {
		mj := m.modeleJeton(t)
		c := m.unite(t, cle, nil)
		mj.certs, mj.certESS = [][]byte{c}, c
		r := Verifier(m.entree(t, fabriquerJeton(t, mj), m.ancresTest()))
		if r.Statut != commun.Echoue {
			t.Errorf("clé invalide : %s", abrege(r))
		}
	}
	mj := m.modeleJeton(t)
	mj.attrs = func(a []attrTest, _ []byte) []attrTest { a[2].valeurs = nil; return a }
	r := Verifier(m.entree(t, fabriquerJeton(t, mj), m.ancresTest()))
	if abrege(r) != "re re ec ec ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe" {
		t.Errorf("attribut sans valeur : %s", abrege(r))
	}
}

// --- Fuzzing (EX-15.3) ---

func graines(f *testing.F) [][]byte {
	var out [][]byte
	ents, _ := os.ReadDir(filepath.Join(racineCT6, "rfc3161/jetons"))
	for _, e := range ents {
		if b, err := os.ReadFile(filepath.Join(racineCT6, "rfc3161/jetons", e.Name())); err == nil {
			out = append(out, b)
		}
	}
	return out
}

// FuzzJeton : l'analyseur du jeton (CMS et TSTInfo) et les onze
// vérifications ne paniquent pas et rendent toujours onze résultats.
func FuzzJeton(f *testing.F) {
	for _, g := range graines(f) {
		f.Add(g)
	}
	m := mat(f)
	a := m.ancresTest()
	f.Fuzz(func(t *testing.T, b []byte) {
		r := Verifier(m.entree(t, b, a))
		if len(r.Verifications) != 11 || (r.Faits != nil) != (r.Statut == commun.Reussi) {
			t.Fatalf("résultat incohérent")
		}
		for _, v := range r.Verifications {
			if v.Raison == commun.AConstruire {
				t.Fatalf("raison provisoire")
			}
		}
	})
}

// FuzzCertificat : lecture stricte d'un certificat (N-1 et T-1).
func FuzzCertificat(f *testing.F) {
	ents, _ := os.ReadDir(filepath.Join(racineCT6, "rfc3161/cles"))
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".pem") && !strings.HasSuffix(e.Name(), ".cle.pem") {
			b, _ := os.ReadFile(filepath.Join(racineCT6, "rfc3161/cles", e.Name()))
			if p, _ := pem.Decode(b); p != nil {
				f.Add(p.Bytes)
			}
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		c, d := lireCertificat(b)
		if (c == nil) == (d == nil) {
			t.Fatalf("lecture incohérente")
		}
		_ = ControleurAncres{}.Certificat(b)
	})
}

// FuzzCRL : lecture stricte d'une CRL (N-1 et T-10).
func FuzzCRL(f *testing.F) {
	for _, n := range []string{"crl-vide.pem", "crl-tsa-revoquee.pem"} {
		b, _ := os.ReadFile(filepath.Join(racineCT6, "rfc3161/crl", n))
		if p, _ := pem.Decode(b); p != nil {
			f.Add(p.Bytes)
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		l, d := lireCRL(b)
		if (l == nil) == (d == nil) {
			t.Fatalf("lecture incohérente")
		}
		if l != nil {
			l.complete()
			l.liste([]byte{1})
		}
	})
}
