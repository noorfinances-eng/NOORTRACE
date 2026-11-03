package horodatage

// Fabrique de jetons, de certificats et de CRL pour les tests : chaque
// variante part d'un jeton conforme, construit comme periode-1.der
// (annexe A.3, EX-A.5) avec les clés de test publiques de
// spec/vecteurs/ct-6/rfc3161/cles, puis change une seule chose.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	casn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/noorfinances-eng/noortrace/verificateur/ancres"
	"github.com/noorfinances-eng/noortrace/verificateur/cryptographie"
	"github.com/noorfinances-eng/noortrace/verificateur/entree"
)

// periodHash de la période 1 (EX-A.2).
const periodHash1 = "0xae22426f25529379efab196ba8b5f73c4729b27d8fca4409a26d803848860914"

var politiqueTest = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1, 1}

// materiel : clés et certificats de test, lus une fois.
type materiel struct {
	cleAC, cleTSA *rsa.PrivateKey
	certAC        []byte
	certTSA       []byte
	crlVide       []byte
	crlRevoquee   []byte
	ac, tsa       *certificat
}

var (
	materielUne  sync.Once
	materielTest materiel
)

func lirePEM(t testing.TB, chemin string) []byte {
	t.Helper()
	b, _ := pem.Decode(lire(t, chemin))
	if b == nil {
		t.Fatalf("%s : PEM illisible", chemin)
	}
	return b.Bytes
}

func mat(t testing.TB) *materiel {
	t.Helper()
	materielUne.Do(func() {
		dir := filepath.Join(racineCT6, "rfc3161")
		k1, err := x509.ParsePKCS8PrivateKey(lirePEM(t, filepath.Join(dir, "cles/ac-test.cle.pem")))
		if err != nil {
			t.Fatal(err)
		}
		k2, err := x509.ParsePKCS8PrivateKey(lirePEM(t, filepath.Join(dir, "cles/tsa-test.cle.pem")))
		if err != nil {
			t.Fatal(err)
		}
		m := &materielTest
		m.cleAC, m.cleTSA = k1.(*rsa.PrivateKey), k2.(*rsa.PrivateKey)
		m.certAC = lirePEM(t, filepath.Join(dir, "cles/ac-test.pem"))
		m.certTSA = lirePEM(t, filepath.Join(dir, "cles/tsa-test.pem"))
		m.crlVide = lirePEM(t, filepath.Join(dir, "crl/crl-vide.pem"))
		m.crlRevoquee = lirePEM(t, filepath.Join(dir, "crl/crl-tsa-revoquee.pem"))
		var d *defaut
		if m.ac, d = lireCertificat(m.certAC); d != nil {
			t.Fatal(d.fr)
		}
		if m.tsa, d = lireCertificat(m.certTSA); d != nil {
			t.Fatal(d.fr)
		}
	})
	if materielTest.cleAC == nil {
		t.Fatal("matériel de test indisponible")
	}
	return &materielTest
}

// --- Briques DER ---

func construire(f func(b *cryptobyte.Builder)) []byte {
	var b cryptobyte.Builder
	f(&b)
	return b.BytesOrPanic()
}

func elem(tag casn1.Tag, contenu ...[]byte) []byte {
	return construire(func(b *cryptobyte.Builder) {
		b.AddASN1(tag, func(b *cryptobyte.Builder) {
			for _, c := range contenu {
				b.AddBytes(c)
			}
		})
	})
}

func seq(c ...[]byte) []byte { return elem(casn1.SEQUENCE, c...) }
func set(c ...[]byte) []byte { return elem(casn1.SET, c...) }
func oct(c []byte) []byte    { return elem(casn1.OCTET_STRING, c) }
func entierDER(n int64) []byte {
	return construire(func(b *cryptobyte.Builder) { b.AddASN1Int64(n) })
}
func oidDER(o asn1.ObjectIdentifier) []byte {
	return construire(func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(o) })
}
func boolDER(v bool) []byte {
	if v {
		return []byte{0x01, 0x01, 0xff}
	}
	return []byte{0x01, 0x01, 0x00}
}
func bitsDER(b []byte) []byte { return elem(casn1.BIT_STRING, append([]byte{0}, b...)) }
func algoDER(o asn1.ObjectIdentifier, nul bool) []byte {
	if nul {
		return seq(oidDER(o), []byte{0x05, 0x00})
	}
	return seq(oidDER(o))
}

// attrNom : un attribut d'un Name.
type attrNom struct {
	oid asn1.ObjectIdentifier
	tag casn1.Tag
	val []byte
}

func nomDER(attrs ...attrNom) []byte {
	var rdns [][]byte
	for _, a := range attrs {
		rdns = append(rdns, set(seq(oidDER(a.oid), elem(a.tag, a.val))))
	}
	return seq(rdns...)
}

var (
	oidPays = asn1.ObjectIdentifier{2, 5, 4, 6}
	oidOrg  = asn1.ObjectIdentifier{2, 5, 4, 10}
)

func nomSimple(cn string) []byte {
	return nomDER(attrNom{oidPays, casn1.PrintableString, []byte("CH")}, attrNom{oidOrg, casn1.UTF8String, []byte("NOORTRACE tests")}, attrNom{oidCommonName, casn1.UTF8String, []byte(cn)})
}

// extTest : extension ; critique 0 absent, 1 TRUE, 2 FALSE encodé.
type extTest struct {
	oid      asn1.ObjectIdentifier
	critique int
	valeur   []byte
}

func extDER(x extTest) []byte {
	parts := [][]byte{oidDER(x.oid)}
	switch x.critique {
	case 1:
		parts = append(parts, boolDER(true))
	case 2:
		parts = append(parts, boolDER(false))
	}
	return seq(append(parts, oct(x.valeur))...)
}

func extsDER(xs []extTest) [][]byte {
	var out [][]byte
	for _, x := range xs {
		out = append(out, extDER(x))
	}
	return out
}

func extEKU(critique int, oids ...asn1.ObjectIdentifier) extTest {
	var c [][]byte
	for _, o := range oids {
		c = append(c, oidDER(o))
	}
	return extTest{oidExtKeyUsage, critique, seq(c...)}
}

func extKU(critique int, octet byte, inutilises byte) extTest {
	return extTest{oidKeyUsage, critique, elem(casn1.BIT_STRING, []byte{inutilises, octet})}
}

func extBC(critique int, contenu ...[]byte) extTest {
	return extTest{oidBasicConstr, critique, seq(contenu...)}
}

func extSKI(id []byte) extTest { return extTest{oidSKI, 0, oct(id)} }

// signeur : clé et algorithme de signature.
type signeur struct {
	cle  crypto.Signer
	algo []byte // AlgorithmIdentifier DER
	hash crypto.Hash
	pss  bool
}

func signeurRSA(k *rsa.PrivateKey) signeur {
	return signeur{cle: k, algo: algoDER(oidSHA256RSA, true), hash: crypto.SHA256}
}

func (s signeur) signer(t testing.TB, m []byte) []byte {
	h := s.hash.New()
	h.Write(m)
	d := h.Sum(nil)
	var sig []byte
	var err error
	switch k := s.cle.(type) {
	case *rsa.PrivateKey:
		if s.pss {
			sig, err = rsa.SignPSS(rand.Reader, k, s.hash, d, &rsa.PSSOptions{SaltLength: s.hash.Size(), Hash: s.hash})
		} else {
			sig, err = rsa.SignPKCS1v15(nil, k, s.hash, d)
		}
	case *ecdsa.PrivateKey:
		sig, err = ecdsa.SignASN1(rand.Reader, k, d)
	case ed25519.PrivateKey:
		// Ed25519 (RFC 8419) signe le message lui-même.
		sig = ed25519.Sign(k, m)
	}
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// modeleCert : certificat à fabriquer.
type modeleCert struct {
	// version : élément [0] brut ; nil pour v3 (a0 03 02 01 02) ; vide
	// pour l'omettre (v1 implicite).
	version    []byte
	serie      int64
	emetteur   []byte
	sujet      []byte
	debut, fin time.Time
	pub        crypto.PublicKey
	exts       []extTest
	sign       signeur
}

func fabriquerCert(t testing.TB, m modeleCert) []byte {
	t.Helper()
	spki, err := x509.MarshalPKIXPublicKey(m.pub)
	if err != nil {
		t.Fatal(err)
	}
	var tbsParts [][]byte
	switch {
	case m.version == nil:
		tbsParts = append(tbsParts, elem(ctx(0, true), entierDER(2)))
	case len(m.version) > 0:
		tbsParts = append(tbsParts, m.version)
	}
	tbsParts = append(tbsParts, entierDER(m.serie), m.sign.algo, m.emetteur,
		seq(temps(m.debut), temps(m.fin)), m.sujet, spki)
	if len(m.exts) > 0 {
		tbsParts = append(tbsParts, elem(ctx(3, true), seq(extsDER(m.exts)...)))
	}
	tbs := seq(tbsParts...)
	return seq(tbs, m.sign.algo, bitsDER(m.sign.signer(t, tbs)))
}

func temps(t time.Time) []byte {
	return construire(func(b *cryptobyte.Builder) { b.AddASN1UTCTime(t) })
}

// modeleTSA : unité signée par l'AC de test, comme tsa-test.pem.
func (m *materiel) modeleTSA() modeleCert {
	return modeleCert{
		serie:    2,
		emetteur: m.ac.sujet,
		sujet:    m.tsa.sujet,
		debut:    time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		fin:      time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC),
		pub:      m.cleTSA.Public(),
		exts:     []extTest{extKU(1, 0x80, 7), extEKU(1, oidTimeStamping), extSKI([]byte{1, 2, 3, 4})},
		sign:     signeurRSA(m.cleAC),
	}
}

// entreeTest : entrée de CRL ; raison -1 pour aucune.
type entreeTest struct {
	serie  int64
	date   time.Time
	raison int
}

type modeleCRL struct {
	emetteur   []byte
	thisUpdate time.Time
	entrees    []entreeTest
	exts       []extTest
	sign       signeur
}

func fabriquerCRL(t testing.TB, m modeleCRL) []byte {
	t.Helper()
	parts := [][]byte{entierDER(1), m.sign.algo, m.emetteur, temps(m.thisUpdate), temps(m.thisUpdate.AddDate(0, 1, 0))}
	if len(m.entrees) > 0 {
		var es [][]byte
		for _, e := range m.entrees {
			c := [][]byte{entierDER(e.serie), temps(e.date)}
			if e.raison >= 0 {
				r := construire(func(b *cryptobyte.Builder) { b.AddASN1Enum(int64(e.raison)) })
				c = append(c, seq(extDER(extTest{oidCRLReason, 0, r})))
			}
			es = append(es, seq(c...))
		}
		parts = append(parts, seq(es...))
	}
	if len(m.exts) > 0 {
		parts = append(parts, elem(ctx(0, true), seq(extsDER(m.exts)...)))
	}
	tbs := seq(parts...)
	return seq(tbs, m.sign.algo, bitsDER(m.sign.signer(t, tbs)))
}

// attrTest : attribut signé.
type attrTest struct {
	oid     asn1.ObjectIdentifier
	valeurs [][]byte
}

// modeleJeton : jeton à fabriquer.
type modeleJeton struct {
	empreinte   []byte
	algoImprint []byte
	politique   asn1.ObjectIdentifier
	serie       []byte // élément INTEGER complet
	genTime     string
	precision   []byte // Accuracy DER, ou nil
	ordering    []byte
	tsa         []byte // contenu de [0] (un GeneralName), ou nil
	extsTST     []extTest
	certs       [][]byte
	crls        [][]byte
	// sidSKI : si non nil, SignerInfo version 3.
	sidSKI      []byte
	sidEmetteur []byte
	sidSerie    int64
	digest      []byte // AlgorithmIdentifier de digestAlgorithm
	digestHash  crypto.Hash
	// certESS : certificat que désigne signingCertificateV2 par défaut.
	certESS []byte
	// attrs : modifie la liste des attributs signés par défaut.
	attrs func(a []attrTest, tst []byte) []attrTest
	sign  signeur
	// sigAlgo : signatureAlgorithm de SignerInfo, ou nil pour celui du
	// signeur.
	sigAlgo []byte
	// apres : retouche du TSTInfo, du SignerInfo ou du jeton fini.
	tstBrut     func([]byte) []byte
	versionSD   int64
	versionTST  int64
	inverserSig bool
	// doublerSI : deux SignerInfo ; eContentConstruit : eContent en OCTET
	// STRING construite.
	doublerSI         bool
	eContentConstruit bool
}

func (m *materiel) modeleJeton(t testing.TB) *modeleJeton {
	e, _ := cryptographie.LireHex(periodHash1, 32)
	return &modeleJeton{
		empreinte:   e,
		algoImprint: algoDER(oidSHA256, true),
		politique:   politiqueTest,
		serie:       entierDER(1),
		genTime:     "20261105100005Z",
		precision:   seq(entierDER(1)),
		tsa:         elem(ctx(4, true), m.tsa.sujet),
		certs:       [][]byte{m.certTSA},
		sidEmetteur: m.ac.sujet,
		sidSerie:    2,
		digest:      algoDER(oidSHA256, false),
		digestHash:  crypto.SHA256,
		certESS:     m.certTSA,
		sign:        signeurRSA(m.cleTSA),
		versionSD:   3,
		versionTST:  1,
	}
}

func (mj *modeleJeton) tstDER() []byte {
	parts := [][]byte{entierDER(mj.versionTST), oidDER(mj.politique), seq(mj.algoImprint, oct(mj.empreinte)), mj.serie,
		elem(casn1.GeneralizedTime, []byte(mj.genTime))}
	if mj.precision != nil {
		parts = append(parts, mj.precision)
	}
	if mj.ordering != nil {
		parts = append(parts, mj.ordering)
	}
	parts = append(parts, entierDER(0x44036595))
	if mj.tsa != nil {
		parts = append(parts, elem(ctx(0, true), mj.tsa))
	}
	if len(mj.extsTST) > 0 {
		parts = append(parts, elem(ctx(1, true), extsDER(mj.extsTST)...))
	}
	b := seq(parts...)
	if mj.tstBrut != nil {
		b = mj.tstBrut(b)
	}
	return b
}

// essV2 : SigningCertificateV2 avec un ESSCertIDv2 (hashAlgorithm absent)
// et issuerSerial.
func essV2(cert []byte, emetteur []byte, serie int64) []byte {
	h := sha256.Sum256(cert)
	return seq(seq(seq(oct(h[:]), seq(seq(elem(ctx(4, true), emetteur)), entierDER(serie)))))
}

func attributDER(a attrTest) []byte { return seq(oidDER(a.oid), set(a.valeurs...)) }

func fabriquerJeton(t testing.TB, mj *modeleJeton) []byte {
	t.Helper()
	tst := mj.tstDER()
	md := mj.digestHash.New()
	md.Write(tst)
	ct := attrTest{oidContentType, [][]byte{oidDER(oidTSTInfo)}}
	mdA := attrTest{oidMessageDig, [][]byte{oct(md.Sum(nil))}}
	ess := attrTest{oidSigningCert2, [][]byte{essV2(mj.certESS, mj.sidEmetteur, mj.sidSerie)}}
	attrs := []attrTest{ct, mdA, ess}
	if mj.attrs != nil {
		attrs = mj.attrs(attrs, tst)
	}
	var ad [][]byte
	for _, a := range attrs {
		ad = append(ad, attributDER(a))
	}
	aSet := set(ad...)
	sig := mj.sign.signer(t, aSet)
	if mj.inverserSig {
		sig[len(sig)-1] ^= 0xff
	}
	signed := append([]byte{0xa0}, aSet[1:]...)
	var sid []byte
	ver := int64(1)
	if mj.sidSKI != nil {
		ver = 3
		sid = elem(ctx(0, false), mj.sidSKI)
	} else {
		sid = seq(mj.sidEmetteur, entierDER(mj.sidSerie))
	}
	sa := mj.sigAlgo
	if sa == nil {
		sa = mj.sign.algo
	}
	si := seq(entierDER(ver), sid, mj.digest, signed, sa, oct(sig))
	ec := oct(tst)
	if mj.eContentConstruit {
		ec = elem(casn1.Tag(4).Constructed(), oct(tst))
	}
	sdParts := [][]byte{entierDER(mj.versionSD), set(mj.digest), seq(oidDER(oidTSTInfo), elem(ctx(0, true), ec))}
	if len(mj.certs) > 0 {
		sdParts = append(sdParts, elem(ctx(0, true), mj.certs...))
	}
	if len(mj.crls) > 0 {
		sdParts = append(sdParts, elem(ctx(1, true), mj.crls...))
	}
	if mj.doublerSI {
		sdParts = append(sdParts, set(si, si))
	} else {
		sdParts = append(sdParts, set(si))
	}
	return seq(oidDER(oidSignedData), elem(ctx(0, true), seq(sdParts...)))
}

// ancresTest : ancres-test.json réduit à sa partie d'horodatage.
func (m *materiel) ancresTest() *ancres.Ancres {
	return &ancres.Ancres{
		Autorites: []ancres.Autorite{{Pointeur: "/tsa_authorities/0", Nom: "AC de test CT-6", Certificat: m.certAC, PolitiquesAdmises: []string{politiqueTest.String()}}},
		CRLs:      []ancres.CRL{{Pointeur: "/revocation/crls/0", DER: m.crlVide}},
	}
}

// entreeTest construit l'Entree d'un jeton de clôture.
func (m *materiel) entree(t testing.TB, jeton []byte, a *ancres.Ancres) Entree {
	e := Entree{Usage: Cloture, Jeton: jeton, Etat: entree.Lu, EmpreinteDisponible: true, Ancres: a}
	e.EmpreinteAttendue = hex32(t, periodHash1)
	return e
}
