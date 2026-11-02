package horodatage

// Lecture stricte des certificats X.509 et des CRL (RFC 5280), du jeton
// comme du fichier d'ancres, selon le profil de §9.3 : noms d'EX-9.4,
// valeurs DEFAULT encodées d'EX-9.21 (critical à FALSE, cA à FALSE,
// version v1), et ControleurAncres pour N-1 (EX-12.2).

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"time"

	"golang.org/x/crypto/cryptobyte"
	casn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// certificat : certificat lu selon le profil de §9.3.
type certificat struct {
	der    []byte
	sha256 [32]byte
	// tbs : élément DER complet de tbsCertificate (octets signés).
	tbs     []byte
	version int
	serie   []byte
	// emetteur, sujet : éléments DER complets des Name, comparés octet pour
	// octet (EX-9.10, EX-9.13).
	emetteur, sujet []byte
	cn              *string
	debut, fin      time.Time
	spki            []byte
	extensions      []extension
	algoSig         algo
	signature       []byte

	// Extensions décodées.
	bc  *contraintes
	ku  *usageCle
	eku *usageEtendu
	ski []byte
}

type contraintes struct {
	critique bool
	ca       bool
	// longueur : pathLenConstraint, ou -1 s'il est absent.
	longueur int64
}

type usageCle struct {
	bits []byte
	// nbBits : nombre de bits significatifs.
	nbBits int
}

// a dit si le bit n (0 = digitalSignature) est positionné.
func (u *usageCle) a(n int) bool {
	if n >= u.nbBits || n/8 >= len(u.bits) {
		return false
	}
	return u.bits[n/8]&(0x80>>(n%8)) != 0
}

// positionnes rend les numéros des bits positionnés.
func (u *usageCle) positionnes() []int {
	var out []int
	for i := 0; i < u.nbBits; i++ {
		if u.a(i) {
			out = append(out, i)
		}
	}
	return out
}

type usageEtendu struct {
	critique bool
	oids     []asn1.ObjectIdentifier
}

// lireCertificat lit un certificat DER complet, sans octet en trop.
func lireCertificat(der []byte) (*certificat, *defaut) {
	if d := verifierProfil(der, 0); d != nil {
		return nil, d
	}
	return analyserCertificat(der)
}

func illisible(fr, en string) *defaut {
	return def("certificat illisible : "+fr, "unreadable certificate: "+en)
}

// analyserCertificat lit un certificat dont le profil DER général a déjà
// été contrôlé (seul ou comme partie d'un jeton).
func analyserCertificat(der []byte) (*certificat, *defaut) {
	c := &certificat{der: der, sha256: sha256.Sum256(der)}
	s := cryptobyte.String(der)
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, casn1.SEQUENCE) || !s.Empty() {
		return nil, illisible("Certificate n'est pas une SEQUENCE seule", "Certificate is not a single SEQUENCE")
	}
	var tbsBrut cryptobyte.String
	if !seq.ReadASN1Element(&tbsBrut, casn1.SEQUENCE) {
		return nil, illisible("tbsCertificate", "tbsCertificate")
	}
	c.tbs = []byte(tbsBrut)
	var ok bool
	if c.algoSig, ok = lireAlgo(&seq); !ok {
		return nil, illisible("signatureAlgorithm", "signatureAlgorithm")
	}
	var bits asn1.BitString
	if !seq.ReadASN1BitString(&bits) || bits.BitLength%8 != 0 || !seq.Empty() {
		return nil, illisible("signatureValue, ou éléments en trop", "signatureValue, or extra elements")
	}
	c.signature = bits.Bytes

	tbs := cryptobyte.String(c.tbs)
	var t cryptobyte.String
	tbs.ReadASN1(&t, casn1.SEQUENCE)
	c.version = 1
	if t.PeekASN1Tag(ctx(0, true)) {
		var v cryptobyte.String
		if !t.ReadASN1(&v, ctx(0, true)) {
			return nil, illisible("version", "version")
		}
		b, ok := lireEntier(&v, casn1.INTEGER)
		n, ok2 := petitEntier(b)
		if !ok || !ok2 || !v.Empty() {
			return nil, illisible("version", "version")
		}
		switch n {
		case 0:
			return nil, def("certificat illisible : version v1 encodée, valeur DEFAULT (EX-9.21)", "unreadable certificate: version v1 encoded, a DEFAULT value (EX-9.21)")
		case 1, 2:
			c.version = int(n) + 1
		default:
			return nil, illisible("version inconnue", "unknown version")
		}
	}
	if c.serie, ok = lireEntier(&t, casn1.INTEGER); !ok {
		return nil, illisible("serialNumber", "serialNumber")
	}
	algoTBS, ok := lireAlgo(&t)
	if !ok {
		return nil, illisible("signature du tbsCertificate", "tbsCertificate signature")
	}
	var d *defaut
	if c.emetteur, _, d = lireNom(&t); d != nil {
		return nil, prefixer(d, "certificat illisible : émetteur : ", "unreadable certificate: issuer: ")
	}
	var val cryptobyte.String
	if !t.ReadASN1(&val, casn1.SEQUENCE) {
		return nil, illisible("validity", "validity")
	}
	if c.debut, ok = lireTemps(&val); !ok {
		return nil, illisible("notBefore", "notBefore")
	}
	if c.fin, ok = lireTemps(&val); !ok || !val.Empty() {
		return nil, illisible("notAfter", "notAfter")
	}
	if c.sujet, c.cn, d = lireNom(&t); d != nil {
		return nil, prefixer(d, "certificat illisible : sujet : ", "unreadable certificate: subject: ")
	}
	var spki cryptobyte.String
	if !t.ReadASN1Element(&spki, casn1.SEQUENCE) {
		return nil, illisible("subjectPublicKeyInfo", "subjectPublicKeyInfo")
	}
	c.spki = []byte(spki)
	for _, n := range []uint8{1, 2} {
		if t.PeekASN1Tag(ctx(n, false)) {
			if c.version < 2 || !t.SkipASN1(ctx(n, false)) {
				return nil, illisible("identifiant unique", "unique identifier")
			}
		}
	}
	if t.PeekASN1Tag(ctx(3, true)) {
		var e cryptobyte.String
		if c.version != 3 || !t.ReadASN1(&e, ctx(3, true)) {
			return nil, illisible("extensions", "extensions")
		}
		if c.extensions, ok = lireExtensions(&e); !ok || !e.Empty() {
			return nil, illisible("extensions", "extensions")
		}
	}
	if !t.Empty() {
		return nil, illisible("éléments en trop dans tbsCertificate", "extra elements in tbsCertificate")
	}
	if !algoTBS.oid.Equal(c.algoSig.oid) || !bytes.Equal(algoTBS.params, c.algoSig.params) {
		return nil, illisible("algorithmes de signature différents dans tbsCertificate et Certificate", "different signature algorithms in tbsCertificate and Certificate")
	}
	if d := c.decoderExtensions(); d != nil {
		return nil, d
	}
	return c, nil
}

// decoderExtensions refuse un critical encodé à FALSE et une extension en
// double, et décode basicConstraints (cA encodé à FALSE refusé, EX-9.21),
// keyUsage, extKeyUsage et subjectKeyIdentifier.
func (c *certificat) decoderExtensions() *defaut {
	vus := map[string]bool{}
	for _, x := range c.extensions {
		if x.critiqueFauxEncode {
			return defF("certificat illisible : critical encodé à FALSE dans l'extension %s, valeur DEFAULT (EX-9.21)", "unreadable certificate: critical encoded as FALSE in extension %s, a DEFAULT value (EX-9.21)", x.oid.String())
		}
		k := x.oid.String()
		if vus[k] {
			return defF("certificat illisible : extension %s en double", "unreadable certificate: duplicate extension %s", k)
		}
		vus[k] = true
		mal := func() *defaut {
			return defF("certificat illisible : valeur de l'extension %s", "unreadable certificate: value of extension %s", k)
		}
		if !x.oid.Equal(oidBasicConstr) && !x.oid.Equal(oidKeyUsage) && !x.oid.Equal(oidExtKeyUsage) && !x.oid.Equal(oidSKI) {
			continue
		}
		if d := verifierProfil(x.valeur, 0); d != nil {
			return mal()
		}
		v := cryptobyte.String(x.valeur)
		switch {
		case x.oid.Equal(oidBasicConstr):
			var seq cryptobyte.String
			if !v.ReadASN1(&seq, casn1.SEQUENCE) || !v.Empty() {
				return mal()
			}
			bc := &contraintes{critique: x.critique, longueur: -1}
			if seq.PeekASN1Tag(casn1.BOOLEAN) {
				if !seq.ReadASN1Boolean(&bc.ca) {
					return mal()
				}
				if !bc.ca {
					return def("certificat illisible : cA de basicConstraints encodé à FALSE, valeur DEFAULT (EX-9.21)", "unreadable certificate: basicConstraints cA encoded as FALSE, a DEFAULT value (EX-9.21)")
				}
			}
			if seq.PeekASN1Tag(casn1.INTEGER) {
				b, ok := lireEntier(&seq, casn1.INTEGER)
				n, ok2 := petitEntier(b)
				if !ok || !ok2 || n < 0 {
					return mal()
				}
				bc.longueur = n
			}
			if !seq.Empty() {
				return mal()
			}
			c.bc = bc
		case x.oid.Equal(oidKeyUsage):
			var bits asn1.BitString
			if !v.ReadASN1BitString(&bits) || !v.Empty() {
				return mal()
			}
			c.ku = &usageCle{bits: bits.Bytes, nbBits: bits.BitLength}
		case x.oid.Equal(oidExtKeyUsage):
			var seq cryptobyte.String
			if !v.ReadASN1(&seq, casn1.SEQUENCE) || !v.Empty() {
				return mal()
			}
			u := &usageEtendu{critique: x.critique}
			for !seq.Empty() {
				o, ok := lireOID(&seq)
				if !ok {
					return mal()
				}
				u.oids = append(u.oids, o)
			}
			c.eku = u
		case x.oid.Equal(oidSKI):
			var o cryptobyte.String
			if !v.ReadASN1(&o, casn1.OCTET_STRING) || !v.Empty() {
				return mal()
			}
			c.ski = []byte(o)
		}
	}
	return nil
}

// critiqueInconnue rend l'OID d'une extension critique autre que
// basicConstraints, keyUsage et extKeyUsage (règle 6 de T-7), ou "".
func (c *certificat) critiqueInconnue() string {
	for _, x := range c.extensions {
		if x.critique && !x.oid.Equal(oidBasicConstr) && !x.oid.Equal(oidKeyUsage) && !x.oid.Equal(oidExtKeyUsage) {
			return x.oid.String()
		}
	}
	return ""
}

// crl : liste de révocation lue selon le profil de §9.3.
type crl struct {
	der []byte
	// tbs : élément DER complet de tbsCertList (octets signés).
	tbs        []byte
	emetteur   []byte
	thisUpdate time.Time
	entrees    []entreeCRL
	extensions []extension
	algoSig    algo
	signature  []byte
}

type entreeCRL struct {
	serie []byte
	date  time.Time
	// raison : cRLReasons, ou -1 si l'entrée n'en porte pas.
	raison int
}

// complete : ni deltaCRLIndicator, ni issuingDistributionPoint critique
// (EX-9.16).
func (l *crl) complete() bool {
	for _, x := range l.extensions {
		if x.oid.Equal(oidDeltaCRL) || (x.oid.Equal(oidIDP) && x.critique) {
			return false
		}
	}
	return true
}

// liste rend l'entrée qui porte ce numéro de série, ou nil.
func (l *crl) liste(serie []byte) *entreeCRL {
	for i := range l.entrees {
		if memeEntier(l.entrees[i].serie, serie) {
			return &l.entrees[i]
		}
	}
	return nil
}

func crlIllisible(fr, en string) *defaut {
	return def("CRL illisible : "+fr, "unreadable CRL: "+en)
}

// lireCRL lit une CRL DER complète, sans octet en trop.
func lireCRL(der []byte) (*crl, *defaut) {
	if d := verifierProfil(der, 0); d != nil {
		return nil, d
	}
	l := &crl{der: der}
	s := cryptobyte.String(der)
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, casn1.SEQUENCE) || !s.Empty() {
		return nil, crlIllisible("CertificateList n'est pas une SEQUENCE seule", "CertificateList is not a single SEQUENCE")
	}
	var tbsBrut cryptobyte.String
	if !seq.ReadASN1Element(&tbsBrut, casn1.SEQUENCE) {
		return nil, crlIllisible("tbsCertList", "tbsCertList")
	}
	l.tbs = []byte(tbsBrut)
	var ok bool
	if l.algoSig, ok = lireAlgo(&seq); !ok {
		return nil, crlIllisible("signatureAlgorithm", "signatureAlgorithm")
	}
	var bits asn1.BitString
	if !seq.ReadASN1BitString(&bits) || bits.BitLength%8 != 0 || !seq.Empty() {
		return nil, crlIllisible("signatureValue, ou éléments en trop", "signatureValue, or extra elements")
	}
	l.signature = bits.Bytes
	tbs := cryptobyte.String(l.tbs)
	var t cryptobyte.String
	tbs.ReadASN1(&t, casn1.SEQUENCE)
	if t.PeekASN1Tag(casn1.INTEGER) {
		b, ok := lireEntier(&t, casn1.INTEGER)
		n, ok2 := petitEntier(b)
		if !ok || !ok2 || (n != 0 && n != 1) {
			return nil, crlIllisible("version", "version")
		}
	}
	algoTBS, ok := lireAlgo(&t)
	if !ok || !algoTBS.oid.Equal(l.algoSig.oid) || !bytes.Equal(algoTBS.params, l.algoSig.params) {
		return nil, crlIllisible("signature du tbsCertList", "tbsCertList signature")
	}
	var d *defaut
	if l.emetteur, _, d = lireNom(&t); d != nil {
		return nil, prefixer(d, "CRL illisible : émetteur : ", "unreadable CRL: issuer: ")
	}
	if l.thisUpdate, ok = lireTemps(&t); !ok {
		return nil, crlIllisible("thisUpdate", "thisUpdate")
	}
	if t.PeekASN1Tag(casn1.UTCTime) || t.PeekASN1Tag(casn1.GeneralizedTime) {
		if _, ok := lireTemps(&t); !ok {
			return nil, crlIllisible("nextUpdate", "nextUpdate")
		}
	}
	if t.PeekASN1Tag(casn1.SEQUENCE) {
		var rev cryptobyte.String
		t.ReadASN1(&rev, casn1.SEQUENCE)
		for !rev.Empty() {
			var e cryptobyte.String
			if !rev.ReadASN1(&e, casn1.SEQUENCE) {
				return nil, crlIllisible("revokedCertificates", "revokedCertificates")
			}
			en := entreeCRL{raison: -1}
			if en.serie, ok = lireEntier(&e, casn1.INTEGER); !ok {
				return nil, crlIllisible("userCertificate", "userCertificate")
			}
			if en.date, ok = lireTemps(&e); !ok {
				return nil, crlIllisible("revocationDate", "revocationDate")
			}
			if !e.Empty() {
				exts, ok := lireExtensions(&e)
				if !ok || !e.Empty() {
					return nil, crlIllisible("crlEntryExtensions", "crlEntryExtensions")
				}
				for _, x := range exts {
					if x.critiqueFauxEncode {
						return nil, defF("CRL illisible : critical encodé à FALSE dans l'extension d'entrée %s, valeur DEFAULT (EX-9.21)", "unreadable CRL: critical encoded as FALSE in entry extension %s, a DEFAULT value (EX-9.21)", x.oid.String())
					}
					if x.oid.Equal(oidCRLReason) {
						v := cryptobyte.String(x.valeur)
						var r int
						if verifierProfil(x.valeur, 0) != nil || !v.ReadASN1Enum(&r) || !v.Empty() || en.raison != -1 {
							return nil, crlIllisible("cRLReasons", "cRLReasons")
						}
						en.raison = r
					}
				}
			}
			l.entrees = append(l.entrees, en)
		}
	}
	if t.PeekASN1Tag(ctx(0, true)) {
		var e cryptobyte.String
		t.ReadASN1(&e, ctx(0, true))
		if l.extensions, ok = lireExtensions(&e); !ok || !e.Empty() {
			return nil, crlIllisible("crlExtensions", "crlExtensions")
		}
		for _, x := range l.extensions {
			if x.critiqueFauxEncode {
				return nil, defF("CRL illisible : critical encodé à FALSE dans l'extension %s, valeur DEFAULT (EX-9.21)", "unreadable CRL: critical encoded as FALSE in extension %s, a DEFAULT value (EX-9.21)", x.oid.String())
			}
		}
	}
	if !t.Empty() {
		return nil, crlIllisible("éléments en trop dans tbsCertList", "extra elements in tbsCertList")
	}
	return l, nil
}

// controlerCertificat : N-1 pour un certificat du fichier d'ancres
// (EX-12.2) : profil DER de §9.3, noms d'EX-9.4, valeurs DEFAULT
// d'EX-9.21.
func controlerCertificat(der []byte) error {
	if _, d := lireCertificat(der); d != nil {
		return d
	}
	return nil
}

// controlerCRL : N-1 pour une CRL du fichier d'ancres.
func controlerCRL(der []byte) error {
	if _, d := lireCRL(der); d != nil {
		return d
	}
	return nil
}
