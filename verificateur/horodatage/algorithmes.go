package horodatage

// Identifiants (CT-6 §9.4), fonctions de hachage, clés publiques et
// vérification des signatures (T-3, T-5, T-6, et la règle 3 de T-7 et de
// T-10). Les signatures sont vérifiées par crypto/rsa et crypto/ecdsa ;
// crypto/x509 ne sert qu'à lire une clé publique ECDSA (EX-14.4).

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"hash"

	"golang.org/x/crypto/cryptobyte"
	casn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidSignedData   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidContentType  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDig   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningCert  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	oidSigningCert2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}

	oidMD5    = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA224 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidRSA          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidMD5RSA       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	oidSHA1RSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidPSS          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidSHA256RSA    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384RSA    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512RSA    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidSHA224RSA    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 14}
	oidMGF1         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	oidECDSASHA1    = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidECDSASHA224  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 1}
	oidECDSASHA256  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSASHA384  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSASHA512  = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidClePubliqueE = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidP256         = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidP384         = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidP521         = asn1.ObjectIdentifier{1, 3, 132, 0, 35}

	oidTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidQCStatements = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 3}
	oidQTST         = asn1.ObjectIdentifier{0, 4, 0, 19422, 1, 1}
	oidSKI          = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidKeyUsage     = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidBasicConstr  = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtKeyUsage  = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidCRLReason    = asn1.ObjectIdentifier{2, 5, 29, 21}
	oidDeltaCRL     = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidIDP          = asn1.ObjectIdentifier{2, 5, 29, 28}
	oidCommonName   = asn1.ObjectIdentifier{2, 5, 4, 3}
)

// empreinteParOID : fonction de hachage d'un AlgorithmIdentifier de
// hachage ; T-3 la calcule pour MD5, SHA-1, SHA-224, SHA-256, SHA-384 et
// SHA-512 (EX-9.9).
func empreinteParOID(o asn1.ObjectIdentifier) (crypto.Hash, bool) {
	switch {
	case o.Equal(oidMD5):
		return crypto.MD5, true
	case o.Equal(oidSHA1):
		return crypto.SHA1, true
	case o.Equal(oidSHA224):
		return crypto.SHA224, true
	case o.Equal(oidSHA256):
		return crypto.SHA256, true
	case o.Equal(oidSHA384):
		return crypto.SHA384, true
	case o.Equal(oidSHA512):
		return crypto.SHA512, true
	}
	return 0, false
}

// nouveauHachage rend un hachage des six fonctions que T-3 calcule.
func nouveauHachage(h crypto.Hash) hash.Hash {
	switch h {
	case crypto.MD5:
		return md5.New()
	case crypto.SHA1:
		return sha1.New()
	case crypto.SHA224:
		return sha256.New224()
	case crypto.SHA256:
		return sha256.New()
	case crypto.SHA384:
		return sha512.New384()
	case crypto.SHA512:
		return sha512.New()
	}
	return nil
}

func hacher(h crypto.Hash, b []byte) []byte {
	x := nouveauHachage(h)
	if x == nil {
		return nil
	}
	x.Write(b)
	return x.Sum(nil)
}

// admise : fonction admise par T-5 (SHA-256, SHA-384, SHA-512, EX-9.11).
func admise(h crypto.Hash) bool {
	return h == crypto.SHA256 || h == crypto.SHA384 || h == crypto.SHA512
}

func nomEmpreinte(h crypto.Hash) string {
	switch h {
	case crypto.SHA256:
		return "sha256"
	case crypto.SHA384:
		return "sha384"
	case crypto.SHA512:
		return "sha512"
	case crypto.SHA224:
		return "sha224"
	case crypto.SHA1:
		return "sha1"
	case crypto.MD5:
		return "md5"
	}
	return "inconnue"
}

// Admission d'un élément par T-5 (EX-9.11).
type admission int

const (
	admis admission = iota
	refuse
	horsPerimetre
)

// genreSignature : famille d'une signature admise.
type genreSignature int

const (
	sigRSAPKCS1 genreSignature = iota
	sigRSAPSS
	sigECDSA
)

// signature : algorithme de signature analysé.
type signature struct {
	nom   string
	genre genreSignature
	hash  crypto.Hash
	sel   int // longueur du sel (RSASSA-PSS)
}

// analyserSignature applique la table d'EX-9.11 à un algorithme de
// signature. digest est la fonction de SignerInfo.digestAlgorithm, ou 0
// pour la signature d'un certificat ou d'une CRL (règle 3 de T-7, règle 1
// de T-10), où la fonction est celle de l'algorithme lui-même.
func analyserSignature(a algo, digest crypto.Hash) (signature, admission, *defaut) {
	avecHash := func(nom string, g genreSignature, h crypto.Hash) (signature, admission, *defaut) {
		s := signature{nom: nom, genre: g, hash: h}
		if !a.paramsNulOuAbsents() {
			return s, refuse, defF("paramètres de %s contraires à EX-9.11", "parameters of %s contrary to EX-9.11", nom)
		}
		if digest != 0 && h != digest {
			return s, refuse, defF("%s ne porte pas la fonction de digestAlgorithm (%s)", "%s does not use the digestAlgorithm function (%s)", nom, nomEmpreinte(digest))
		}
		return s, admis, nil
	}
	switch {
	case a.oid.Equal(oidRSA):
		if digest == 0 {
			return signature{nom: "rsaEncryption"}, refuse, def("rsaEncryption ne désigne pas de fonction de hachage pour une signature de certificat", "rsaEncryption names no hash function for a certificate signature")
		}
		s := signature{nom: "rsaEncryption", genre: sigRSAPKCS1, hash: digest}
		if !a.paramsNulOuAbsents() {
			return s, refuse, def("paramètres de rsaEncryption ni NULL ni absents", "rsaEncryption parameters neither NULL nor absent")
		}
		return s, admis, nil
	case a.oid.Equal(oidSHA256RSA):
		return avecHash("sha256WithRSAEncryption", sigRSAPKCS1, crypto.SHA256)
	case a.oid.Equal(oidSHA384RSA):
		return avecHash("sha384WithRSAEncryption", sigRSAPKCS1, crypto.SHA384)
	case a.oid.Equal(oidSHA512RSA):
		return avecHash("sha512WithRSAEncryption", sigRSAPKCS1, crypto.SHA512)
	case a.oid.Equal(oidECDSASHA256):
		return avecHash("ecdsa-with-SHA256", sigECDSA, crypto.SHA256)
	case a.oid.Equal(oidECDSASHA384):
		return avecHash("ecdsa-with-SHA384", sigECDSA, crypto.SHA384)
	case a.oid.Equal(oidECDSASHA512):
		return avecHash("ecdsa-with-SHA512", sigECDSA, crypto.SHA512)
	case a.oid.Equal(oidSHA1RSA), a.oid.Equal(oidMD5RSA), a.oid.Equal(oidECDSASHA1):
		return signature{nom: a.oid.String()}, refuse, def("signature RSA ou ECDSA sur SHA-1 ou MD5 (EX-9.11)", "RSA or ECDSA signature over SHA-1 or MD5 (EX-9.11)")
	case a.oid.Equal(oidSHA224RSA), a.oid.Equal(oidECDSASHA224):
		return signature{nom: a.oid.String()}, refuse, def("signature RSA ou ECDSA sur SHA-224, fonction non admise (EX-9.11)", "RSA or ECDSA signature over SHA-224, function not admitted (EX-9.11)")
	case a.oid.Equal(oidPSS):
		return analyserPSS(a, digest)
	}
	return signature{nom: a.oid.String()}, horsPerimetre, defF("algorithme de signature %s hors de la version 0 (EX-9.11)", "signature algorithm %s outside version 0 (EX-9.11)", a.oid.String())
}

// analyserPSS lit RSASSA-PSS-params (RFC 4055 §3.1) : hashAlgorithm [0]
// (SHA-1 par défaut), maskGenAlgorithm [1] (MGF1 avec SHA-1 par défaut),
// saltLength [2] (20), trailerField [3] (1).
func analyserPSS(a algo, digest crypto.Hash) (signature, admission, *defaut) {
	s := signature{nom: "id-RSASSA-PSS", genre: sigRSAPSS, hash: crypto.SHA1, sel: 20}
	contraire := func() (signature, admission, *defaut) {
		return s, refuse, def("paramètres RSASSA-PSS contraires à EX-9.11", "RSASSA-PSS parameters contrary to EX-9.11")
	}
	if a.params == nil {
		return contraire()
	}
	p := cryptobyte.String(a.params)
	var seq cryptobyte.String
	if !p.ReadASN1(&seq, casn1.SEQUENCE) || !p.Empty() {
		return contraire()
	}
	mgfHash := crypto.SHA1
	trailer := int64(1)
	if seq.PeekASN1Tag(ctx(0, true)) {
		var c cryptobyte.String
		if !seq.ReadASN1(&c, ctx(0, true)) {
			return contraire()
		}
		h, ok := lireAlgo(&c)
		if !ok || !c.Empty() || !h.paramsNulOuAbsents() {
			return contraire()
		}
		hh, ok := empreinteParOID(h.oid)
		if !ok {
			return contraire()
		}
		s.hash = hh
	}
	if seq.PeekASN1Tag(ctx(1, true)) {
		var c cryptobyte.String
		if !seq.ReadASN1(&c, ctx(1, true)) {
			return contraire()
		}
		m, ok := lireAlgo(&c)
		if !ok || !c.Empty() || !m.oid.Equal(oidMGF1) || m.params == nil {
			return contraire()
		}
		mp := cryptobyte.String(m.params)
		h, ok := lireAlgo(&mp)
		if !ok || !mp.Empty() || !h.paramsNulOuAbsents() {
			return contraire()
		}
		hh, ok := empreinteParOID(h.oid)
		if !ok {
			return contraire()
		}
		mgfHash = hh
	}
	if seq.PeekASN1Tag(ctx(2, true)) {
		var c cryptobyte.String
		b, ok := []byte(nil), seq.ReadASN1(&c, ctx(2, true))
		if ok {
			b, ok = lireEntier(&c, casn1.INTEGER)
		}
		n, ok2 := petitEntier(b)
		if !ok || !ok2 || !c.Empty() || n < 0 || n > 1<<16 {
			return contraire()
		}
		s.sel = int(n)
	}
	if seq.PeekASN1Tag(ctx(3, true)) {
		var c cryptobyte.String
		b, ok := []byte(nil), seq.ReadASN1(&c, ctx(3, true))
		if ok {
			b, ok = lireEntier(&c, casn1.INTEGER)
		}
		n, ok2 := petitEntier(b)
		if !ok || !ok2 || !c.Empty() {
			return contraire()
		}
		trailer = n
	}
	if !seq.Empty() {
		return contraire()
	}
	if !admise(s.hash) || mgfHash != s.hash || trailer != 1 || (digest != 0 && s.hash != digest) {
		return contraire()
	}
	return s, admis, nil
}

// cle : clé publique d'un certificat (subjectPublicKeyInfo).
type cle struct {
	rsa   *rsa.PublicKey
	ecdsa *ecdsa.PublicKey
	bits  int
}

// lireCle lit une clé publique et applique la ligne « Clé publique de S »
// d'EX-9.11 : RSA de module d'au moins 2048 bits, ECDSA sur P-256, P-384
// ou P-521 ; RSA plus courte : refusée ; autre type ou autre courbe : hors
// de la version 0.
func lireCle(spki []byte) (*cle, admission, *defaut) {
	s := cryptobyte.String(spki)
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, casn1.SEQUENCE) || !s.Empty() {
		return nil, refuse, def("subjectPublicKeyInfo illisible", "unreadable subjectPublicKeyInfo")
	}
	a, ok := lireAlgo(&seq)
	var bits asn1.BitString
	if !ok || !seq.ReadASN1BitString(&bits) || !seq.Empty() || bits.BitLength%8 != 0 {
		return nil, refuse, def("subjectPublicKeyInfo illisible", "unreadable subjectPublicKeyInfo")
	}
	switch {
	case a.oid.Equal(oidRSA):
		if !a.paramsNulOuAbsents() {
			return nil, refuse, def("paramètres de clé RSA ni NULL ni absents", "RSA key parameters neither NULL nor absent")
		}
		k := cryptobyte.String(bits.Bytes)
		var rk cryptobyte.String
		if !k.ReadASN1(&rk, casn1.SEQUENCE) || !k.Empty() {
			return nil, refuse, def("clé RSA illisible", "unreadable RSA key")
		}
		nb, ok1 := lireEntier(&rk, casn1.INTEGER)
		eb, ok2 := lireEntier(&rk, casn1.INTEGER)
		if !ok1 || !ok2 || !rk.Empty() {
			return nil, refuse, def("clé RSA illisible", "unreadable RSA key")
		}
		n, e := valeurEntier(nb), valeurEntier(eb)
		if n.Sign() <= 0 || e.Sign() <= 0 || !e.IsInt64() || e.Int64() > 1<<31-1 || e.Int64() < 2 {
			return nil, refuse, def("clé RSA invalide", "invalid RSA key")
		}
		c := &cle{rsa: &rsa.PublicKey{N: n, E: int(e.Int64())}, bits: n.BitLen()}
		if c.bits < 2048 {
			return c, refuse, defF("clé RSA de %d bits, moins de 2048 (EX-9.11)", "RSA key of %d bits, less than 2048 (EX-9.11)", c.bits)
		}
		return c, admis, nil
	case a.oid.Equal(oidClePubliqueE):
		pc := cryptobyte.String(a.params)
		courbe, ok := lireOID(&pc)
		if a.params == nil || !ok || !pc.Empty() {
			return nil, horsPerimetre, def("clé ECDSA sans courbe nommée, hors de la version 0", "ECDSA key without a named curve, outside version 0")
		}
		if !courbe.Equal(oidP256) && !courbe.Equal(oidP384) && !courbe.Equal(oidP521) {
			return nil, horsPerimetre, defF("courbe %s hors de la version 0 (EX-9.11)", "curve %s outside version 0 (EX-9.11)", courbe.String())
		}
		pub, err := x509.ParsePKIXPublicKey(spki)
		k, okE := pub.(*ecdsa.PublicKey)
		if err != nil || !okE {
			return nil, refuse, def("clé ECDSA illisible", "unreadable ECDSA key")
		}
		return &cle{ecdsa: k, bits: k.Curve.Params().BitSize}, admis, nil
	}
	return nil, horsPerimetre, defF("type de clé %s hors de la version 0 (EX-9.11)", "key type %s outside version 0 (EX-9.11)", a.oid.String())
}

// accorde : la famille de signature convient au type de clé.
func (c *cle) accorde(s signature) bool {
	if c == nil {
		return false
	}
	switch s.genre {
	case sigRSAPKCS1, sigRSAPSS:
		return c.rsa != nil
	case sigECDSA:
		return c.ecdsa != nil
	}
	return false
}

// verifier vérifie une signature sur un message (EX-9.12) : RSA PKCS #1
// v1.5 (valeur de la longueur du module), RSASSA-PSS, ou ECDSA (structure
// DER SEQUENCE { r, s }).
func (c *cle) verifier(s signature, message, sig []byte) bool {
	if !c.accorde(s) {
		return false
	}
	h := hacher(s.hash, message)
	if h == nil {
		return false
	}
	switch s.genre {
	case sigRSAPKCS1:
		return rsa.VerifyPKCS1v15(c.rsa, s.hash, h, sig) == nil
	case sigRSAPSS:
		return rsa.VerifyPSS(c.rsa, s.hash, h, sig, &rsa.PSSOptions{SaltLength: s.sel, Hash: s.hash}) == nil
	case sigECDSA:
		return ecdsa.VerifyASN1(c.ecdsa, h, sig)
	}
	return false
}
