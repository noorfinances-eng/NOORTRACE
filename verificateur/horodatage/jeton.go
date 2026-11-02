package horodatage

// Lecture du TimeStampToken (T-1, EX-9.2, EX-9.7) : ContentInfo,
// SignedData, SignerInfo et TSTInfo selon le profil de §9.3. Le jeton
// n'est jamais réencodé (EX-9.6) : les éléments signés sont gardés tels
// que reçus.

import (
	"encoding/asn1"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	casn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// maxCertificats : certificats dans le champ certificates (EX-9.7, §15.1).
const maxCertificats = 16

// attribut : Attribute d'un signedAttrs (RFC 5652 §5.3).
type attribut struct {
	oid asn1.ObjectIdentifier
	// valeurs : éléments DER complets du SET OF AttributeValue.
	valeurs [][]byte
}

// signataire : le SignerInfo unique (EX-9.7).
type signataire struct {
	version int
	// sid : issuerAndSerialNumber (version 1) ou subjectKeyIdentifier
	// (version 3).
	sidEmetteur, sidSerie []byte
	sidSKI                []byte
	digest                algo
	// attrsBruts : élément DER complet de signedAttrs, étiquette a0
	// comprise (EX-9.12).
	attrsBruts []byte
	attributs  []attribut
	algoSig    algo
	signature  []byte
}

// precisionLue : Accuracy de TSTInfo, octets des INTEGER présents.
type precisionLue struct {
	s, ms, us []byte
}

// tstInfo : TSTInfo (RFC 3161 §2.4.2).
type tstInfo struct {
	politique   asn1.ObjectIdentifier
	algoImprint algo
	imprint     []byte
	serie       []byte
	genTime     []byte
	precision   *precisionLue
	tsaPresent  bool
	// tsaNom : élément DER complet du Name quand tsa est un directoryName.
	tsaNom     []byte
	extensions []extension
}

// jeton : TimeStampToken lu.
type jeton struct {
	certificats []*certificat
	// crls : éléments CertificateList du champ crls, dans l'ordre.
	crls     [][]byte
	eContent []byte
	tst      tstInfo
	sig      signataire
}

func t1(fr, en string) *defaut { return def(fr, en) }

// lireJeton applique EX-9.7 aux octets du fichier (ou du base64 décodé).
func lireJeton(der []byte) (*jeton, *defaut) {
	if d := verifierProfil(der, 0); d != nil {
		return nil, d
	}
	j := &jeton{}
	s := cryptobyte.String(der)
	var ci cryptobyte.String
	if !s.ReadASN1(&ci, casn1.SEQUENCE) || !s.Empty() {
		return nil, t1("ContentInfo illisible", "unreadable ContentInfo")
	}
	o, ok := lireOID(&ci)
	if !ok || !o.Equal(oidSignedData) {
		return nil, t1("contentType autre que id-signedData (une réponse TimeStampResp n'est pas un jeton, EX-9.2)", "contentType other than id-signedData (a TimeStampResp is not a token, EX-9.2)")
	}
	var contenu cryptobyte.String
	if !ci.ReadASN1(&contenu, ctx(0, true)) || !ci.Empty() {
		return nil, t1("content [0] du ContentInfo illisible", "unreadable ContentInfo content [0]")
	}
	var sd cryptobyte.String
	if !contenu.ReadASN1(&sd, casn1.SEQUENCE) || !contenu.Empty() {
		return nil, t1("SignedData illisible", "unreadable SignedData")
	}
	b, ok := lireEntier(&sd, casn1.INTEGER)
	if v, ok2 := petitEntier(b); !ok || !ok2 || v != 3 {
		return nil, t1("version de SignedData différente de 3", "SignedData version other than 3")
	}
	var algos cryptobyte.String
	if !sd.ReadASN1(&algos, casn1.SET) {
		return nil, t1("digestAlgorithms illisible", "unreadable digestAlgorithms")
	}
	for !algos.Empty() {
		if _, ok := lireAlgo(&algos); !ok {
			return nil, t1("digestAlgorithms illisible", "unreadable digestAlgorithms")
		}
	}
	// encapContentInfo
	var eci cryptobyte.String
	if !sd.ReadASN1(&eci, casn1.SEQUENCE) {
		return nil, t1("encapContentInfo illisible", "unreadable encapContentInfo")
	}
	if o, ok := lireOID(&eci); !ok || !o.Equal(oidTSTInfo) {
		return nil, t1("eContentType autre que id-ct-TSTInfo", "eContentType other than id-ct-TSTInfo")
	}
	var ec, oct cryptobyte.String
	if !eci.ReadASN1(&ec, ctx(0, true)) || !eci.Empty() {
		return nil, t1("eContent absent ou illisible", "eContent missing or unreadable")
	}
	if !ec.ReadASN1(&oct, casn1.OCTET_STRING) || !ec.Empty() {
		return nil, t1("eContent n'est pas une OCTET STRING primitive", "eContent is not a primitive OCTET STRING")
	}
	j.eContent = []byte(oct)
	// certificates [0] IMPLICIT CertificateSet
	if sd.PeekASN1Tag(ctx(0, true)) {
		var certs cryptobyte.String
		sd.ReadASN1(&certs, ctx(0, true))
		for !certs.Empty() {
			var c cryptobyte.String
			if !certs.ReadASN1Element(&c, casn1.SEQUENCE) {
				return nil, t1("certificates contient autre chose qu'un Certificate X.509", "certificates holds something other than an X.509 Certificate")
			}
			if len(j.certificats) == maxCertificats {
				return nil, t1("plus de 16 certificats dans certificates (§15.1)", "more than 16 certificates in certificates (§15.1)")
			}
			cert, d := analyserCertificat([]byte(c))
			if d != nil {
				return nil, prefixer(d, fmt.Sprintf("certificat %d du jeton : ", len(j.certificats)+1), fmt.Sprintf("token certificate %d: ", len(j.certificats)+1))
			}
			j.certificats = append(j.certificats, cert)
		}
	}
	// crls [1] IMPLICIT RevocationInfoChoices
	if sd.PeekASN1Tag(ctx(1, true)) {
		var crls cryptobyte.String
		sd.ReadASN1(&crls, ctx(1, true))
		for !crls.Empty() {
			var e cryptobyte.String
			var tag casn1.Tag
			if !crls.ReadAnyASN1Element(&e, &tag) {
				return nil, t1("crls illisible", "unreadable crls")
			}
			if tag == casn1.SEQUENCE {
				j.crls = append(j.crls, []byte(e))
			}
		}
	}
	var sis cryptobyte.String
	if !sd.ReadASN1(&sis, casn1.SET) || !sd.Empty() {
		return nil, t1("signerInfos illisible, ou éléments en trop dans SignedData", "unreadable signerInfos, or extra elements in SignedData")
	}
	var si cryptobyte.String
	if !sis.ReadASN1(&si, casn1.SEQUENCE) {
		return nil, t1("aucun SignerInfo", "no SignerInfo")
	}
	if !sis.Empty() {
		return nil, t1("plus d'un SignerInfo (EX-9.7)", "more than one SignerInfo (EX-9.7)")
	}
	if d := j.lireSignataire(si); d != nil {
		return nil, d
	}
	if d := j.lireTST(); d != nil {
		return nil, d
	}
	return j, nil
}

func (j *jeton) lireSignataire(si cryptobyte.String) *defaut {
	g := &j.sig
	b, ok := lireEntier(&si, casn1.INTEGER)
	v, ok2 := petitEntier(b)
	if !ok || !ok2 {
		return t1("version de SignerInfo illisible", "unreadable SignerInfo version")
	}
	switch {
	case v == 1 && si.PeekASN1Tag(casn1.SEQUENCE):
		var ias cryptobyte.String
		si.ReadASN1(&ias, casn1.SEQUENCE)
		var d *defaut
		if g.sidEmetteur, _, d = lireNom(&ias); d != nil {
			return prefixer(d, "sid : ", "sid: ")
		}
		if g.sidSerie, ok = lireEntier(&ias, casn1.INTEGER); !ok || !ias.Empty() {
			return t1("issuerAndSerialNumber illisible", "unreadable issuerAndSerialNumber")
		}
	case v == 3 && si.PeekASN1Tag(ctx(0, false)):
		var ski cryptobyte.String
		si.ReadASN1(&ski, ctx(0, false))
		g.sidSKI = []byte(ski)
	default:
		return t1("SignerInfo ni en version 1 avec issuerAndSerialNumber, ni en version 3 avec subjectKeyIdentifier (EX-9.7)", "SignerInfo neither version 1 with issuerAndSerialNumber nor version 3 with subjectKeyIdentifier (EX-9.7)")
	}
	g.version = int(v)
	if g.digest, ok = lireAlgo(&si); !ok {
		return t1("digestAlgorithm illisible", "unreadable digestAlgorithm")
	}
	var attrs cryptobyte.String
	if !si.ReadASN1Element(&attrs, ctx(0, true)) {
		return t1("signedAttrs absent (EX-9.7)", "signedAttrs missing (EX-9.7)")
	}
	g.attrsBruts = []byte(attrs)
	var contenu cryptobyte.String
	attrs.ReadASN1(&contenu, ctx(0, true))
	for !contenu.Empty() {
		var a cryptobyte.String
		if !contenu.ReadASN1(&a, casn1.SEQUENCE) {
			return t1("attribut signé illisible", "unreadable signed attribute")
		}
		o, ok := lireOID(&a)
		var vals cryptobyte.String
		if !ok || !a.ReadASN1(&vals, casn1.SET) || !a.Empty() {
			return t1("attribut signé illisible", "unreadable signed attribute")
		}
		at := attribut{oid: o}
		for !vals.Empty() {
			var e cryptobyte.String
			var tag casn1.Tag
			if !vals.ReadAnyASN1Element(&e, &tag) {
				return t1("valeur d'attribut signé illisible", "unreadable signed attribute value")
			}
			at.valeurs = append(at.valeurs, []byte(e))
		}
		g.attributs = append(g.attributs, at)
	}
	if g.algoSig, ok = lireAlgo(&si); !ok {
		return t1("signatureAlgorithm illisible", "unreadable signatureAlgorithm")
	}
	var sig cryptobyte.String
	if !si.ReadASN1(&sig, casn1.OCTET_STRING) {
		return t1("signature illisible", "unreadable signature")
	}
	g.signature = []byte(sig)
	if si.PeekASN1Tag(ctx(1, true)) {
		si.SkipASN1(ctx(1, true))
	}
	if !si.Empty() {
		return t1("éléments en trop dans SignerInfo", "extra elements in SignerInfo")
	}
	return nil
}

// lireTST lit les octets de valeur de eContent comme un TSTInfo complet,
// sans octet en trop, de version 1 (EX-9.7).
func (j *jeton) lireTST() *defaut {
	if d := verifierProfil(j.eContent, 0); d != nil {
		return prefixer(d, "TSTInfo : ", "TSTInfo: ")
	}
	t := &j.tst
	s := cryptobyte.String(j.eContent)
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, casn1.SEQUENCE) || !s.Empty() {
		return t1("TSTInfo illisible", "unreadable TSTInfo")
	}
	b, ok := lireEntier(&seq, casn1.INTEGER)
	if v, ok2 := petitEntier(b); !ok || !ok2 || v != 1 {
		return t1("version de TSTInfo différente de 1", "TSTInfo version other than 1")
	}
	if t.politique, ok = lireOID(&seq); !ok {
		return t1("policy de TSTInfo illisible", "unreadable TSTInfo policy")
	}
	var mi, imp cryptobyte.String
	if !seq.ReadASN1(&mi, casn1.SEQUENCE) {
		return t1("messageImprint illisible", "unreadable messageImprint")
	}
	if t.algoImprint, ok = lireAlgo(&mi); !ok || !mi.ReadASN1(&imp, casn1.OCTET_STRING) || !mi.Empty() {
		return t1("messageImprint illisible", "unreadable messageImprint")
	}
	t.imprint = []byte(imp)
	if t.serie, ok = lireEntier(&seq, casn1.INTEGER); !ok {
		return t1("serialNumber de TSTInfo illisible", "unreadable TSTInfo serialNumber")
	}
	var gt cryptobyte.String
	if !seq.ReadASN1(&gt, casn1.GeneralizedTime) {
		return t1("genTime n'est pas un GeneralizedTime", "genTime is not a GeneralizedTime")
	}
	t.genTime = []byte(gt)
	if seq.PeekASN1Tag(casn1.SEQUENCE) {
		var acc cryptobyte.String
		seq.ReadASN1(&acc, casn1.SEQUENCE)
		p := &precisionLue{}
		ok := true
		if acc.PeekASN1Tag(casn1.INTEGER) {
			p.s, ok = lireEntier(&acc, casn1.INTEGER)
		}
		if ok && acc.PeekASN1Tag(ctx(0, false)) {
			p.ms, ok = lireEntier(&acc, ctx(0, false))
		}
		if ok && acc.PeekASN1Tag(ctx(1, false)) {
			p.us, ok = lireEntier(&acc, ctx(1, false))
		}
		if !ok || !acc.Empty() {
			return t1("accuracy illisible", "unreadable accuracy")
		}
		t.precision = p
	}
	if seq.PeekASN1Tag(casn1.BOOLEAN) {
		var ordre bool
		if !seq.ReadASN1Boolean(&ordre) {
			return t1("ordering illisible", "unreadable ordering")
		}
		if !ordre {
			return t1("ordering encodé à FALSE, valeur DEFAULT (EX-9.21)", "ordering encoded as FALSE, a DEFAULT value (EX-9.21)")
		}
	}
	if seq.PeekASN1Tag(casn1.INTEGER) {
		if _, ok := lireEntier(&seq, casn1.INTEGER); !ok {
			return t1("nonce illisible", "unreadable nonce")
		}
	}
	if seq.PeekASN1Tag(ctx(0, true)) {
		var tsa cryptobyte.String
		seq.ReadASN1(&tsa, ctx(0, true))
		t.tsaPresent = true
		var gn cryptobyte.String
		var tag casn1.Tag
		if !tsa.ReadAnyASN1(&gn, &tag) || !tsa.Empty() {
			return t1("tsa illisible", "unreadable tsa")
		}
		if tag == ctx(4, true) {
			var d *defaut
			if t.tsaNom, _, d = lireNom(&gn); d != nil {
				return prefixer(d, "tsa : ", "tsa: ")
			}
			if !gn.Empty() {
				return t1("directoryName de tsa illisible", "unreadable tsa directoryName")
			}
		}
	}
	if seq.PeekASN1Tag(ctx(1, true)) {
		var ex cryptobyte.String
		seq.ReadASN1(&ex, ctx(1, true))
		if t.extensions, ok = lireListeExtensions(ex); !ok {
			return t1("extensions de TSTInfo illisibles", "unreadable TSTInfo extensions")
		}
	}
	if !seq.Empty() {
		return t1("éléments en trop ou hors d'ordre dans TSTInfo", "extra or out-of-order elements in TSTInfo")
	}
	return nil
}

// attributsDe rend les attributs signés d'un type, dans l'ordre.
func (g *signataire) attributsDe(o asn1.ObjectIdentifier) []attribut {
	var out []attribut
	for _, a := range g.attributs {
		if a.oid.Equal(o) {
			out = append(out, a)
		}
	}
	return out
}
