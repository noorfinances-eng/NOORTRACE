package horodatage

// Vérifications T-1 à T-11 (CT-6 §9.5), statut d'EX-9.18 (EX-9.22 pour
// K-7), faits d'EX-9.19, proposition d'EX-9.20 et avertissements AV-T-1 à
// AV-T-4, AV-K-2 et AV-K-4 (§9.7, §9.9).

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"fmt"
	"time"

	"golang.org/x/crypto/cryptobyte"
	casn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/cryptographie"
	"github.com/noorfinances-eng/noortrace/verificateur/entree"
)

// construit : le contrôle 4 est construit (voir Construit).
const construit = true

// seuilAVK4 : écart au-delà duquel AV-K-4 est levé (§9.9, SEUIL_AV_K4_S).
const seuilAVK4 = 3600 * time.Second

// verif : état d'une vérification de jeton.
type verif struct {
	e   Entree
	res [12]commun.Verification // T-1 à T-11, index 1 à 11
	j   *jeton

	// T-4 : candidats (jeton puis ancre, sans doublon) et signataire S.
	autorites []*certificat // certificat de chaque autorité, ou nil
	cands     []*certificat
	s         *certificat
	// T-5
	digest crypto.Hash
	sig    signature
	cleS   *cle
	// T-9
	gen   instant
	prec  *precision
	borne instant // genTime + accuracy (genTime sans accuracy)
	claim bool
	// T-7
	autorite int
	aCert    *certificat
	chemin   []*certificat
	identite bool
	cacheSig map[[2]*certificat]bool
	// T-10, T-11
	revocations    []Revocation
	crlsEmployees  map[int]bool
	qualifie       *Qualifie
	avertissements []commun.Avertissement
}

func verifier(e Entree) Resultat {
	v := &verif{e: e, cacheSig: map[[2]*certificat]bool{}, crlsEmployees: map[int]bool{}}
	v.t1()
	v.t2()
	v.t3()
	v.t4()
	v.t5()
	v.t6()
	v.t8()
	v.t9()
	v.t7()
	v.t10()
	v.t11()
	return v.resultat()
}

// poser fixe le résultat de T-n.
func (v *verif) poser(n int, st commun.Statut, r commun.Raison, fr, en string) {
	v.res[n] = commun.Nouvelle(IDs[n-1], st, r, commun.T(fr, en), 4)
}

func (v *verif) reussie(n int) bool { return v.res[n].Statut == commun.Reussi }

// prerequis applique EX-5.5 : si l'un des prérequis n'a pas réussi, T-n
// est non exécutée, avec prerequis_en_echec pour un échec, sinon la raison
// héritée (la première dans l'ordre d'EX-6.5).
func (v *verif) prerequis(n int, ids ...int) bool {
	var raisons []commun.Raison
	var noms []string
	for _, k := range ids {
		switch v.res[k].Statut {
		case commun.Echoue:
			raisons = append(raisons, commun.PrerequisEnEchec)
			noms = append(noms, IDs[k-1])
		case commun.NonExecute:
			raisons = append(raisons, v.res[k].Raison)
			noms = append(noms, IDs[k-1])
		}
	}
	if len(raisons) == 0 {
		return true
	}
	l := commun.ListeIDs(noms)
	v.poser(n, commun.NonExecute, commun.PremiereRaison(raisons...), "prérequis non réussi : "+l, "prerequisite not passed: "+l)
	return false
}

func (v *verif) avertir(id, verification, fr, en string) {
	v.avertissements = append(v.avertissements, commun.Avertissement{ID: id, Verification: verification, Detail: commun.T(fr, en)})
}

// nomAttendu : « periodHash » ou « checkpoint_hash » selon l'usage.
func (v *verif) nomAttendu() string {
	if v.e.Usage == Point {
		return "checkpoint_hash"
	}
	return "periodHash"
}

// --- T-1 : structure du jeton (EX-9.2, EX-9.3, EX-9.7) ---

func (v *verif) t1() {
	switch v.e.Etat {
	case entree.Absent, entree.Illisible:
		v.poser(1, commun.NonExecute, commun.PrerequisEnEchec, "jeton-rfc3161.der déclaré présent mais absent ou illisible (D-2)", "jeton-rfc3161.der declared present but missing or unreadable (D-2)")
		return
	case entree.TropGrand:
		v.poser(1, commun.Echoue, "", "jeton de plus de 64 Kio, inexploitable (EX-9.3)", "token larger than 64 KiB, unusable (EX-9.3)")
		return
	}
	j, d := lireJeton(v.e.Jeton)
	if d != nil {
		v.poser(1, commun.Echoue, "", "jeton inexploitable : "+d.fr, "unusable token: "+d.en)
		return
	}
	v.j = j
	for _, x := range j.tst.extensions {
		if x.critiqueFauxEncode {
			v.avertir("AV-T-1", "T-1", "critical encodé à FALSE dans l'extension "+x.oid.String()+" de TSTInfo, valeur DEFAULT tolérée (EX-9.5)",
				"critical encoded as FALSE in TSTInfo extension "+x.oid.String()+", tolerated DEFAULT value (EX-9.5)")
		}
	}
	n := len(j.certificats)
	v.poser(1, commun.Reussi, "", fmt.Sprintf("TimeStampToken lu selon le profil DER de §9.3 (%d certificat(s), TSTInfo version 1)", n),
		fmt.Sprintf("TimeStampToken read with the §9.3 DER profile (%d certificate(s), TSTInfo version 1)", n))
}

// --- T-2 : empreinte (EX-9.8) ---

func (v *verif) t2() {
	if !v.prerequis(2, 1) {
		return
	}
	nom := v.nomAttendu()
	if !v.e.EmpreinteDisponible {
		if v.e.Usage == Point {
			v.poser(2, commun.NonExecute, commun.PrerequisEnEchec, "checkpoint_hash non recalculé : K-2 non réussie (EX-9.22)", "checkpoint_hash not recomputed: K-2 not passed (EX-9.22)")
		} else {
			v.poser(2, commun.NonExecute, commun.PrerequisEnEchec, "periodHash non recalculé : P-1 non réussie (EX-5.4)", "periodHash not recomputed: P-1 not passed (EX-5.4)")
		}
		return
	}
	t := v.j.tst
	if !t.algoImprint.oid.Equal(oidSHA256) || !t.algoImprint.paramsNulOuAbsents() {
		v.poser(2, commun.Echoue, "", "messageImprint n'est pas en SHA-256 (paramètres absents ou NULL) : "+t.algoImprint.oid.String(),
			"messageImprint is not SHA-256 (parameters absent or NULL): "+t.algoImprint.oid.String())
		return
	}
	attendu := cryptographie.Hex32(v.e.EmpreinteAttendue)
	if !bytes.Equal(t.imprint, v.e.EmpreinteAttendue[:]) {
		lu := cryptographie.Hex(t.imprint)
		v.poser(2, commun.Echoue, "", "hashedMessage "+lu+" différent de "+nom+" recalculé "+attendu, "hashedMessage "+lu+" differs from recomputed "+nom+" "+attendu)
		return
	}
	v.poser(2, commun.Reussi, "", "hashedMessage égal à "+nom+" recalculé "+attendu, "hashedMessage equals recomputed "+nom+" "+attendu)
}

// --- T-3 : attributs signés (EX-9.9) ---

func (v *verif) t3() {
	if !v.prerequis(3, 1) {
		return
	}
	g := &v.j.sig
	echec := func(fr, en string) { v.poser(3, commun.Echoue, "", fr, en) }
	vus := map[string]bool{}
	for _, a := range g.attributs {
		k := a.oid.String()
		if vus[k] {
			echec("attribut signé "+k+" présent plus d'une fois", "signed attribute "+k+" present more than once")
			return
		}
		vus[k] = true
		if len(a.valeurs) != 1 {
			echec(fmt.Sprintf("attribut signé %s à %d valeurs", k, len(a.valeurs)), fmt.Sprintf("signed attribute %s with %d values", k, len(a.valeurs)))
			return
		}
	}
	ct := g.attributsDe(oidContentType)
	if len(ct) == 0 {
		echec("attribut content-type absent", "content-type attribute missing")
		return
	}
	s := cryptobyte.String(ct[0].valeurs[0])
	if o, ok := lireOID(&s); !ok || !s.Empty() || !o.Equal(oidTSTInfo) {
		echec("content-type ne vaut pas id-ct-TSTInfo", "content-type is not id-ct-TSTInfo")
		return
	}
	md := g.attributsDe(oidMessageDig)
	if len(md) == 0 {
		echec("attribut message-digest absent", "message-digest attribute missing")
		return
	}
	s = cryptobyte.String(md[0].valeurs[0])
	var lu cryptobyte.String
	if !s.ReadASN1(&lu, casn1.OCTET_STRING) || !s.Empty() {
		echec("message-digest illisible", "unreadable message-digest")
		return
	}
	h, ok := empreinteParOID(g.digest.oid)
	if !ok {
		echec("digestAlgorithm "+g.digest.oid.String()+" : empreinte non calculable (EX-9.9)", "digestAlgorithm "+g.digest.oid.String()+": digest not computable (EX-9.9)")
		return
	}
	calc := hacher(h, v.j.eContent)
	if !bytes.Equal(calc, lu) {
		echec("message-digest "+cryptographie.Hex(lu)+" différent de l'empreinte "+nomEmpreinte(h)+" de eContent "+cryptographie.Hex(calc),
			"message-digest "+cryptographie.Hex(lu)+" differs from the "+nomEmpreinte(h)+" digest of eContent "+cryptographie.Hex(calc))
		return
	}
	if len(g.attributsDe(oidSigningCert)) == 0 && len(g.attributsDe(oidSigningCert2)) == 0 {
		echec("ni signingCertificate ni signingCertificateV2", "neither signingCertificate nor signingCertificateV2")
		return
	}
	v.poser(3, commun.Reussi, "", "content-type, message-digest ("+nomEmpreinte(h)+" de eContent) et identifiant du certificat signataire conformes",
		"content-type, message-digest ("+nomEmpreinte(h)+" of eContent) and signer certificate identifier conform")
}

// --- T-4 : certificat signataire (EX-9.10) ---

// chargerCandidats : certificats du jeton, puis certificate et
// intermediates des autorités dans l'ordre du fichier, sans doublon.
func (v *verif) chargerCandidats() {
	vus := map[[32]byte]bool{}
	ajouter := func(c *certificat) {
		if c != nil && !vus[c.sha256] {
			vus[c.sha256] = true
			v.cands = append(v.cands, c)
		}
	}
	for _, c := range v.j.certificats {
		ajouter(c)
	}
	if v.e.Ancres == nil {
		return
	}
	for _, a := range v.e.Ancres.Autorites {
		c, d := lireCertificat(a.Certificat)
		if d != nil {
			c = nil
		}
		v.autorites = append(v.autorites, c)
		ajouter(c)
		for _, i := range a.Intermediaires {
			if ci, d := lireCertificat(i); d == nil {
				ajouter(ci)
			}
		}
	}
}

func (v *verif) designe(c *certificat) bool {
	g := v.j.sig
	if g.version == 1 {
		return bytes.Equal(g.sidEmetteur, c.emetteur) && memeEntier(g.sidSerie, c.serie)
	}
	return c.ski != nil && bytes.Equal(c.ski, g.sidSKI)
}

// unite : nom de l'unité dans un détail (CN, ou SHA-256 du certificat).
func unite(c *certificat) string {
	if c.cn != nil {
		return *c.cn
	}
	return cryptographie.Hex32(c.sha256)
}

func (v *verif) t4() {
	if !v.prerequis(4, 1) {
		return
	}
	v.chargerCandidats()
	var designes []*certificat
	for _, c := range v.cands {
		if v.designe(c) {
			designes = append(designes, c)
		}
	}
	switch {
	case len(designes) == 0 && v.e.Ancres == nil:
		v.poser(4, commun.NonExecute, commun.AncreAbsente, "aucun certificat du jeton n'est désigné par sid, et aucun fichier d'ancres n'est fourni", "no token certificate is designated by sid, and no anchors file is given")
		return
	case len(designes) == 0:
		v.poser(4, commun.NonExecute, commun.AncreAbsente, "le certificat désigné par sid n'est ni dans le jeton ni dans le fichier d'ancres (intermediates)", "the certificate designated by sid is neither in the token nor in the anchors file (intermediates)")
		return
	case len(designes) > 1:
		v.poser(4, commun.Echoue, "", fmt.Sprintf("%d certificats distincts désignés par sid", len(designes)), fmt.Sprintf("%d distinct certificates designated by sid", len(designes)))
		return
	}
	s := designes[0]
	g := &v.j.sig
	if a := g.attributsDe(oidSigningCert); len(a) > 0 {
		_, h, is, d := lireESS(premiereValeur(a[0]), false)
		switch {
		case d != nil:
			v.poser(4, commun.Echoue, "", "signingCertificate : "+d.fr, "signingCertificate: "+d.en)
			return
		case !bytes.Equal(h, hacherSHA1(s.der)):
			v.poser(4, commun.Echoue, "", "certHash du premier ESSCertID différent du SHA-1 du certificat signataire", "certHash of the first ESSCertID differs from the SHA-1 of the signer certificate")
			return
		case is != nil && !issuerSerialEgal(is, s):
			v.poser(4, commun.Echoue, "", "issuerSerial du premier ESSCertID ne désigne pas le certificat signataire", "issuerSerial of the first ESSCertID does not designate the signer certificate")
			return
		}
	}
	if a := g.attributsDe(oidSigningCert2); len(a) > 0 {
		ha, h, is, d := lireESS(premiereValeur(a[0]), true)
		if d != nil {
			v.poser(4, commun.Echoue, "", "signingCertificateV2 : "+d.fr, "signingCertificateV2: "+d.en)
			return
		}
		fn := crypto.SHA256
		if ha != nil {
			if ha.oid.Equal(oidSHA256) {
				v.avertir("AV-T-1", "T-4", "hashAlgorithm encodé à SHA-256 dans le premier ESSCertIDv2, valeur DEFAULT tolérée (EX-9.21)", "hashAlgorithm encoded as SHA-256 in the first ESSCertIDv2, tolerated DEFAULT value (EX-9.21)")
			}
			f, ok := empreinteParOID(ha.oid)
			if !ok || !ha.paramsNulOuAbsents() {
				v.poser(4, commun.Echoue, "", "hashAlgorithm "+ha.oid.String()+" du premier ESSCertIDv2 non calculable", "hashAlgorithm "+ha.oid.String()+" of the first ESSCertIDv2 not computable")
				return
			}
			fn = f
		}
		switch {
		case !bytes.Equal(h, hacher(fn, s.der)):
			v.poser(4, commun.Echoue, "", "certHash du premier ESSCertIDv2 différent de l'empreinte "+nomEmpreinte(fn)+" du certificat signataire", "certHash of the first ESSCertIDv2 differs from the "+nomEmpreinte(fn)+" digest of the signer certificate")
			return
		case is != nil && !issuerSerialEgal(is, s):
			v.poser(4, commun.Echoue, "", "issuerSerial du premier ESSCertIDv2 ne désigne pas le certificat signataire", "issuerSerial of the first ESSCertIDv2 does not designate the signer certificate")
			return
		}
	}
	v.s = s
	sha := cryptographie.Hex32(s.sha256)
	v.poser(4, commun.Reussi, "", "certificat signataire « "+unite(s)+" » ("+sha+") désigné par sid et par l'identifiant signé", "signer certificate “"+unite(s)+"” ("+sha+") designated by sid and by the signed identifier")
}

// premiereValeur : la première valeur d'un attribut, ou nil (T-3 juge le
// nombre de valeurs ; T-4 refuse alors un identifiant illisible).
func premiereValeur(a attribut) []byte {
	if len(a.valeurs) == 0 {
		return nil
	}
	return a.valeurs[0]
}

func hacherSHA1(b []byte) []byte {
	h := sha1.Sum(b)
	return h[:]
}

// lireESS lit SigningCertificate (RFC 2634 §5.4) ou SigningCertificateV2
// (RFC 5035 §3) et rend, pour le premier identifiant, hashAlgorithm (v2,
// nil s'il est absent), certHash et issuerSerial (contenu, ou nil).
func lireESS(val []byte, v2 bool) (*algo, []byte, []byte, *defaut) {
	mal := def("valeur illisible", "unreadable value")
	s := cryptobyte.String(val)
	var sc, certs, id cryptobyte.String
	if !s.ReadASN1(&sc, casn1.SEQUENCE) || !s.Empty() || !sc.ReadASN1(&certs, casn1.SEQUENCE) {
		return nil, nil, nil, mal
	}
	if !sc.Empty() {
		var pol cryptobyte.String
		if !sc.ReadASN1(&pol, casn1.SEQUENCE) || !sc.Empty() {
			return nil, nil, nil, mal
		}
	}
	if !certs.ReadASN1(&id, casn1.SEQUENCE) {
		return nil, nil, nil, def("aucun identifiant de certificat", "no certificate identifier")
	}
	var ha *algo
	if v2 && id.PeekASN1Tag(casn1.SEQUENCE) {
		a, ok := lireAlgo(&id)
		if !ok {
			return nil, nil, nil, mal
		}
		ha = &a
	}
	var h cryptobyte.String
	if !id.ReadASN1(&h, casn1.OCTET_STRING) {
		return nil, nil, nil, mal
	}
	var is []byte
	if !id.Empty() {
		var x cryptobyte.String
		if !id.ReadASN1(&x, casn1.SEQUENCE) || !id.Empty() {
			return nil, nil, nil, mal
		}
		is = []byte(x)
	}
	return ha, []byte(h), is, nil
}

// issuerSerialEgal : issuerSerial porte un directoryName égal octet pour
// octet à l'émetteur de S et le numéro de S (EX-9.10, règle 3).
func issuerSerialEgal(contenu []byte, s *certificat) bool {
	is := cryptobyte.String(contenu)
	var gns cryptobyte.String
	if !is.ReadASN1(&gns, casn1.SEQUENCE) {
		return false
	}
	serie, ok := lireEntier(&is, casn1.INTEGER)
	if !ok || !is.Empty() {
		return false
	}
	trouve := false
	for !gns.Empty() {
		var gn cryptobyte.String
		var tag casn1.Tag
		if !gns.ReadAnyASN1(&gn, &tag) {
			return false
		}
		if tag == ctx(4, true) && bytes.Equal(gn, s.emetteur) {
			trouve = true
		}
	}
	return trouve && memeEntier(serie, s.serie)
}

// --- T-5 : algorithmes (EX-9.11) ---

func (v *verif) t5() {
	if !v.prerequis(5, 4) {
		return
	}
	g := v.j.sig
	var refus, hors []string
	var refusEn, horsEn []string
	noter := func(a admission, d *defaut) {
		switch a {
		case refuse:
			refus, refusEn = append(refus, d.fr), append(refusEn, d.en)
		case horsPerimetre:
			hors, horsEn = append(hors, d.fr), append(horsEn, d.en)
		}
	}
	dh, ok := empreinteParOID(g.digest.oid)
	if !ok || !admise(dh) || !g.digest.paramsNulOuAbsents() {
		noter(refuse, defF("digestAlgorithm %s non admis (SHA-256, SHA-384 ou SHA-512, paramètres absents ou NULL)", "digestAlgorithm %s not admitted (SHA-256, SHA-384 or SHA-512, parameters absent or NULL)", g.digest.oid.String()))
	}
	sig, adm, d := analyserSignature(g.algoSig, dh)
	noter(adm, d)
	c, admC, dC := lireCle(v.s.spki)
	noter(admC, dC)
	if adm == admis && admC == admis && !c.accorde(sig) {
		noter(refuse, def("le type de la clé du certificat signataire ne convient pas à "+sig.nom, "the signer certificate key type does not fit "+sig.nom))
	}
	switch {
	case len(refus) > 0:
		v.poser(5, commun.Echoue, "", joindre(refus), joindre(refusEn))
		return
	case len(hors) > 0:
		v.poser(5, commun.NonExecute, commun.HorsPerimetreVersion, joindre(hors), joindre(horsEn))
		return
	}
	v.digest, v.sig, v.cleS = dh, sig, c
	genre := "RSA"
	if c.ecdsa != nil {
		genre = "ECDSA"
	}
	v.poser(5, commun.Reussi, "", fmt.Sprintf("digestAlgorithm %s, signatureAlgorithm %s, clé %s de %d bits", nomEmpreinte(dh), sig.nom, genre, c.bits),
		fmt.Sprintf("digestAlgorithm %s, signatureAlgorithm %s, %s key of %d bits", nomEmpreinte(dh), sig.nom, genre, c.bits))
}

func joindre(l []string) string {
	s := ""
	for i, x := range l {
		if i > 0 {
			s += " ; "
		}
		s += x
	}
	return s
}

// --- T-6 : signature (EX-9.12) ---

func (v *verif) t6() {
	if !v.prerequis(6, 5) {
		return
	}
	g := v.j.sig
	m := append([]byte{}, g.attrsBruts...)
	m[0] = 0x31
	if !v.cleS.verifier(v.sig, m, g.signature) {
		v.poser(6, commun.Echoue, "", "la signature de SignerInfo ne se vérifie pas sous la clé du certificat signataire", "the SignerInfo signature does not verify under the signer certificate key")
		return
	}
	v.poser(6, commun.Reussi, "", "signature de signedAttrs vérifiée ("+v.sig.nom+")", "signedAttrs signature verified ("+v.sig.nom+")")
}

// --- T-8 : usage horodatage (EX-9.14) ---

func (v *verif) t8() {
	if !v.prerequis(8, 4) {
		return
	}
	s := v.s
	echec := func(fr, en string) { v.poser(8, commun.Echoue, "", fr, en) }
	switch {
	case s.eku == nil:
		echec("extKeyUsage absente du certificat signataire", "extKeyUsage missing from the signer certificate")
		return
	case !s.eku.critique:
		echec("extKeyUsage du certificat signataire non critique", "extKeyUsage of the signer certificate not critical")
		return
	case len(s.eku.oids) != 1 || !s.eku.oids[0].Equal(oidTimeStamping):
		echec("extKeyUsage ne porte pas exactement id-kp-timeStamping", "extKeyUsage does not hold exactly id-kp-timeStamping")
		return
	}
	if s.ku != nil {
		bits := s.ku.positionnes()
		if len(bits) == 0 {
			echec("keyUsage vide", "empty keyUsage")
			return
		}
		for _, b := range bits {
			if b > 1 {
				echec(fmt.Sprintf("keyUsage porte le bit %d, hors de digitalSignature et nonRepudiation", b), fmt.Sprintf("keyUsage holds bit %d, outside digitalSignature and nonRepudiation", b))
				return
			}
		}
	}
	if s.bc != nil && s.bc.ca {
		echec("basicConstraints du certificat signataire avec cA vrai", "signer certificate basicConstraints with cA true")
		return
	}
	v.poser(8, commun.Reussi, "", "extKeyUsage critique réduite à id-kp-timeStamping", "critical extKeyUsage reduced to id-kp-timeStamping")
}

// --- T-9 : contenu de TSTInfo (EX-9.15) ---

func (v *verif) t9() {
	if !v.prerequis(9, 1) {
		return
	}
	t := v.j.tst
	echec := func(fr, en string) { v.poser(9, commun.Echoue, "", fr, en) }
	if t.tsaPresent && t.tsaNom == nil {
		v.avertir("AV-T-2", "T-9", "champ tsa sous une autre forme que directoryName, non comparé (EX-9.15)", "tsa field in a form other than directoryName, not compared (EX-9.15)")
	}
	g, ok := lireGenTime(t.genTime)
	if !ok {
		echec(fmt.Sprintf("genTime %q contraire à la règle 1 d'EX-9.15", string(t.genTime)), fmt.Sprintf("genTime %q contrary to rule 1 of EX-9.15", string(t.genTime)))
		return
	}
	v.gen, v.borne = g, g
	if t.precision != nil {
		p, d := borner(t.precision)
		if d != nil {
			echec(d.fr, d.en)
			return
		}
		b := g.plusMicros(p.micros())
		if b.comparer(limiteGenTime) > 0 {
			echec("genTime + accuracy dépasse 9999-12-31T23:59:59.999999Z", "genTime + accuracy exceeds 9999-12-31T23:59:59.999999Z")
			return
		}
		v.prec, v.borne = &p, b
	}
	for _, x := range t.extensions {
		if x.critique {
			echec("extension critique "+x.oid.String()+" dans TSTInfo (règle 4)", "critical extension "+x.oid.String()+" in TSTInfo (rule 4)")
			return
		}
	}
	for _, x := range t.extensions {
		if !x.oid.Equal(oidQCStatements) {
			continue
		}
		q, ok := lireQCStatements(x.valeur)
		if !ok {
			echec("qcStatements de TSTInfo mal formée (règle 5)", "malformed TSTInfo qcStatements (rule 5)")
			return
		}
		v.claim = v.claim || q
	}
	if v.e.TsDisponible && v.borne.comparer(v.e.TsEvenement) < 0 {
		ts := commun.FormaterInstant(v.e.TsEvenement)
		v.avertir("AV-T-4", "T-9", "ts de l'événement prouvé ("+ts+") postérieur à genTime + accuracy ("+v.borne.texte()+")",
			"ts of the proven event ("+ts+") later than genTime + accuracy ("+v.borne.texte()+")")
	}
	if t.tsaNom != nil {
		switch {
		case v.reussie(4) && !bytes.Equal(t.tsaNom, v.s.sujet):
			echec("tsa différent octet pour octet du sujet du certificat signataire (règle 3)", "tsa differs byte for byte from the signer certificate subject (rule 3)")
			return
		case !v.reussie(4):
			r := v.res[4].Raison
			if v.res[4].Statut == commun.Echoue {
				r = commun.PrerequisEnEchec
			}
			v.poser(9, commun.NonExecute, r, "règles 1, 2, 4 et 5 tenues ; règle 3 non évaluée, T-4 non réussie", "rules 1, 2, 4 and 5 hold; rule 3 not evaluated, T-4 not passed")
			return
		}
	}
	v.poser(9, commun.Reussi, "", "genTime "+g.texte()+", politique "+t.politique.String()+", aucune extension critique", "genTime "+g.texte()+", policy "+t.politique.String()+", no critical extension")
}

// lireQCStatements lit une SEQUENCE OF QCStatement et dit si elle porte
// esi4-qtstStatement-1 (qualified_claim, EX-9.17).
func lireQCStatements(val []byte) (bool, bool) {
	if verifierProfil(val, 0) != nil {
		return false, false
	}
	s := cryptobyte.String(val)
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, casn1.SEQUENCE) || !s.Empty() {
		return false, false
	}
	pretention := false
	for !seq.Empty() {
		var st cryptobyte.String
		if !seq.ReadASN1(&st, casn1.SEQUENCE) {
			return false, false
		}
		o, ok := lireOID(&st)
		if !ok {
			return false, false
		}
		if !st.Empty() {
			var info cryptobyte.String
			var tag casn1.Tag
			if !st.ReadAnyASN1Element(&info, &tag) || !st.Empty() {
				return false, false
			}
		}
		if o.Equal(oidQTST) {
			pretention = true
		}
	}
	return pretention, true
}

// --- T-11 : statut qualifié déclaré (EX-9.17) ---

func (v *verif) t11() {
	if !v.prerequis(11, 7) {
		return
	}
	a := v.e.Ancres.Autorites[v.autorite]
	q := a.Qualification
	if q == nil {
		v.poser(11, commun.NonExecute, commun.AncreAbsente, "l'autorité « "+a.Nom+" » ne porte aucun statut qualifié déclaré", "authority “"+a.Nom+"” carries no declared qualified status")
		return
	}
	if v.gen.comparer(q.Debut) < 0 || (q.Fin != nil && v.gen.comparer(*q.Fin) > 0) {
		v.poser(11, commun.NonExecute, commun.AncreAbsente, "genTime hors de l'intervalle du statut qualifié déclaré pour « "+a.Nom+" »", "genTime outside the interval of the qualified status declared for “"+a.Nom+"”")
		return
	}
	v.qualifie = &Qualifie{Framework: q.Cadre, Source: q.Source}
	v.poser(11, commun.Reussi, "", "statut qualifié "+cadre(q.Cadre)+" déclaré par le réviseur pour « "+a.Nom+" » à genTime", cadre(q.Cadre)+" qualified status declared by the reviewer for “"+a.Nom+"” at genTime")
}

func cadre(f string) string {
	if f == "zertes" {
		return "ZertES"
	}
	return "eIDAS"
}

// --- Synthèse ---

func (v *verif) resultat() Resultat {
	r := Resultat{Verifications: make([]commun.Verification, 0, 11), AncresEmployees: []string{}, Avertissements: []commun.Avertissement{}}
	var raisons []commun.Raison
	echoue := false
	for n := 1; n <= 11; n++ {
		x := v.res[n]
		r.Verifications = append(r.Verifications, x)
		if n == 11 {
			continue
		}
		switch x.Statut {
		case commun.Echoue:
			echoue = true
		case commun.NonExecute:
			raisons = append(raisons, x.Raison)
		}
	}
	switch {
	case echoue:
		r.Statut = commun.Echoue
	case len(raisons) > 0:
		r.Statut, r.Raison = commun.NonExecute, commun.PremiereRaison(raisons...)
	default:
		r.Statut = commun.Reussi
	}
	if v.reussie(7) {
		r.AncresEmployees = append(r.AncresEmployees, v.e.Ancres.Autorites[v.autorite].Pointeur)
		for i, c := range v.e.Ancres.CRLs {
			if v.crlsEmployees[i] {
				r.AncresEmployees = append(r.AncresEmployees, c.Pointeur)
			}
		}
	}
	if r.Statut == commun.Reussi {
		r.Faits = v.faits()
		r.Resume = v.resume(r.Faits)
		if v.e.Usage == Cloture {
			r.Proposition = v.proposition(r.Faits)
		} else {
			v.avertissementsPoint()
		}
	}
	r.Avertissements = append(r.Avertissements, v.avertissements...)
	return r
}

func (v *verif) faits() *Faits {
	a := v.e.Ancres.Autorites[v.autorite]
	f := &Faits{
		Authority:            a.Nom,
		TsuCertificateSha256: cryptographie.Hex32(v.s.sha256),
		TsuSubjectCN:         v.s.cn,
		GenTime:              v.gen.texte(),
		Policy:               v.j.tst.politique.String(),
		SerialNumber:         cryptographie.Hex(v.j.tst.serie),
		DigestAlgorithm:      nomEmpreinte(v.digest),
		SignatureAlgorithm:   v.sig.nom,
		KeyBits:              v.cleS.bits,
		QualifiedClaim:       v.claim,
		Qualified:            v.qualifie,
		Revocation:           append([]Revocation{}, v.revocations...),
		GenTimeInstant:       v.gen.t,
	}
	if p := v.prec; p != nil {
		f.Accuracy = &Precision{Seconds: p.s, Millis: p.ms, Micros: p.us}
		ub := v.borne.texte()
		f.UpperBound = &ub
		t := v.borne.t
		f.UpperBoundInstant = &t
	}
	return f
}

// tsu : nom de l'unité dans l'énoncé (EX-9.20).
func tsu(f *Faits) string {
	if f.TsuSubjectCN != nil {
		return *f.TsuSubjectCN
	}
	return f.TsuCertificateSha256
}

// proposition : EX-9.20, sans « ; » de tête.
func (v *verif) proposition(f *Faits) commun.Texte {
	ph := cryptographie.Hex32(v.e.EmpreinteAttendue)
	fr := fmt.Sprintf("selon %s (unité %s), le manifeste d'empreinte %s existait au plus tard le ", f.Authority, tsu(f), ph)
	en := fmt.Sprintf("according to %s (unit %s), the manifest with digest %s existed no later than ", f.Authority, tsu(f), ph)
	if f.UpperBound != nil {
		fr += *f.UpperBound + " UTC"
		en += *f.UpperBound + " UTC"
	} else {
		fr += f.GenTime + " UTC, à la précision près de la politique " + f.Policy + ", que le jeton n'indique pas"
		en += f.GenTime + " UTC, within the accuracy of policy " + f.Policy + ", not stated in the token"
	}
	if q := f.Qualified; q != nil {
		fr += " ; horodatage qualifié " + cadre(q.Framework) + " selon le réviseur (" + q.Source + ")"
		en += "; " + cadre(q.Framework) + " qualified timestamp according to the reviewer (" + q.Source + ")"
	}
	return commun.T(fr, en)
}

// resume : summary du contrôle 4, et résumé ajouté au détail de K-7.
func (v *verif) resume(f *Faits) commun.Texte {
	borneFr, borneEn := f.GenTime+" (précision non indiquée par le jeton)", f.GenTime+" (accuracy not stated in the token)"
	if f.UpperBound != nil {
		borneFr, borneEn = *f.UpperBound, *f.UpperBound
	}
	fr := fmt.Sprintf("selon %s (unité %s), au plus tard %s", f.Authority, tsu(f), borneFr)
	en := fmt.Sprintf("according to %s (unit %s), no later than %s", f.Authority, tsu(f), borneEn)
	if q := f.Qualified; q != nil {
		fr += " ; horodatage qualifié " + cadre(q.Framework) + " selon le réviseur"
		en += "; " + cadre(q.Framework) + " qualified time-stamp according to the reviewer"
	} else {
		fr += " ; aucun statut qualifié déclaré"
		en += "; no qualified status declared"
	}
	return commun.T(fr, en)
}

// avertissementsPoint : AV-K-2 et AV-K-4 (§9.9), K-7 réussie.
func (v *verif) avertissementsPoint() {
	ck := v.e.CheckpointTs
	cks := commun.FormaterInstant(ck)
	if v.borne.comparer(ck) < 0 {
		v.avertir("AV-K-2", "K-7", "checkpoint_ts ("+cks+") postérieur à genTime + accuracy du jeton du point ("+v.borne.texte()+")",
			"checkpoint_ts ("+cks+") later than genTime + accuracy of the checkpoint token ("+v.borne.texte()+")")
	}
	if v.borne.comparer(ck.Add(seuilAVK4)) > 0 {
		v.avertir("AV-K-4", "K-7", "genTime + accuracy du jeton du point ("+v.borne.texte()+") postérieur de plus de 3600 s à checkpoint_ts ("+cks+")",
			"genTime + accuracy of the checkpoint token ("+v.borne.texte()+") more than 3600 s after checkpoint_ts ("+cks+")")
	}
}
