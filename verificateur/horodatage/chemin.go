package horodatage

// T-7 (chemin de certification jusqu'à une autorité de l'ancre, à genTime,
// EX-9.13) et T-10 (révocation, EX-9.16). La validation de chemin est faite
// ici, jamais par x509.Certificate.Verify (EX-3.3, EX-14.4).

import (
	"bytes"
	"fmt"

	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/cryptographie"
)

// maxIntermediaires : n ≤ 4, soit un chemin de 5 certificats au plus, ancre
// non comprise (EX-9.13, §15.1).
const maxIntermediaires = 4

// valide applique les règles 4, 5 et 6 d'EX-9.13 au certificat de rang i
// du chemin (i = 0 pour S).
func (v *verif) valide(c *certificat, i int) bool {
	if v.gen.comparer(c.debut) < 0 || v.gen.comparer(c.fin) > 0 {
		return false
	}
	if c.critiqueInconnue() != "" {
		return false
	}
	if i >= 1 {
		bc := c.bc
		if bc == nil || !bc.critique || !bc.ca {
			return false
		}
		if bc.longueur >= 0 && bc.longueur < int64(i-1) {
			return false
		}
		if c.ku != nil && !c.ku.a(5) {
			return false
		}
	}
	return true
}

// signatureAdmise : signature d'un certificat ou d'une CRL, par un
// algorithme admis par T-5, vérifiée sous la clé publique spki (règle 3 de
// T-7, règle 1 de T-10).
func signatureAdmise(a algo, spki, message, sig []byte) bool {
	s, adm, _ := analyserSignature(a, 0)
	if adm != admis {
		return false
	}
	c, admC, _ := lireCle(spki)
	if admC != admis {
		return false
	}
	return c.verifier(s, message, sig)
}

// signePar : l'émetteur de enfant égale octet pour octet le sujet de
// parent, et la signature de enfant se vérifie sous la clé de parent
// (règles 1 à 3 d'EX-9.13). Résultat gardé en cache.
func (v *verif) signePar(enfant, parent *certificat) bool {
	if !bytes.Equal(enfant.emetteur, parent.sujet) {
		return false
	}
	k := [2]*certificat{enfant, parent}
	if r, ok := v.cacheSig[k]; ok {
		return r
	}
	r := signatureAdmise(enfant.algoSig, parent.spki, enfant.tbs, enfant.signature)
	v.cacheSig[k] = r
	return r
}

func contientPolitique(l []string, p string) bool {
	for _, x := range l {
		if x == p {
			return true
		}
	}
	return false
}

func (v *verif) t7() {
	if !v.prerequis(7, 4, 6, 9) {
		return
	}
	if v.e.Ancres == nil || len(v.e.Ancres.Autorites) == 0 {
		v.poser(7, commun.NonExecute, commun.AncreAbsente, "aucune autorité d'horodatage dans le fichier d'ancres, ou pas de fichier d'ancres", "no time-stamping authority in the anchors file, or no anchors file")
		return
	}
	politique := v.j.tst.politique.String()
	for i, a := range v.e.Ancres.Autorites {
		ac := v.autorites[i]
		if ac == nil || (a.PolitiquesAdmises != nil && !contientPolitique(a.PolitiquesAdmises, politique)) {
			continue
		}
		chemin, identite := v.cheminPour(ac)
		if chemin == nil {
			continue
		}
		v.autorite, v.aCert, v.chemin, v.identite = i, ac, chemin, identite
		if identite {
			v.poser(7, commun.Reussi, "", "l'autorité « "+a.Nom+" » ("+a.Pointeur+") désigne le certificat signataire lui-même, valide à genTime",
				"authority “"+a.Nom+"” ("+a.Pointeur+") designates the signer certificate itself, valid at genTime")
			return
		}
		v.poser(7, commun.Reussi, "", fmt.Sprintf("chemin de %d certificat(s) valide à genTime jusqu'à l'autorité « %s » (%s)", len(chemin), a.Nom, a.Pointeur),
			fmt.Sprintf("path of %d certificate(s) valid at genTime up to authority “%s” (%s)", len(chemin), a.Nom, a.Pointeur))
		return
	}
	v.poser(7, commun.Echoue, "", "aucun chemin de certification valide à genTime "+v.gen.texte()+" jusqu'à une autorité du fichier d'ancres (règles 1 à 7 d'EX-9.13)",
		"no certification path valid at genTime "+v.gen.texte()+" up to an authority of the anchors file (rules 1 to 7 of EX-9.13)")
}

// cheminPour cherche le chemin retenu pour une autorité : le plus court,
// n = 0 d'abord (l'identité avant la signature de S par l'autorité), puis,
// à longueur égale, le premier dans l'ordre des candidats comparés de c₁ à
// cₙ. Les niveaux sont calculés en largeur, sans énumérer les chemins.
func (v *verif) cheminPour(ac *certificat) ([]*certificat, bool) {
	s := v.s
	if !v.valide(s, 0) {
		return nil, false
	}
	if bytes.Equal(s.der, ac.der) {
		return []*certificat{s}, true
	}
	if v.signePar(s, ac) {
		return []*certificat{s}, false
	}
	niveaux := [][]*certificat{{s}}
	for n := 1; n <= maxIntermediaires; n++ {
		var courant []*certificat
		for _, c := range v.cands {
			if !v.valide(c, n) {
				continue
			}
			for _, p := range niveaux[n-1] {
				if v.signePar(p, c) {
					courant = append(courant, c)
					break
				}
			}
		}
		if len(courant) == 0 {
			return nil, false
		}
		niveaux = append(niveaux, courant)
		var bons []*certificat
		for _, c := range courant {
			if v.signePar(c, ac) {
				bons = append(bons, c)
			}
		}
		if len(bons) == 0 {
			continue
		}
		// Ensembles des certificats de chaque niveau qui mènent à
		// l'autorité en exactement n − i pas.
		mene := make([][]*certificat, n+1)
		mene[n] = bons
		for i := n - 1; i >= 1; i-- {
			for _, c := range niveaux[i] {
				for _, b := range mene[i+1] {
					if v.signePar(c, b) {
						mene[i] = append(mene[i], c)
						break
					}
				}
			}
		}
		chemin := []*certificat{s}
		for i := 1; i <= n; i++ {
			prec := chemin[i-1]
			for _, c := range mene[i] {
				if v.signePar(prec, c) {
					chemin = append(chemin, c)
					break
				}
			}
		}
		return chemin, false
	}
	return nil, false
}

// crlConsultee : une CRL du fichier d'ancres ou du jeton.
type crlConsultee struct {
	l *crl
	// ancre : index dans revocation.crls, ou -1 pour une CRL du jeton.
	ancre int
	// jeton : rang dans le champ crls du jeton (à partir de 1).
	jeton int
}

func (c crlConsultee) nom() (string, string) {
	if c.ancre >= 0 {
		p := fmt.Sprintf("/revocation/crls/%d", c.ancre)
		return "CRL " + p + " du fichier d'ancres", "CRL " + p + " of the anchors file"
	}
	return fmt.Sprintf("CRL %d du champ crls du jeton", c.jeton), fmt.Sprintf("CRL %d of the token crls field", c.jeton)
}

// toleree : révocation qui laisse le jeton valide (EX-9.16) : raison
// unspecified, affiliationChanged, superseded ou cessationOfOperation, et
// date strictement postérieure à genTime.
func (v *verif) toleree(e *entreeCRL) bool {
	switch e.raison {
	case 0, 3, 4, 5:
		return v.gen.comparer(e.date) < 0
	}
	return false
}

func (v *verif) t10() {
	if !v.prerequis(10, 7) {
		return
	}
	var crls []crlConsultee
	for i, c := range v.e.Ancres.CRLs {
		if l, d := lireCRL(c.DER); d == nil {
			crls = append(crls, crlConsultee{l: l, ancre: i})
		}
	}
	for k, b := range v.j.crls {
		l, d := lireCRL(b)
		if d != nil {
			fr, en := crlConsultee{ancre: -1, jeton: k + 1}.nom()
			v.avertir("AV-T-3", "T-10", fr+" illisible, écartée ("+d.fr+")", en+" unreadable, discarded ("+d.en+")")
			continue
		}
		crls = append(crls, crlConsultee{l: l, ancre: -1, jeton: k + 1})
	}
	chemin := v.chemin
	if v.identite {
		chemin = nil
	}
	cle := func(i int) []byte {
		if i+1 < len(chemin) {
			return chemin[i+1].spki
		}
		return v.aCert.spki
	}
	preuves := make([]*Revocation, len(chemin))
	var echecsFr, echecsEn []string
	revoque := func(c *certificat, quoi, what string) {
		echecsFr = append(echecsFr, quoi+" "+cryptographie.Hex32(c.sha256)+" révoqué")
		echecsEn = append(echecsEn, what+" "+cryptographie.Hex32(c.sha256)+" revoked")
	}
	for _, cc := range crls {
		l := cc.l
		concerne, retenue := false, false
		motifFr, motifEn := "", ""
		for i, c := range chemin {
			if !bytes.Equal(l.emetteur, c.emetteur) {
				continue
			}
			concerne = true
			switch {
			case !l.complete():
				motifFr, motifEn = "delta ou partielle", "delta or partial"
			case !signatureAdmise(l.algoSig, cle(i), l.tbs, l.signature):
				motifFr, motifEn = "signature invalide ou algorithme non admis", "invalid signature or algorithm not admitted"
			case v.gen.comparer(l.thisUpdate) > 0:
				motifFr, motifEn = "thisUpdate antérieur à genTime", "thisUpdate earlier than genTime"
			default:
				retenue = true
				if preuves[i] == nil {
					preuves[i] = &Revocation{CertificateSha256: cryptographie.Hex32(c.sha256), Evidence: "crl", IssuedAt: commun.FormaterInstant(l.thisUpdate)}
				}
				if e := l.liste(c.serie); e != nil && !v.toleree(e) {
					revoque(c, "certificat du chemin", "path certificate")
				}
			}
		}
		if retenue && cc.ancre >= 0 {
			v.crlsEmployees[cc.ancre] = true
		}
		if concerne && !retenue {
			fr, en := cc.nom()
			v.avertir("AV-T-3", "T-10", fr+" écartée : "+motifFr, en+" discarded: "+motifEn)
		}
	}
	for i, c := range chemin {
		if preuves[i] != nil {
			continue
		}
		for _, d := range v.e.Ancres.Declarations {
			if d.CertificatSha256 == c.sha256 && v.gen.comparer(d.NonRevoqueA) <= 0 {
				preuves[i] = &Revocation{CertificateSha256: cryptographie.Hex32(c.sha256), Evidence: "declaration", IssuedAt: commun.FormaterInstant(d.NonRevoqueA)}
				break
			}
		}
	}
	// Certificat de l'autorité : seules les CRL complètes du fichier
	// d'ancres, sans contrôle de signature (EX-9.16, §12.1).
	for _, cc := range crls {
		l := cc.l
		if cc.ancre < 0 || !l.complete() || !bytes.Equal(l.emetteur, v.aCert.emetteur) {
			continue
		}
		if e := l.liste(v.aCert.serie); e != nil {
			v.crlsEmployees[cc.ancre] = true
			if !v.toleree(e) {
				revoque(v.aCert, "certificat de l'autorité", "authority certificate")
			}
		}
	}
	for _, p := range preuves {
		if p != nil {
			v.revocations = append(v.revocations, *p)
		}
	}
	switch {
	case len(echecsFr) > 0:
		v.poser(10, commun.Echoue, "", joindre(echecsFr)+" (raison non tolérée ou date non postérieure à genTime, EX-9.16)", joindre(echecsEn)+" (reason not tolerated or date not after genTime, EX-9.16)")
	case len(v.revocations) == len(chemin):
		if len(chemin) == 0 {
			v.poser(10, commun.Reussi, "", "unité épinglée par l'ancre : aucun certificat du chemin à prouver non révoqué", "unit pinned by the anchor: no path certificate to prove unrevoked")
			return
		}
		v.poser(10, commun.Reussi, "", fmt.Sprintf("preuve de non-révocation pour %d certificat(s) du chemin", len(chemin)), fmt.Sprintf("non-revocation evidence for %d path certificate(s)", len(chemin)))
	default:
		v.poser(10, commun.NonExecute, commun.AncreAbsente, "aucune CRL retenue ni déclaration pour un certificat du chemin (EX-9.16)", "no retained CRL nor statement for a path certificate (EX-9.16)")
	}
}
