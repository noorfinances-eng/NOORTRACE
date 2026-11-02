package horodatage

// Chaque vérification T-1 à T-11, AV-T-1 à AV-T-4, AV-K-2 et AV-K-4, en
// réussite et en échec, sur des jetons fabriqués (fabrique_test.go).

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"strings"
	"testing"
	"time"

	casn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/noorfinances-eng/noortrace/verificateur/ancres"
	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/entree"
)

// abrege : « re », « ec », « ne:pe » (prerequis_en_echec), « ne:aa »
// (ancre_absente), « ne:hp » (hors_perimetre_version).
func abrege(r Resultat) string {
	var p []string
	for _, v := range r.Verifications {
		switch v.Statut {
		case commun.Reussi:
			p = append(p, "re")
		case commun.Echoue:
			p = append(p, "ec")
		default:
			p = append(p, "ne:"+map[commun.Raison]string{commun.PrerequisEnEchec: "pe", commun.AncreAbsente: "aa", commun.HorsPerimetreVersion: "hp", commun.PartieAbsente: "pa"}[v.Raison])
		}
	}
	return strings.Join(p, " ")
}

const tousReussis = "re re re re re re re re re re ne:aa"

// cas : une variante du jeton conforme.
type cas struct {
	nom    string
	jeton  func(m *materiel, mj *modeleJeton)
	ancres func(m *materiel, a *ancres.Ancres) *ancres.Ancres
	entree func(e *Entree)
	// attendu : statuts abrégés de T-1 à T-11.
	attendu string
	avert   []string
	verif   func(t *testing.T, r Resultat)
}

func executer(t *testing.T, m *materiel, c cas) Resultat {
	t.Helper()
	mj := m.modeleJeton(t)
	if c.jeton != nil {
		c.jeton(m, mj)
	}
	a := m.ancresTest()
	if c.ancres != nil {
		a = c.ancres(m, a)
	}
	e := m.entree(t, fabriquerJeton(t, mj), a)
	if c.entree != nil {
		c.entree(&e)
	}
	return Verifier(e)
}

func jouer(t *testing.T, liste []cas) {
	m := mat(t)
	for _, c := range liste {
		t.Run(c.nom, func(t *testing.T) {
			r := executer(t, m, c)
			if got := abrege(r); got != c.attendu {
				var d []string
				for _, v := range r.Verifications {
					if v.Statut != commun.Reussi {
						d = append(d, v.ID+" : "+v.Detail.Fr)
					}
				}
				t.Errorf("statuts\n obtenu  %s\n attendu %s\n%s", got, c.attendu, strings.Join(d, "\n"))
			}
			if got := idsAvertissements(r.Avertissements); strings.Join(got, ",") != strings.Join(c.avert, ",") {
				t.Errorf("avertissements %v, attendu %v", got, c.avert)
			}
			invariants(t, r)
			if c.verif != nil {
				c.verif(t, r)
			}
		})
	}
}

// invariants : onze vérifications dans l'ordre, contrôle 4, raisons de la
// liste fermée, détail bilingue, statut d'EX-9.18, faits ssi réussi.
func invariants(t *testing.T, r Resultat) {
	t.Helper()
	if len(r.Verifications) != 11 {
		t.Fatalf("%d vérifications", len(r.Verifications))
	}
	echoue, nonExec := false, false
	for i, v := range r.Verifications {
		if v.ID != IDs[i] || len(v.Controles) != 1 || v.Controles[0] != 4 {
			t.Errorf("vérification %d : %s %v", i, v.ID, v.Controles)
		}
		if v.Detail.Fr == "" || v.Detail.En == "" {
			t.Errorf("%s : détail vide", v.ID)
		}
		switch v.Statut {
		case commun.NonExecute:
			if !v.Raison.Admise() && v.Raison != commun.PrerequisEnEchec {
				t.Errorf("%s : raison %q hors de la liste fermée", v.ID, v.Raison)
			}
			nonExec = nonExec || i < 10
		case commun.Echoue:
			echoue = echoue || i < 10
			if v.Raison != "" {
				t.Errorf("%s : raison sur un échec", v.ID)
			}
		}
	}
	switch {
	case echoue && r.Statut != commun.Echoue, !echoue && nonExec && r.Statut != commun.NonExecute, !echoue && !nonExec && r.Statut != commun.Reussi:
		t.Errorf("statut %s incohérent", r.Statut)
	}
	if (r.Faits != nil) != (r.Statut == commun.Reussi) {
		t.Errorf("faits %v pour le statut %s", r.Faits != nil, r.Statut)
	}
	if r.Faits != nil {
		if (r.Faits.Qualified != nil) != (r.Verifications[10].Statut == commun.Reussi) || r.Faits.Revocation == nil {
			t.Errorf("faits incohérents")
		}
	}
	if r.AncresEmployees == nil || r.Avertissements == nil {
		t.Errorf("tranche nulle")
	}
	for _, a := range r.Avertissements {
		if a.Detail.Fr == "" || a.Detail.En == "" || a.Verification == "" {
			t.Errorf("avertissement %s incomplet", a.ID)
		}
	}
}

func attrsSans(o asn1.ObjectIdentifier) func(a []attrTest, tst []byte) []attrTest {
	return func(a []attrTest, _ []byte) []attrTest {
		var out []attrTest
		for _, x := range a {
			if !x.oid.Equal(o) {
				out = append(out, x)
			}
		}
		return out
	}
}

func remplacerAttr(o asn1.ObjectIdentifier, valeurs ...[]byte) func(a []attrTest, tst []byte) []attrTest {
	return func(a []attrTest, _ []byte) []attrTest {
		for i := range a {
			if a[i].oid.Equal(o) {
				a[i].valeurs = valeurs
			}
		}
		return a
	}
}

func TestT1Structure(t *testing.T) {
	cascade := "ec ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe"
	jouer(t, []cas{
		{nom: "jeton conforme", attendu: tousReussis, verif: func(t *testing.T, r Resultat) {
			if r.Statut != commun.Reussi || r.Faits == nil {
				t.Fatalf("statut %s", r.Statut)
			}
		}},
		{nom: "octet après le ContentInfo", entree: func(e *Entree) { e.Jeton = append(e.Jeton, 0) }, attendu: cascade},
		{nom: "plus de 64 Kio", entree: func(e *Entree) { e.Etat = entree.TropGrand }, attendu: cascade},
		{nom: "partie absente", entree: func(e *Entree) { e.Etat = entree.Absent; e.Jeton = nil },
			attendu: "ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe"},
		{nom: "partie illisible", entree: func(e *Entree) { e.Etat = entree.Illisible; e.Jeton = nil },
			attendu: "ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe"},
		{nom: "jeton vide", entree: func(e *Entree) { e.Jeton = []byte{} }, attendu: cascade},
		{nom: "SignedData version 1", jeton: func(m *materiel, mj *modeleJeton) { mj.versionSD = 1 }, attendu: cascade},
		{nom: "TSTInfo version 2", jeton: func(m *materiel, mj *modeleJeton) { mj.versionTST = 2 }, attendu: cascade},
		{nom: "deux SignerInfo", jeton: func(m *materiel, mj *modeleJeton) { mj.doublerSI = true }, attendu: cascade},
		{nom: "eContent construite", jeton: func(m *materiel, mj *modeleJeton) { mj.eContentConstruit = true }, attendu: cascade},
		{nom: "ordering encodé à FALSE", jeton: func(m *materiel, mj *modeleJeton) { mj.ordering = boolDER(false) }, attendu: cascade},
		{nom: "ordering à TRUE", jeton: func(m *materiel, mj *modeleJeton) { mj.ordering = boolDER(true) }, attendu: tousReussis},
		{nom: "dix-sept certificats", jeton: func(m *materiel, mj *modeleJeton) {
			for len(mj.certs) < 17 {
				mj.certs = append(mj.certs, m.certTSA)
			}
		}, attendu: cascade},
		{nom: "seize certificats", jeton: func(m *materiel, mj *modeleJeton) {
			for len(mj.certs) < 16 {
				mj.certs = append(mj.certs, m.certTSA)
			}
		}, attendu: tousReussis},
		{nom: "TimeStampResp au lieu d'un jeton", entree: func(e *Entree) {
			e.Jeton = seq(seq(entierDER(0)), e.Jeton)
		}, attendu: cascade},
		{nom: "TSTInfo suivi d'un octet", jeton: func(m *materiel, mj *modeleJeton) {
			mj.tstBrut = func(b []byte) []byte { return append(b, 0) }
		}, attendu: cascade},
		{nom: "extension de TSTInfo à critical FALSE (AV-T-1)", jeton: func(m *materiel, mj *modeleJeton) {
			mj.extsTST = []extTest{{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 3}, 2, []byte{5, 0}}}
		}, attendu: tousReussis, avert: []string{"AV-T-1"}},
		{nom: "BMPString impaire dans tsa", jeton: func(m *materiel, mj *modeleJeton) {
			mj.tsa = elem(ctx(4, true), nomDER(attrNom{oidCommonName, tagBMPString, []byte{0, 'A', 0}}))
		}, attendu: cascade},
		{nom: "UTF8String invalide dans sid", jeton: func(m *materiel, mj *modeleJeton) {
			mj.sidEmetteur = nomDER(attrNom{oidCommonName, casn1.UTF8String, []byte{0xff, 0xfe}})
		}, attendu: cascade},
		{nom: "certificat du jeton en version v1 encodée", jeton: func(m *materiel, mj *modeleJeton) {
			c := m.modeleTSA()
			c.version = elem(ctx(0, true), entierDER(0))
			mj.certs = [][]byte{fabriquerCert(t, c)}
		}, attendu: cascade},
		{nom: "certificat du jeton à cA encodé FALSE", jeton: func(m *materiel, mj *modeleJeton) {
			c := m.modeleTSA()
			c.exts = append(c.exts, extBC(1, boolDER(false)))
			mj.certs = [][]byte{fabriquerCert(t, c)}
		}, attendu: cascade},
		{nom: "certificat du jeton à extension critical FALSE", jeton: func(m *materiel, mj *modeleJeton) {
			c := m.modeleTSA()
			c.exts[2].critique = 2
			mj.certs = [][]byte{fabriquerCert(t, c)}
		}, attendu: cascade},
		{nom: "certificat du jeton à CN UniversalString (lisible)", jeton: func(m *materiel, mj *modeleJeton) {
			c := m.modeleTSA()
			c.sujet = nomDER(attrNom{oidCommonName, casn1.Tag(28), []byte{0, 0, 0, 'X'}})
			mj.certs = [][]byte{fabriquerCert(t, c)}
			mj.certESS = mj.certs[0]
			mj.tsa = elem(ctx(4, true), c.sujet)
		}, attendu: tousReussis, verif: func(t *testing.T, r Resultat) {
			if r.Faits == nil || r.Faits.TsuSubjectCN != nil {
				t.Errorf("tsu_subject_cn devrait être null")
			}
			if !strings.Contains(r.Proposition.Fr, "(unité "+r.Faits.TsuCertificateSha256+")") {
				t.Errorf("proposition : %s", r.Proposition.Fr)
			}
		}},
	})
}

func TestT2Empreinte(t *testing.T) {
	jouer(t, []cas{
		{nom: "autre empreinte", jeton: func(m *materiel, mj *modeleJeton) { mj.empreinte = make([]byte, 32) },
			attendu: "re ec re re re re re re re re ne:aa"},
		{nom: "messageImprint en SHA-384", jeton: func(m *materiel, mj *modeleJeton) {
			mj.algoImprint = algoDER(oidSHA384, true)
		}, attendu: "re ec re re re re re re re re ne:aa"},
		{nom: "paramètres de messageImprint ni NULL ni absents", jeton: func(m *materiel, mj *modeleJeton) {
			mj.algoImprint = seq(oidDER(oidSHA256), entierDER(0))
		}, attendu: "re ec re re re re re re re re ne:aa"},
		{nom: "messageImprint sans paramètres", jeton: func(m *materiel, mj *modeleJeton) {
			mj.algoImprint = algoDER(oidSHA256, false)
		}, attendu: tousReussis},
		{nom: "periodHash indisponible (P-1)", entree: func(e *Entree) { e.EmpreinteDisponible = false },
			attendu: "re ne:pe re re re re re re re re ne:aa", verif: func(t *testing.T, r Resultat) {
				if r.Statut != commun.NonExecute || r.Raison != commun.PrerequisEnEchec || !strings.Contains(r.Verifications[1].Detail.Fr, "P-1") {
					t.Errorf("statut %s/%s : %s", r.Statut, r.Raison, r.Verifications[1].Detail.Fr)
				}
			}},
		{nom: "checkpoint_hash indisponible (K-2)", entree: func(e *Entree) { e.Usage = Point; e.EmpreinteDisponible = false },
			attendu: "re ne:pe re re re re re re re re ne:aa", verif: func(t *testing.T, r Resultat) {
				if !strings.Contains(r.Verifications[1].Detail.Fr, "K-2") {
					t.Errorf("détail : %s", r.Verifications[1].Detail.Fr)
				}
			}},
	})
}

func TestT3AttributsSignes(t *testing.T) {
	jouer(t, []cas{
		{nom: "content-type absent", jeton: func(m *materiel, mj *modeleJeton) { mj.attrs = attrsSans(oidContentType) },
			attendu: "re re ec re re re re re re re ne:aa"},
		{nom: "content-type autre", jeton: func(m *materiel, mj *modeleJeton) {
			mj.attrs = remplacerAttr(oidContentType, oidDER(oidSignedData))
		}, attendu: "re re ec re re re re re re re ne:aa"},
		{nom: "message-digest absent", jeton: func(m *materiel, mj *modeleJeton) { mj.attrs = attrsSans(oidMessageDig) },
			attendu: "re re ec re re re re re re re ne:aa"},
		{nom: "message-digest faux", jeton: func(m *materiel, mj *modeleJeton) {
			mj.attrs = remplacerAttr(oidMessageDig, oct(make([]byte, 32)))
		}, attendu: "re re ec re re re re re re re ne:aa"},
		{nom: "attribut en double", jeton: func(m *materiel, mj *modeleJeton) {
			mj.attrs = func(a []attrTest, _ []byte) []attrTest { return append(a, a[0]) }
		}, attendu: "re re ec re re re re re re re ne:aa"},
		{nom: "attribut à deux valeurs", jeton: func(m *materiel, mj *modeleJeton) {
			mj.attrs = func(a []attrTest, _ []byte) []attrTest {
				a[0].valeurs = append(a[0].valeurs, a[0].valeurs[0])
				return a
			}
		}, attendu: "re re ec re re re re re re re ne:aa"},
		{nom: "ni signingCertificate ni V2", jeton: func(m *materiel, mj *modeleJeton) { mj.attrs = attrsSans(oidSigningCert2) },
			attendu: "re re ec re re re re re re re ne:aa"},
		{nom: "digestAlgorithm inconnu", jeton: func(m *materiel, mj *modeleJeton) {
			mj.digest = algoDER(asn1.ObjectIdentifier{1, 2, 3, 4}, false)
		}, attendu: "re re ec re ec ne:pe ne:pe re re ne:pe ne:pe"},
		{nom: "message-digest en MD5 (T-3 calcule, T-5 refuse)", jeton: func(m *materiel, mj *modeleJeton) {
			mj.digest = algoDER(oidMD5, true)
			mj.digestHash = crypto.MD5
		}, attendu: "re re re re ec ne:pe ne:pe re re ne:pe ne:pe"},
		{nom: "tout en SHA-512", jeton: func(m *materiel, mj *modeleJeton) {
			mj.digest = algoDER(oidSHA512, false)
			mj.digestHash = crypto.SHA512
			mj.sign.hash = crypto.SHA512
			mj.sign.algo = algoDER(oidSHA512RSA, true)
		}, attendu: tousReussis, verif: func(t *testing.T, r Resultat) {
			if r.Faits.DigestAlgorithm != "sha512" || r.Faits.SignatureAlgorithm != "sha512WithRSAEncryption" {
				t.Errorf("faits : %s %s", r.Faits.DigestAlgorithm, r.Faits.SignatureAlgorithm)
			}
		}},
	})
}

func essV1(cert []byte) []byte {
	h := sha1.Sum(cert)
	return seq(seq(seq(oct(h[:]))))
}

func TestT4CertificatSignataire(t *testing.T) {
	jouer(t, []cas{
		{nom: "sid subjectKeyIdentifier", jeton: func(m *materiel, mj *modeleJeton) { mj.sidSKI = m.tsa.ski }, attendu: tousReussis},
		{nom: "sid inconnu, sans ancres", jeton: func(m *materiel, mj *modeleJeton) { mj.sidSKI = []byte{9, 9} },
			ancres:  func(*materiel, *ancres.Ancres) *ancres.Ancres { return nil },
			attendu: "re re re ne:aa ne:aa ne:aa ne:aa ne:aa ne:aa ne:aa ne:aa", verif: func(t *testing.T, r Resultat) {
				if r.Statut != commun.NonExecute || r.Raison != commun.AncreAbsente {
					t.Errorf("statut %s/%s", r.Statut, r.Raison)
				}
			}},
		{nom: "certificat dans intermediates de l'ancre seulement", jeton: func(m *materiel, mj *modeleJeton) { mj.certs = nil },
			ancres: func(m *materiel, a *ancres.Ancres) *ancres.Ancres {
				a.Autorites[0].Intermediaires = [][]byte{m.certTSA}
				return a
			}, attendu: tousReussis},
		{nom: "certificat ni dans le jeton ni dans l'ancre", jeton: func(m *materiel, mj *modeleJeton) { mj.certs = nil },
			attendu: "re re re ne:aa ne:aa ne:aa ne:aa ne:aa ne:aa ne:aa ne:aa"},
		{nom: "deux certificats distincts désignés", jeton: func(m *materiel, mj *modeleJeton) {
			c := m.modeleTSA()
			c.fin = c.fin.AddDate(0, 0, 1)
			mj.certs = append(mj.certs, fabriquerCert(t, c))
		}, attendu: "re re re ec ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe"},
		{nom: "le même certificat deux fois", jeton: func(m *materiel, mj *modeleJeton) { mj.certs = append(mj.certs, m.certTSA) },
			attendu: tousReussis},
		{nom: "signingCertificate (ESS v1) juste", jeton: func(m *materiel, mj *modeleJeton) {
			mj.attrs = func(a []attrTest, _ []byte) []attrTest {
				return []attrTest{a[0], a[1], {oidSigningCert, [][]byte{essV1(m.certTSA)}}}
			}
		}, attendu: tousReussis},
		{nom: "signingCertificate (ESS v1) faux", jeton: func(m *materiel, mj *modeleJeton) {
			mj.attrs = func(a []attrTest, _ []byte) []attrTest {
				return append(a, attrTest{oidSigningCert, [][]byte{essV1(m.certAC)}})
			}
		}, attendu: "re re re ec ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe"},
		{nom: "ESSCertIDv2 à hashAlgorithm SHA-256 encodé (AV-T-1)", jeton: func(m *materiel, mj *modeleJeton) {
			h := sha256.Sum256(m.certTSA)
			mj.attrs = remplacerAttr(oidSigningCert2, seq(seq(seq(algoDER(oidSHA256, false), oct(h[:])))))
		}, attendu: tousReussis, avert: []string{"AV-T-1"}},
		{nom: "ESSCertIDv2 en SHA-512", jeton: func(m *materiel, mj *modeleJeton) {
			h := sha512.Sum512(m.certTSA)
			mj.attrs = remplacerAttr(oidSigningCert2, seq(seq(seq(algoDER(oidSHA512, false), oct(h[:])))))
		}, attendu: tousReussis},
		{nom: "ESSCertIDv2 d'une fonction inconnue", jeton: func(m *materiel, mj *modeleJeton) {
			mj.attrs = remplacerAttr(oidSigningCert2, seq(seq(seq(algoDER(asn1.ObjectIdentifier{1, 2, 3}, false), oct([]byte{1})))))
		}, attendu: "re re re ec ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe"},
		{nom: "issuerSerial d'un autre numéro", jeton: func(m *materiel, mj *modeleJeton) {
			mj.attrs = remplacerAttr(oidSigningCert2, essV2(m.certTSA, m.ac.sujet, 3))
		}, attendu: "re re re ec ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe"},
		{nom: "issuerSerial d'un autre émetteur", jeton: func(m *materiel, mj *modeleJeton) {
			mj.attrs = remplacerAttr(oidSigningCert2, essV2(m.certTSA, m.tsa.sujet, 2))
		}, attendu: "re re re ec ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe"},
		{nom: "signingCertificateV2 illisible", jeton: func(m *materiel, mj *modeleJeton) {
			mj.attrs = remplacerAttr(oidSigningCert2, oct([]byte{1}))
		}, attendu: "re re re ec ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe"},
	})
}

// unite fabrique une unité de clé pub, signée par l'AC de test.
func (m *materiel) unite(t *testing.T, pub crypto.PublicKey, f func(c *modeleCert)) []byte {
	c := m.modeleTSA()
	c.pub = pub
	if f != nil {
		f(&c)
	}
	return fabriquerCert(t, c)
}

func TestT5Algorithmes(t *testing.T) {
	m := mat(t)
	petite, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p224, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	avecCle := func(cle crypto.Signer, algo []byte) func(m *materiel, mj *modeleJeton) {
		return func(m *materiel, mj *modeleJeton) {
			c := m.unite(t, cle.Public(), nil)
			mj.certs, mj.certESS = [][]byte{c}, c
			mj.sign = signeur{cle: cle, algo: algo, hash: crypto.SHA256}
		}
	}
	pss := seq(oidDER(oidPSS), seq(elem(ctx(0, true), algoDER(oidSHA256, true)), elem(ctx(1, true), seq(oidDER(oidMGF1), algoDER(oidSHA256, true))), elem(ctx(2, true), entierDER(32))))
	pssMGF1 := seq(oidDER(oidPSS), seq(elem(ctx(0, true), algoDER(oidSHA256, true)), elem(ctx(2, true), entierDER(32))))
	jouer(t, []cas{
		{nom: "rsaEncryption", jeton: func(m *materiel, mj *modeleJeton) { mj.sigAlgo = algoDER(oidRSA, true) }, attendu: tousReussis,
			verif: func(t *testing.T, r Resultat) {
				if r.Faits.SignatureAlgorithm != "rsaEncryption" || r.Faits.KeyBits != 3072 {
					t.Errorf("faits : %s %d", r.Faits.SignatureAlgorithm, r.Faits.KeyBits)
				}
			}},
		{nom: "sha384WithRSAEncryption avec digestAlgorithm SHA-256", jeton: func(m *materiel, mj *modeleJeton) {
			mj.sigAlgo = algoDER(oidSHA384RSA, true)
		}, attendu: "re re re re ec ne:pe ne:pe re re ne:pe ne:pe"},
		{nom: "sha1WithRSAEncryption", jeton: func(m *materiel, mj *modeleJeton) { mj.sigAlgo = algoDER(oidSHA1RSA, true) },
			attendu: "re re re re ec ne:pe ne:pe re re ne:pe ne:pe"},
		{nom: "RSASSA-PSS", jeton: func(m *materiel, mj *modeleJeton) {
			mj.sign.pss = true
			mj.sign.algo = pss
		}, attendu: tousReussis, verif: func(t *testing.T, r Resultat) {
			if r.Faits.SignatureAlgorithm != "id-RSASSA-PSS" {
				t.Errorf("signature_algorithm %s", r.Faits.SignatureAlgorithm)
			}
		}},
		{nom: "RSASSA-PSS à MGF1 SHA-1 par défaut", jeton: func(m *materiel, mj *modeleJeton) {
			mj.sign.pss = true
			mj.sign.algo = pssMGF1
		}, attendu: "re re re re ec ne:pe ne:pe re re ne:pe ne:pe"},
		{nom: "clé RSA de 1024 bits", jeton: avecCle(petite, algoDER(oidSHA256RSA, true)),
			attendu: "re re re re ec ne:pe ne:pe re re ne:pe ne:pe"},
		{nom: "ECDSA P-256", jeton: avecCle(p256, algoDER(oidECDSASHA256, false)), attendu: tousReussis,
			verif: func(t *testing.T, r Resultat) {
				if r.Faits.KeyBits != 256 || r.Faits.SignatureAlgorithm != "ecdsa-with-SHA256" {
					t.Errorf("faits : %d %s", r.Faits.KeyBits, r.Faits.SignatureAlgorithm)
				}
			}},
		{nom: "ECDSA P-224, hors de la version 0", jeton: avecCle(p224, algoDER(oidECDSASHA256, false)),
			attendu: "re re re re ne:hp ne:hp ne:hp re re ne:hp ne:hp", verif: func(t *testing.T, r Resultat) {
				if r.Statut != commun.NonExecute || r.Raison != commun.HorsPerimetreVersion {
					t.Errorf("statut %s/%s", r.Statut, r.Raison)
				}
			}},
		{nom: "signature ECDSA sous clé RSA", jeton: func(m *materiel, mj *modeleJeton) { mj.sigAlgo = algoDER(oidECDSASHA256, false) },
			attendu: "re re re re ec ne:pe ne:pe re re ne:pe ne:pe"},
		{nom: "algorithme DSA, hors de la version 0", jeton: func(m *materiel, mj *modeleJeton) {
			mj.sigAlgo = algoDER(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}, false)
		}, attendu: "re re re re ne:hp ne:hp ne:hp re re ne:hp ne:hp"},
	})
	_ = m
}

func TestT6Signature(t *testing.T) {
	jouer(t, []cas{
		{nom: "signature altérée", jeton: func(m *materiel, mj *modeleJeton) { mj.inverserSig = true },
			attendu: "re re re re re ec ne:pe re re ne:pe ne:pe"},
		{nom: "signature d'une autre clé", jeton: func(m *materiel, mj *modeleJeton) { mj.sign.cle = m.cleAC },
			attendu: "re re re re re ec ne:pe re re ne:pe ne:pe"},
	})
}

// interCA fabrique une AC intermédiaire signée par parent.
func interCA(t *testing.T, cle *rsa.PrivateKey, sujet, emetteur []byte, signe *rsa.PrivateKey, exts ...extTest) []byte {
	if exts == nil {
		exts = []extTest{extBC(1, boolDER(true)), extKU(1, 0x06, 1)}
	}
	return fabriquerCert(t, modeleCert{serie: 10, emetteur: emetteur, sujet: sujet,
		debut: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), fin: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		pub: cle.Public(), exts: exts, sign: signeurRSA(signe)})
}

func TestT7Chemin(t *testing.T) {
	m := mat(t)
	cleI1, _ := rsa.GenerateKey(rand.Reader, 2048)
	cleI2, _ := rsa.GenerateKey(rand.Reader, 2048)
	sujetI1, sujetI2 := nomSimple("AC intermédiaire 1"), nomSimple("AC intermédiaire 2")
	// Unité émise par I1.
	tsaSous := func(emetteur []byte, signe *rsa.PrivateKey) []byte {
		c := m.modeleTSA()
		c.emetteur, c.sign = emetteur, signeurRSA(signe)
		return fabriquerCert(t, c)
	}
	viaI1 := func(inter []byte) func(m *materiel, mj *modeleJeton) {
		return func(m *materiel, mj *modeleJeton) {
			c := tsaSous(sujetI1, cleI1)
			mj.certs, mj.certESS, mj.sidEmetteur = [][]byte{c, inter}, c, sujetI1
		}
	}
	i1 := interCA(t, cleI1, sujetI1, m.ac.sujet, m.cleAC)
	declaration := func(cert []byte) func(m *materiel, a *ancres.Ancres) *ancres.Ancres {
		return func(m *materiel, a *ancres.Ancres) *ancres.Ancres {
			a.Declarations = []ancres.Declaration{{Pointeur: "/revocation/statements/0", CertificatSha256: sha256.Sum256(cert), NonRevoqueA: time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)}}
			return a
		}
	}
	jouer(t, []cas{
		{nom: "sans fichier d'ancres", ancres: func(*materiel, *ancres.Ancres) *ancres.Ancres { return nil },
			attendu: "re re re re re re ne:aa re re ne:aa ne:aa", verif: func(t *testing.T, r Resultat) {
				if r.Statut != commun.NonExecute || r.Raison != commun.AncreAbsente || len(r.AncresEmployees) != 0 {
					t.Errorf("statut %s/%s %v", r.Statut, r.Raison, r.AncresEmployees)
				}
			}},
		{nom: "fichier d'ancres sans autorité", ancres: func(m *materiel, a *ancres.Ancres) *ancres.Ancres { a.Autorites = nil; return a },
			attendu: "re re re re re re ne:aa re re ne:aa ne:aa"},
		{nom: "politique non admise", ancres: func(m *materiel, a *ancres.Ancres) *ancres.Ancres {
			a.Autorites[0].PolitiquesAdmises = []string{"1.2.3"}
			return a
		}, attendu: "re re re re re re ec re re ne:pe ne:pe"},
		{nom: "toute politique admise", ancres: func(m *materiel, a *ancres.Ancres) *ancres.Ancres {
			a.Autorites[0].PolitiquesAdmises = nil
			return a
		}, attendu: tousReussis, verif: func(t *testing.T, r Resultat) {
			if strings.Join(r.AncresEmployees, ",") != "/tsa_authorities/0,/revocation/crls/0" {
				t.Errorf("anchors_used %v", r.AncresEmployees)
			}
		}},
		{nom: "unité épinglée (identité)", ancres: func(m *materiel, a *ancres.Ancres) *ancres.Ancres {
			a.Autorites[0].Certificat = m.certTSA
			a.Autorites[0].Nom = "Unité épinglée"
			return a
		}, attendu: tousReussis, verif: func(t *testing.T, r Resultat) {
			if r.Faits.Authority != "Unité épinglée" || len(r.Faits.Revocation) != 0 {
				t.Errorf("faits %+v", r.Faits)
			}
		}},
		{nom: "première autorité retenue", ancres: func(m *materiel, a *ancres.Ancres) *ancres.Ancres {
			a.Autorites = append(a.Autorites, ancres.Autorite{Pointeur: "/tsa_authorities/1", Nom: "Unité", Certificat: m.certTSA,
				Qualification: &ancres.Qualification{Cadre: "zertes", Debut: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Source: "s"}})
			return a
		}, attendu: tousReussis, verif: func(t *testing.T, r Resultat) {
			if r.Faits.Authority != "AC de test CT-6" {
				t.Errorf("autorité %s", r.Faits.Authority)
			}
		}},
		{nom: "autorité de politique refusée sautée", ancres: func(m *materiel, a *ancres.Ancres) *ancres.Ancres {
			a.Autorites[0].PolitiquesAdmises = []string{"1.2.3"}
			a.Autorites = append(a.Autorites, ancres.Autorite{Pointeur: "/tsa_authorities/1", Nom: "Unité", Certificat: m.certTSA,
				Qualification: &ancres.Qualification{Cadre: "zertes", Debut: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Source: "s"}})
			return a
		}, attendu: "re re re re re re re re re re re", verif: func(t *testing.T, r Resultat) {
			if r.Faits.Authority != "Unité" || r.Faits.Qualified == nil || r.Faits.Qualified.Framework != "zertes" {
				t.Errorf("faits %+v", r.Faits)
			}
			if !strings.HasSuffix(r.Proposition.Fr, " ; horodatage qualifié ZertES selon le réviseur (s)") || !strings.HasSuffix(r.Proposition.En, "; ZertES qualified timestamp according to the reviewer (s)") {
				t.Errorf("proposition : %s / %s", r.Proposition.Fr, r.Proposition.En)
			}
			if strings.Join(r.AncresEmployees, ",") != "/tsa_authorities/1" {
				t.Errorf("anchors_used %v", r.AncresEmployees)
			}
		}},
		{nom: "chemin par une AC intermédiaire, sans preuve pour l'unité", jeton: viaI1(i1),
			attendu: "re re re re re re re re re ne:aa ne:aa", avert: nil},
		{nom: "chemin par une AC intermédiaire, déclaration pour l'unité", jeton: viaI1(i1),
			ancres: func(m *materiel, a *ancres.Ancres) *ancres.Ancres {
				return declaration(tsaSous(sujetI1, cleI1))(m, a)
			}, attendu: tousReussis, verif: func(t *testing.T, r Resultat) {
				if len(r.Faits.Revocation) != 2 || r.Faits.Revocation[0].Evidence != "declaration" || r.Faits.Revocation[1].Evidence != "crl" {
					t.Errorf("révocation %+v", r.Faits.Revocation)
				}
			}},
		{nom: "intermédiaire dans l'ancre seulement", jeton: func(m *materiel, mj *modeleJeton) {
			c := tsaSous(sujetI1, cleI1)
			mj.certs, mj.certESS, mj.sidEmetteur = [][]byte{c}, c, sujetI1
		}, ancres: func(m *materiel, a *ancres.Ancres) *ancres.Ancres {
			a.Autorites[0].Intermediaires = [][]byte{i1}
			return declaration(tsaSous(sujetI1, cleI1))(m, a)
		}, attendu: tousReussis},
		{nom: "intermédiaire à basicConstraints non critique", jeton: viaI1(interCA(t, cleI1, sujetI1, m.ac.sujet, m.cleAC, extBC(0, boolDER(true)))),
			attendu: "re re re re re re ec re re ne:pe ne:pe"},
		{nom: "intermédiaire sans keyCertSign", jeton: viaI1(interCA(t, cleI1, sujetI1, m.ac.sujet, m.cleAC, extBC(1, boolDER(true)), extKU(1, 0x80, 7))),
			attendu: "re re re re re re ec re re ne:pe ne:pe"},
		{nom: "deux intermédiaires, pathLenConstraint 0 au second", jeton: func(m *materiel, mj *modeleJeton) {
			c := tsaSous(sujetI1, cleI1)
			a := interCA(t, cleI1, sujetI1, sujetI2, cleI2)
			b := interCA(t, cleI2, sujetI2, m.ac.sujet, m.cleAC, extBC(1, boolDER(true), entierDER(0)))
			mj.certs, mj.certESS, mj.sidEmetteur = [][]byte{c, a, b}, c, sujetI1
		}, attendu: "re re re re re re ec re re ne:pe ne:pe"},
		{nom: "deux intermédiaires, pathLenConstraint 1 au second", jeton: func(m *materiel, mj *modeleJeton) {
			c := tsaSous(sujetI1, cleI1)
			a := interCA(t, cleI1, sujetI1, sujetI2, cleI2)
			b := interCA(t, cleI2, sujetI2, m.ac.sujet, m.cleAC, extBC(1, boolDER(true), entierDER(1)))
			mj.certs, mj.certESS, mj.sidEmetteur = [][]byte{c, a, b}, c, sujetI1
		}, attendu: "re re re re re re re re re ne:aa ne:aa"},
		{nom: "extension critique inconnue dans l'unité", jeton: func(m *materiel, mj *modeleJeton) {
			c := m.unite(t, m.cleTSA.Public(), func(c *modeleCert) {
				c.exts = append(c.exts, extTest{asn1.ObjectIdentifier{1, 2, 3, 4}, 1, []byte{5, 0}})
			})
			mj.certs, mj.certESS = [][]byte{c}, c
		}, attendu: "re re re re re re ec re re ne:pe ne:pe"},
		{nom: "unité pas encore valide à genTime", jeton: func(m *materiel, mj *modeleJeton) {
			c := m.unite(t, m.cleTSA.Public(), func(c *modeleCert) { c.debut = time.Date(2026, 11, 5, 10, 0, 6, 0, time.UTC) })
			mj.certs, mj.certESS = [][]byte{c}, c
		}, attendu: "re re re re re re ec re re ne:pe ne:pe"},
		{nom: "unité valide à la seconde près (bornes incluses)", jeton: func(m *materiel, mj *modeleJeton) {
			c := m.unite(t, m.cleTSA.Public(), func(c *modeleCert) { c.debut = time.Date(2026, 11, 5, 10, 0, 5, 0, time.UTC) })
			mj.certs, mj.certESS = [][]byte{c}, c
		}, attendu: tousReussis},
		{nom: "genTime fractionnaire au-delà de notAfter", jeton: func(m *materiel, mj *modeleJeton) {
			c := m.unite(t, m.cleTSA.Public(), func(c *modeleCert) { c.fin = time.Date(2026, 11, 5, 10, 0, 5, 0, time.UTC) })
			mj.certs, mj.certESS = [][]byte{c}, c
			mj.genTime = "20261105100005.0000000001Z"
		}, attendu: "re re re re re re ec re re ne:pe ne:pe"},
		{nom: "unité signée par une autre clé que l'AC", jeton: func(m *materiel, mj *modeleJeton) {
			c := m.unite(t, m.cleTSA.Public(), func(c *modeleCert) { c.sign = signeurRSA(m.cleTSA) })
			mj.certs, mj.certESS = [][]byte{c}, c
		}, attendu: "re re re re re re ec re re ne:pe ne:pe"},
	})
}

func TestT8Usage(t *testing.T) {
	avec := func(f func(c *modeleCert)) func(m *materiel, mj *modeleJeton) {
		return func(m *materiel, mj *modeleJeton) {
			c := m.unite(t, m.cleTSA.Public(), f)
			mj.certs, mj.certESS = [][]byte{c}, c
		}
	}
	echec := "re re re re re re re ec re re ne:aa"
	jouer(t, []cas{
		{nom: "extKeyUsage absente", jeton: avec(func(c *modeleCert) { c.exts = []extTest{extKU(1, 0x80, 7)} }), attendu: echec},
		{nom: "extKeyUsage non critique", jeton: avec(func(c *modeleCert) { c.exts[1] = extEKU(0, oidTimeStamping) }), attendu: echec},
		{nom: "extKeyUsage à deux valeurs", jeton: avec(func(c *modeleCert) {
			c.exts[1] = extEKU(1, oidTimeStamping, asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1})
		}), attendu: echec},
		{nom: "keyUsage avec keyCertSign", jeton: avec(func(c *modeleCert) { c.exts[0] = extKU(1, 0x84, 2) }), attendu: echec},
		{nom: "keyUsage nonRepudiation seul", jeton: avec(func(c *modeleCert) { c.exts[0] = extKU(1, 0x40, 6) }), attendu: tousReussis},
		{nom: "keyUsage absent", jeton: avec(func(c *modeleCert) { c.exts = c.exts[1:] }), attendu: tousReussis},
		{nom: "basicConstraints à cA vrai", jeton: avec(func(c *modeleCert) { c.exts = append(c.exts, extBC(1, boolDER(true))) }), attendu: echec},
		{nom: "basicConstraints vide", jeton: avec(func(c *modeleCert) { c.exts = append(c.exts, extBC(0)) }), attendu: tousReussis},
	})
}

func TestT9ContenuTSTInfo(t *testing.T) {
	m := mat(t)
	echec := "re re re re re re ne:pe re ec ne:pe ne:pe"
	qc := func(contenu []byte, critique int) func(m *materiel, mj *modeleJeton) {
		return func(m *materiel, mj *modeleJeton) {
			mj.extsTST = []extTest{{oidQCStatements, critique, contenu}}
		}
	}
	jouer(t, []cas{
		{nom: "fraction à zéro final", jeton: func(m *materiel, mj *modeleJeton) { mj.genTime = "20261105100005.50Z" }, attendu: echec},
		{nom: "point sans fraction", jeton: func(m *materiel, mj *modeleJeton) { mj.genTime = "20261105100005.Z" }, attendu: echec},
		{nom: "date inexistante", jeton: func(m *materiel, mj *modeleJeton) { mj.genTime = "20260230100005Z" }, attendu: echec},
		{nom: "sans Z", jeton: func(m *materiel, mj *modeleJeton) { mj.genTime = "20261105100005" }, attendu: echec},
		{nom: "fraction longue conservée", jeton: func(m *materiel, mj *modeleJeton) {
			mj.genTime = "20261105100005.123456789012Z"
			mj.precision = seq(entierDER(1), elem(ctx(0, false), []byte{0x01, 0xf4}), elem(ctx(1, false), []byte{0x07}))
		}, attendu: tousReussis, verif: func(t *testing.T, r Resultat) {
			f := r.Faits
			if f.GenTime != "2026-11-05T10:00:05.123456789012Z" || *f.UpperBound != "2026-11-05T10:00:06.623463789012Z" {
				t.Errorf("gen_time %s, upper_bound %s", f.GenTime, *f.UpperBound)
			}
			if *f.Accuracy.Seconds != 1 || *f.Accuracy.Millis != 500 || *f.Accuracy.Micros != 7 {
				t.Errorf("accuracy %+v", f.Accuracy)
			}
		}},
		{nom: "accuracy de 86401 s", jeton: func(m *materiel, mj *modeleJeton) { mj.precision = seq(entierDER(86401)) }, attendu: echec},
		{nom: "accuracy de 86400 s", jeton: func(m *materiel, mj *modeleJeton) { mj.precision = seq(entierDER(86400)) }, attendu: tousReussis},
		{nom: "millis à 0", jeton: func(m *materiel, mj *modeleJeton) { mj.precision = seq(elem(ctx(0, false), []byte{0})) }, attendu: echec},
		{nom: "micros à 1000", jeton: func(m *materiel, mj *modeleJeton) { mj.precision = seq(elem(ctx(1, false), []byte{0x03, 0xe8})) }, attendu: echec},
		{nom: "secondes négatives", jeton: func(m *materiel, mj *modeleJeton) { mj.precision = seq(entierDER(-1)) }, attendu: echec},
		{nom: "secondes immenses (lues par T-1, bornées par T-9)", jeton: func(m *materiel, mj *modeleJeton) {
			mj.precision = seq(elem(casn1.INTEGER, append([]byte{0x01}, make([]byte, 40)...)))
		}, attendu: echec},
		{nom: "accuracy vide", jeton: func(m *materiel, mj *modeleJeton) { mj.precision = seq() }, attendu: tousReussis,
			verif: func(t *testing.T, r Resultat) {
				if r.Faits.Accuracy == nil || r.Faits.Accuracy.Seconds != nil || *r.Faits.UpperBound != r.Faits.GenTime {
					t.Errorf("faits %+v", r.Faits)
				}
			}},
		{nom: "sans accuracy", jeton: func(m *materiel, mj *modeleJeton) { mj.precision = nil }, attendu: tousReussis,
			verif: func(t *testing.T, r Resultat) {
				if r.Faits.Accuracy != nil || r.Faits.UpperBound != nil || r.Faits.UpperBoundInstant != nil {
					t.Errorf("faits %+v", r.Faits)
				}
				fr := "selon AC de test CT-6 (unité TSA de test CT-6), le manifeste d'empreinte " + periodHash1 + " existait au plus tard le 2026-11-05T10:00:05Z UTC, à la précision près de la politique 1.3.6.1.4.1.99999.1.1, que le jeton n'indique pas"
				en := "according to AC de test CT-6 (unit TSA de test CT-6), the manifest with digest " + periodHash1 + " existed no later than 2026-11-05T10:00:05Z UTC, within the accuracy of policy 1.3.6.1.4.1.99999.1.1, not stated in the token"
				if r.Proposition.Fr != fr || r.Proposition.En != en {
					t.Errorf("proposition :\n%s\n%s", r.Proposition.Fr, r.Proposition.En)
				}
			}},
		{nom: "genTime + accuracy au-delà de 9999", jeton: func(m *materiel, mj *modeleJeton) { mj.genTime = "99991231235959Z" }, attendu: echec},
		{nom: "année 0000 lue telle quelle", jeton: func(m *materiel, mj *modeleJeton) { mj.genTime = "00000101000000Z" },
			attendu: "re re re re re re ec re re ne:pe ne:pe"},
		{nom: "tsa différent du sujet", jeton: func(m *materiel, mj *modeleJeton) { mj.tsa = elem(ctx(4, true), nomSimple("autre")) }, attendu: echec},
		{nom: "tsa sous forme dNSName (AV-T-2)", jeton: func(m *materiel, mj *modeleJeton) { mj.tsa = elem(ctx(2, false), []byte("tsa.example")) },
			attendu: tousReussis, avert: []string{"AV-T-2"}},
		{nom: "tsa absent", jeton: func(m *materiel, mj *modeleJeton) { mj.tsa = nil }, attendu: tousReussis},
		{nom: "tsa directoryName et T-4 non exécutée", jeton: func(m *materiel, mj *modeleJeton) { mj.certs = nil },
			attendu: "re re re ne:aa ne:aa ne:aa ne:aa ne:aa ne:aa ne:aa ne:aa", verif: func(t *testing.T, r Resultat) {
				if !strings.Contains(r.Verifications[8].Detail.Fr, "règle 3 non évaluée") {
					t.Errorf("T-9 : %s", r.Verifications[8].Detail.Fr)
				}
			}},
		{nom: "tsa directoryName et T-4 en échec", jeton: func(m *materiel, mj *modeleJeton) {
			mj.attrs = remplacerAttr(oidSigningCert2, essV2(m.certAC, m.ac.sujet, 2))
		}, attendu: "re re re ec ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe"},
		{nom: "règle 1 en échec avant la règle 3", jeton: func(m *materiel, mj *modeleJeton) {
			mj.certs = nil
			mj.genTime = "2026"
		}, attendu: "re re re ne:aa ne:aa ne:aa ne:pe ne:aa ec ne:pe ne:pe"},
		{nom: "extension critique", jeton: func(m *materiel, mj *modeleJeton) {
			mj.extsTST = []extTest{{asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 2}, 1, []byte{5, 0}}}
		}, attendu: echec},
		{nom: "qcStatements avec esi4-qtstStatement-1", jeton: qc(seq(seq(oidDER(oidQTST))), 0), attendu: tousReussis,
			verif: func(t *testing.T, r Resultat) {
				if !r.Faits.QualifiedClaim || r.Faits.Qualified != nil {
					t.Errorf("qualified_claim %v", r.Faits.QualifiedClaim)
				}
			}},
		{nom: "qcStatements sans esi4-qtstStatement-1", jeton: qc(seq(seq(oidDER(asn1.ObjectIdentifier{1, 2, 3}), []byte{5, 0})), 0), attendu: tousReussis,
			verif: func(t *testing.T, r Resultat) {
				if r.Faits.QualifiedClaim {
					t.Errorf("qualified_claim vrai")
				}
			}},
		{nom: "qcStatements mal formée", jeton: qc(seq(oidDER(oidQTST)), 0), attendu: echec},
		{nom: "qcStatements à critical FALSE (AV-T-1, T-9 réussie)", jeton: qc(seq(seq(oidDER(oidQTST))), 2), attendu: tousReussis, avert: []string{"AV-T-1"}},
		{nom: "ts de l'événement après genTime + accuracy (AV-T-4)", entree: func(e *Entree) {
			e.TsEvenement, e.TsDisponible = time.Date(2026, 11, 5, 10, 0, 6, 1_000_000, time.UTC), true
		}, attendu: tousReussis, avert: []string{"AV-T-4"}},
		{nom: "ts de l'événement égal à genTime + accuracy", entree: func(e *Entree) {
			e.TsEvenement, e.TsDisponible = time.Date(2026, 11, 5, 10, 0, 6, 0, time.UTC), true
		}, attendu: tousReussis},
		{nom: "ts indisponible", entree: func(e *Entree) {
			e.TsEvenement, e.TsDisponible = time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), false
		}, attendu: tousReussis},
	})
	_ = m
}

func TestT10Revocation(t *testing.T) {
	m := mat(t)
	gen := time.Date(2026, 11, 5, 10, 0, 5, 0, time.UTC)
	crlAC := func(f func(c *modeleCRL)) []byte {
		c := modeleCRL{emetteur: m.ac.sujet, thisUpdate: time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC), sign: signeurRSA(m.cleAC)}
		if f != nil {
			f(&c)
		}
		return fabriquerCRL(t, c)
	}
	avecCRL := func(crls ...[]byte) func(m *materiel, a *ancres.Ancres) *ancres.Ancres {
		return func(m *materiel, a *ancres.Ancres) *ancres.Ancres {
			a.CRLs = nil
			for i, c := range crls {
				a.CRLs = append(a.CRLs, ancres.CRL{Pointeur: "/revocation/crls/" + string(rune('0'+i)), DER: c})
			}
			return a
		}
	}
	revocation := func(raison int, date time.Time) []byte {
		return crlAC(func(c *modeleCRL) { c.entrees = []entreeTest{{2, date, raison}} })
	}
	sansPreuve := "re re re re re re re re re ne:aa ne:aa"
	echec := "re re re re re re re re re ec ne:aa"
	epingle := func(crls ...[]byte) func(m *materiel, a *ancres.Ancres) *ancres.Ancres {
		return func(m *materiel, a *ancres.Ancres) *ancres.Ancres {
			a = avecCRL(crls...)(m, a)
			a.Autorites[0].Certificat = m.certTSA
			return a
		}
	}
	jouer(t, []cas{
		{nom: "CRL vide de l'ancre", attendu: tousReussis, verif: func(t *testing.T, r Resultat) {
			if len(r.Faits.Revocation) != 1 || r.Faits.Revocation[0].IssuedAt != "2026-11-06T00:00:00Z" || r.Faits.Revocation[0].CertificateSha256 != r.Faits.TsuCertificateSha256 {
				t.Errorf("révocation %+v", r.Faits.Revocation)
			}
		}},
		{nom: "keyCompromise", ancres: avecCRL(revocation(1, gen.Add(time.Hour))), attendu: echec},
		{nom: "superseded après genTime (tolérée)", ancres: avecCRL(revocation(4, gen.Add(time.Hour))), attendu: tousReussis},
		{nom: "cessationOfOperation à genTime exactement", ancres: avecCRL(revocation(5, gen)), attendu: echec},
		{nom: "unspecified après genTime (tolérée)", ancres: avecCRL(revocation(0, gen.Add(time.Second))), attendu: tousReussis},
		{nom: "certificateHold après genTime", ancres: avecCRL(revocation(6, gen.Add(time.Hour))), attendu: echec},
		{nom: "sans raison", ancres: avecCRL(revocation(-1, gen.Add(time.Hour))), attendu: echec},
		{nom: "autre numéro révoqué", ancres: avecCRL(crlAC(func(c *modeleCRL) { c.entrees = []entreeTest{{7, gen, 1}} })), attendu: tousReussis},
		{nom: "CRL antérieure à genTime (AV-T-3)", ancres: avecCRL(crlAC(func(c *modeleCRL) { c.thisUpdate = gen.Add(-time.Second) })),
			attendu: sansPreuve, avert: []string{"AV-T-3"}},
		{nom: "CRL delta (AV-T-3)", ancres: avecCRL(crlAC(func(c *modeleCRL) { c.exts = []extTest{{oidDeltaCRL, 1, entierDER(1)}} })),
			attendu: sansPreuve, avert: []string{"AV-T-3"}},
		{nom: "CRL à issuingDistributionPoint critique (AV-T-3)", ancres: avecCRL(crlAC(func(c *modeleCRL) { c.exts = []extTest{{oidIDP, 1, seq()}} })),
			attendu: sansPreuve, avert: []string{"AV-T-3"}},
		{nom: "CRL mal signée (AV-T-3)", ancres: avecCRL(crlAC(func(c *modeleCRL) { c.sign = signeurRSA(m.cleTSA) })),
			attendu: sansPreuve, avert: []string{"AV-T-3"}},
		{nom: "CRL écartée puis CRL retenue", ancres: avecCRL(crlAC(func(c *modeleCRL) { c.thisUpdate = gen.Add(-time.Second) }), m.crlVide),
			attendu: tousReussis, avert: []string{"AV-T-3"}, verif: func(t *testing.T, r Resultat) {
				if strings.Join(r.AncresEmployees, ",") != "/tsa_authorities/0,/revocation/crls/1" {
					t.Errorf("anchors_used %v", r.AncresEmployees)
				}
			}},
		{nom: "CRL d'un autre émetteur, non consultée", ancres: avecCRL(crlAC(func(c *modeleCRL) { c.emetteur = nomSimple("autre") })),
			attendu: sansPreuve},
		{nom: "déclaration du réviseur", ancres: func(m *materiel, a *ancres.Ancres) *ancres.Ancres {
			a.CRLs = nil
			a.Declarations = []ancres.Declaration{{Pointeur: "/revocation/statements/0", CertificatSha256: sha256.Sum256(m.certTSA), NonRevoqueA: gen}}
			return a
		}, attendu: tousReussis, verif: func(t *testing.T, r Resultat) {
			if r.Faits.Revocation[0].Evidence != "declaration" || r.Faits.Revocation[0].IssuedAt != "2026-11-05T10:00:05Z" {
				t.Errorf("révocation %+v", r.Faits.Revocation)
			}
			if strings.Join(r.AncresEmployees, ",") != "/tsa_authorities/0" {
				t.Errorf("anchors_used %v", r.AncresEmployees)
			}
		}},
		{nom: "déclaration antérieure à genTime", ancres: func(m *materiel, a *ancres.Ancres) *ancres.Ancres {
			a.CRLs = nil
			a.Declarations = []ancres.Declaration{{Pointeur: "/revocation/statements/0", CertificatSha256: sha256.Sum256(m.certTSA), NonRevoqueA: gen.Add(-time.Millisecond)}}
			return a
		}, attendu: sansPreuve},
		{nom: "CRL du jeton retenue", jeton: func(m *materiel, mj *modeleJeton) { mj.crls = [][]byte{m.crlVide} },
			ancres: avecCRL(), attendu: tousReussis},
		{nom: "CRL du jeton qui révoque", jeton: func(m *materiel, mj *modeleJeton) { mj.crls = [][]byte{m.crlRevoquee} },
			ancres: avecCRL(), attendu: echec},
		{nom: "CRL du jeton illisible (AV-T-3)", jeton: func(m *materiel, mj *modeleJeton) { mj.crls = [][]byte{seq(entierDER(1))} },
			ancres: avecCRL(), attendu: sansPreuve, avert: []string{"AV-T-3"}},
		{nom: "autre format de révocation du jeton, ignoré", jeton: func(m *materiel, mj *modeleJeton) { mj.crls = [][]byte{elem(ctx(1, true), seq())} },
			attendu: tousReussis},
		{nom: "unité épinglée révoquée par la CRL de l'ancre", ancres: epingle(m.crlRevoquee), attendu: echec, verif: func(t *testing.T, r Resultat) {
			if strings.Join(r.AncresEmployees, ",") != "/tsa_authorities/0,/revocation/crls/0" {
				t.Errorf("anchors_used %v", r.AncresEmployees)
			}
		}},
		{nom: "unité épinglée, révocation tolérée", ancres: epingle(revocation(3, gen.Add(time.Hour))), attendu: tousReussis},
		{nom: "unité épinglée, CRL mal signée prise quand même", ancres: epingle(crlAC(func(c *modeleCRL) {
			c.sign = signeurRSA(m.cleTSA)
			c.entrees = []entreeTest{{2, gen, 1}}
		})), attendu: echec},
		{nom: "unité épinglée, CRL du jeton non consultée", jeton: func(m *materiel, mj *modeleJeton) { mj.crls = [][]byte{m.crlRevoquee} },
			ancres: epingle(), attendu: tousReussis},
		{nom: "unité épinglée, CRL delta ignorée", ancres: epingle(crlAC(func(c *modeleCRL) {
			c.entrees = []entreeTest{{2, gen, 1}}
			c.exts = []extTest{{oidDeltaCRL, 1, entierDER(1)}}
		})), attendu: tousReussis},
	})
}

func TestT11Qualification(t *testing.T) {
	q := func(debut time.Time, fin *time.Time) func(m *materiel, a *ancres.Ancres) *ancres.Ancres {
		return func(m *materiel, a *ancres.Ancres) *ancres.Ancres {
			a.Autorites[0].Qualification = &ancres.Qualification{Cadre: "eidas", Debut: debut, Fin: fin, Source: "déclaration"}
			return a
		}
	}
	gen := time.Date(2026, 11, 5, 10, 0, 5, 0, time.UTC)
	avant := gen.Add(-time.Millisecond)
	jouer(t, []cas{
		{nom: "intervalle sans borne haute", ancres: q(gen, nil), attendu: "re re re re re re re re re re re", verif: func(t *testing.T, r Resultat) {
			if r.Faits.Qualified == nil || r.Faits.Qualified.Framework != "eidas" || r.Faits.Qualified.Source != "déclaration" {
				t.Errorf("qualified %+v", r.Faits.Qualified)
			}
		}},
		{nom: "intervalle fermé sur genTime", ancres: q(gen, &gen), attendu: "re re re re re re re re re re re"},
		{nom: "intervalle échu", ancres: q(avant.Add(-time.Hour), &avant), attendu: tousReussis, verif: func(t *testing.T, r Resultat) {
			if r.Faits.Qualified != nil || strings.Contains(r.Proposition.Fr, "qualifié") {
				t.Errorf("qualifié à tort")
			}
		}},
		{nom: "intervalle futur", ancres: q(gen.Add(time.Millisecond), nil), attendu: tousReussis},
	})
}

func TestK7Point(t *testing.T) {
	borne := time.Date(2026, 11, 5, 10, 0, 6, 0, time.UTC)
	point := func(ck time.Time) func(e *Entree) {
		return func(e *Entree) { e.Usage = Point; e.CheckpointTs = ck }
	}
	verifPoint := func(t *testing.T, r Resultat) {
		if !r.Proposition.Vide() || r.Faits == nil || r.Resume.Vide() {
			t.Errorf("point : proposition %q, faits %v", r.Proposition.Fr, r.Faits != nil)
		}
		for _, a := range r.Avertissements {
			if strings.HasPrefix(a.ID, "AV-K-") && a.Verification != "K-7" {
				t.Errorf("%s levé par %s", a.ID, a.Verification)
			}
		}
	}
	jouer(t, []cas{
		{nom: "point contresigné à temps", entree: point(borne.Add(-2 * time.Second)), attendu: tousReussis, verif: verifPoint},
		{nom: "checkpoint_ts égal à la borne", entree: point(borne), attendu: tousReussis, verif: verifPoint},
		{nom: "checkpoint_ts après la borne (AV-K-2)", entree: point(borne.Add(time.Millisecond)), attendu: tousReussis, avert: []string{"AV-K-2"}, verif: verifPoint},
		{nom: "contresignature tardive (AV-K-4)", entree: point(borne.Add(-3600*time.Second - time.Millisecond)), attendu: tousReussis, avert: []string{"AV-K-4"}, verif: verifPoint},
		{nom: "contresignature à 3600 s exactement", entree: point(borne.Add(-3600 * time.Second)), attendu: tousReussis, verif: verifPoint},
		{nom: "K-7 en échec : pas d'AV-K", jeton: func(m *materiel, mj *modeleJeton) { mj.inverserSig = true },
			entree: point(borne.Add(time.Hour)), attendu: "re re re re re ec ne:pe re re ne:pe ne:pe"},
		{nom: "point, AV-T-4 et AV-K-2 ensemble", entree: func(e *Entree) {
			point(borne.Add(time.Second))(e)
			e.TsEvenement, e.TsDisponible = borne.Add(time.Second), true
		}, attendu: tousReussis, avert: []string{"AV-T-4", "AV-K-2"}},
	})
}

func TestResumeEtProposition(t *testing.T) {
	m := mat(t)
	r := executer(t, m, cas{})
	if r.Resume.Fr != "selon AC de test CT-6 (unité TSA de test CT-6), au plus tard 2026-11-05T10:00:06Z ; aucun statut qualifié déclaré" {
		t.Errorf("résumé : %s", r.Resume.Fr)
	}
	fr := "selon AC de test CT-6 (unité TSA de test CT-6), le manifeste d'empreinte " + periodHash1 + " existait au plus tard le 2026-11-05T10:00:06Z UTC"
	en := "according to AC de test CT-6 (unit TSA de test CT-6), the manifest with digest " + periodHash1 + " existed no later than 2026-11-05T10:00:06Z UTC"
	if r.Proposition.Fr != fr || r.Proposition.En != en {
		t.Errorf("proposition :\n%s\n%s", r.Proposition.Fr, r.Proposition.En)
	}
	// Un résultat non réussi ne porte ni faits, ni proposition, ni résumé.
	r = executer(t, m, cas{jeton: func(m *materiel, mj *modeleJeton) { mj.inverserSig = true }})
	if r.Faits != nil || !r.Proposition.Vide() || !r.Resume.Vide() {
		t.Errorf("résultat en échec avec faits ou textes")
	}
}
