package horodatage

// Essais de la revue de sécurité interne de l'étape 8 : CT-6 EX-9.11 (sel
// RSASSA-PSS de longueur déclarée 0), (CRL au numéro de série non
// minimal, EX-9.6) et N-1 (lecture des paramètres RSASSA-PSS éprouvée
// branche par branche). Chaque règle a un cas qui échoue sur l'ancien code
// et passe sur le nouveau.

import (
	"crypto"
	"crypto/rsa"
	"math/big"
	"testing"
	"time"

	"github.com/noorfinances-eng/noortrace/verificateur/ancres"
	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"golang.org/x/crypto/cryptobyte"
	casn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// signerPSSSelVide signe mHash selon EMSA-PSS-ENCODE (RFC 8017 §9.1.1) avec
// sLen = 0, puis RSASP1 : la bibliothèque standard ne produit pas de sel
// vide (SaltLength 0 y vaut « automatique », longueur maximale).
func signerPSSSelVide(k *rsa.PrivateKey, h crypto.Hash, mHash []byte) []byte {
	hLen := h.Size()
	emBits := k.N.BitLen() - 1
	emLen := (emBits + 7) / 8
	x := h.New()
	x.Write(make([]byte, 8))
	x.Write(mHash)
	H := x.Sum(nil)
	db := make([]byte, emLen-hLen-1)
	db[len(db)-1] = 0x01
	masque := mgf1(h, H, len(db))
	for i := range db {
		db[i] ^= masque[i]
	}
	db[0] &= 0xff >> (8*emLen - emBits)
	em := append(append(db, H...), 0xbc)
	m := new(big.Int).SetBytes(em)
	s := new(big.Int).Exp(m, k.D, k.N)
	out := make([]byte, (k.N.BitLen()+7)/8)
	s.FillBytes(out)
	return out
}

// paramsPSS construit RSASSA-PSS-params avec SHA-256, MGF1-SHA-256 et la
// longueur de sel donnée.
func paramsPSS(sel int64) []byte {
	return seq(oidDER(oidPSS), seq(elem(ctx(0, true), algoDER(oidSHA256, true)), elem(ctx(1, true), seq(oidDER(oidMGF1), algoDER(oidSHA256, true))), elem(ctx(2, true), entierDER(sel))))
}

// TestPSSSelDeclareZero : CT-6 EX-9.11. Des paramètres qui déclarent saltLength 0
// n'admettent qu'une signature au sel vide : une signature au sel de 32
// octets est refusée (T-6), une signature au sel vide est acceptée.
func TestPSSSelDeclareZero(t *testing.T) {
	jouer(t, []cas{
		{nom: "saltLength 0 déclaré, sel de 32 octets : T-6 échoue", jeton: func(m *materiel, mj *modeleJeton) {
			mj.sign.pss = true
			mj.sign.algo = paramsPSS(0)
		}, attendu: "re re re re re ec ne:pe re re ne:pe ne:pe"},
		{nom: "saltLength 0 déclaré, sel vide : réussi", jeton: func(m *materiel, mj *modeleJeton) {
			mj.sign.pss, mj.sign.selVide = true, true
			mj.sign.algo = paramsPSS(0)
		}, attendu: tousReussis},
		{nom: "saltLength 32 déclaré, sel vide : T-6 échoue", jeton: func(m *materiel, mj *modeleJeton) {
			mj.sign.pss, mj.sign.selVide = true, true
			mj.sign.algo = paramsPSS(32)
		}, attendu: "re re re re re ec ne:pe re re ne:pe ne:pe"},
	})
}

// TestPSSParametresBranches : CT-6 N-1. Chaque branche de refus de la lecture
// des paramètres RSASSA-PSS a son cas (T-5 échoue, « paramètres RSASSA-PSS
// contraires à EX-9.11 »).
func TestPSSParametresBranches(t *testing.T) {
	t5Echoue := "re re re re ec ne:pe ne:pe re re ne:pe ne:pe"
	mgf := func(h []byte) []byte { return elem(ctx(1, true), seq(oidDER(oidMGF1), h)) }
	hashA := func(h []byte) []byte { return elem(ctx(0, true), h) }
	tableau := []struct {
		nom    string
		params []byte
	}{
		{"paramètres absents (SHA-1 par défaut)", seq(oidDER(oidPSS))},
		{"paramètres qui ne sont pas une SEQUENCE", seq(oidDER(oidPSS), oct([]byte{1}))},
		{"hashAlgorithm SHA-1", seq(oidDER(oidPSS), seq(hashA(algoDER(oidSHA1, true)), mgf(algoDER(oidSHA1, true))))},
		{"hashAlgorithm à paramètres non NULL", seq(oidDER(oidPSS), seq(hashA(seq(oidDER(oidSHA256), oct([]byte{1}))), mgf(algoDER(oidSHA256, true))))},
		{"maskGenAlgorithm autre que MGF1", seq(oidDER(oidPSS), seq(hashA(algoDER(oidSHA256, true)), elem(ctx(1, true), seq(oidDER(oidSHA256), algoDER(oidSHA256, true)))))},
		{"MGF1 sans paramètres", seq(oidDER(oidPSS), seq(hashA(algoDER(oidSHA256, true)), elem(ctx(1, true), seq(oidDER(oidMGF1)))))},
		{"MGF1 sur SHA-384 alors que hashAlgorithm est SHA-256", seq(oidDER(oidPSS), seq(hashA(algoDER(oidSHA256, true)), mgf(algoDER(oidSHA384, true))))},
		{"saltLength négatif", seq(oidDER(oidPSS), seq(hashA(algoDER(oidSHA256, true)), mgf(algoDER(oidSHA256, true)), elem(ctx(2, true), entierDER(-1))))},
		{"saltLength au-delà de 65 536", seq(oidDER(oidPSS), seq(hashA(algoDER(oidSHA256, true)), mgf(algoDER(oidSHA256, true)), elem(ctx(2, true), entierDER(1<<17))))},
		{"trailerField 2", seq(oidDER(oidPSS), seq(hashA(algoDER(oidSHA256, true)), mgf(algoDER(oidSHA256, true)), elem(ctx(2, true), entierDER(32)), elem(ctx(3, true), entierDER(2))))},
		{"trailerField qui n'est pas un INTEGER", seq(oidDER(oidPSS), seq(hashA(algoDER(oidSHA256, true)), mgf(algoDER(oidSHA256, true)), elem(ctx(2, true), entierDER(32)), elem(ctx(3, true), oct([]byte{1}))))},
		{"élément en trop après trailerField", seq(oidDER(oidPSS), seq(hashA(algoDER(oidSHA256, true)), mgf(algoDER(oidSHA256, true)), elem(ctx(2, true), entierDER(32)), elem(ctx(3, true), entierDER(1)), oct([]byte{1})))},
		{"hashAlgorithm SHA-384 alors que digestAlgorithm est SHA-256", seq(oidDER(oidPSS), seq(hashA(algoDER(oidSHA384, true)), mgf(algoDER(oidSHA384, true))))},
	}
	var liste []cas
	for _, c := range tableau {
		p := c.params
		liste = append(liste, cas{nom: c.nom, jeton: func(m *materiel, mj *modeleJeton) {
			mj.sign.pss = true
			mj.sign.algo = p
		}, attendu: t5Echoue, verif: func(t *testing.T, r Resultat) {
			if d := r.Verifications[4].Detail.Fr; d != "paramètres RSASSA-PSS contraires à EX-9.11" {
				t.Errorf("détail de T-5 : %s", d)
			}
		}})
	}
	jouer(t, liste)
}

// TestCRLNumeroNonMinimal : CT-6 EX-9.6. Une CRL dont le numéro de série d'une
// entrée est encodé sous forme non minimale (02 02 00 02 pour 2) est lue
// (EX-9.6 : la forme minimale des INTEGER n'est pas contrôlée), N-1 la
// garde, et T-10 voit la révocation : le numéro se compare par sa valeur.
func TestCRLNumeroNonMinimal(t *testing.T) {
	m := mat(t)
	serieTSA := m.tsa.serie
	nonMinimal := append([]byte{0x02, byte(len(serieTSA) + 1), 0x00}, serieTSA...)
	crl := fabriquerCRL(t, modeleCRL{emetteur: m.ac.sujet, thisUpdate: time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC),
		entrees:      []entreeTest{{serie: 0, date: time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC), raison: 1}},
		seriesBrutes: map[int][]byte{0: nonMinimal},
		sign:         signeurRSA(m.cleAC)})
	if err := (ControleurAncres{}).CRL(crl); err != nil {
		t.Fatalf("N-1 refuse la CRL au numéro non minimal : %v", err)
	}
	l, d := lireCRL(crl)
	if d != nil {
		t.Fatal(d.fr)
	}
	if l.liste(serieTSA) == nil {
		t.Fatal("l'entrée au numéro non minimal n'est pas retrouvée par sa valeur")
	}
	jouer(t, []cas{{nom: "CRL de l'ancre au numéro non minimal : T-10 échoue (keyCompromise)",
		ancres: func(m *materiel, a *ancres.Ancres) *ancres.Ancres {
			a.CRLs = []ancres.CRL{{Pointeur: "/revocation/crls/0", DER: crl}}
			return a
		}, attendu: "re re re re re re re re re ec ne:aa",
		verif: func(t *testing.T, r Resultat) {
			if r.Verifications[9].Statut != commun.Echoue {
				t.Errorf("T-10 %s", r.Verifications[9].Statut)
			}
		}}})
}

// TestProfilDERGardeLesEntiersTelsQuels : le lecteur du profil de §9.3 ne
// contrôle pas la forme minimale d'un INTEGER (EX-9.6), mais un INTEGER
// vide reste un défaut de lecture là où une valeur est lue.
func TestProfilDERGardeLesEntiersTelsQuels(t *testing.T) {
	b := cryptobyte.String([]byte{0x02, 0x02, 0x00, 0x02})
	v, ok := lireEntier(&b, casn1.INTEGER)
	if !ok || !memeEntier(v, []byte{0x02}) {
		t.Fatalf("INTEGER non minimal : %x, %v", v, ok)
	}
	if d := verifierProfil([]byte{0x30, 0x04, 0x02, 0x02, 0x00, 0x02}, 0); d != nil {
		t.Fatalf("profil : %s", d.fr)
	}
}
