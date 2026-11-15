package horodatage

// Essais de la revue de sécurité interne de l'étape 8, révision 0.9 de
// CT-6 : le profil DER d'EX-9.4 s'applique à tout le jeton, signature
// couvrant l'octet ou non ; une CRL à extension critique que la version 0 ne lit pas, sur la liste ou
// sur une entrée, n'est pas une preuve de non-révocation (EX-9.16).

import (
	"encoding/asn1"
	"testing"
	"time"

	"github.com/noorfinances-eng/noortrace/verificateur/ancres"
	"github.com/noorfinances-eng/noortrace/verificateur/commun"
)

var oidEssaiInconnu = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 2}

const t1Echoue = "ec ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe"

// TestProfilDERToutLeJetonP : CT-6 EX-9.4. Cinq formes que X.690 interdit,
// placées dans le champ crls [1] (hors de la signature), et un NULL de
// longueur 1 dans unsignedAttrs, mettent T-1 en échec ; un INTEGER non
// minimal reste admis (EX-9.6).
func TestProfilDERToutLeJetonP(t *testing.T) {
	formes := []struct {
		nom string
		der []byte
	}{
		{"NULL de longueur 1", []byte{0x05, 0x01, 0x00}},
		{"INTEGER vide", []byte{0x02, 0x00}},
		{"BIT STRING vide", []byte{0x03, 0x00}},
		{"OCTET STRING construite", []byte{0x24, 0x02, 0x04, 0x00}},
		{"étiquette universelle 0", []byte{0x00, 0x00}},
	}
	var liste []cas
	for _, f := range formes {
		der := f.der
		liste = append(liste, cas{nom: f.nom + " dans crls", jeton: func(m *materiel, mj *modeleJeton) { mj.crls = [][]byte{der} }, attendu: t1Echoue})
	}
	liste = append(liste, cas{nom: "NULL de longueur 1 dans unsignedAttrs", jeton: func(m *materiel, mj *modeleJeton) {
		mj.nonSignes = seq(oidDER(oidEssaiInconnu), set([]byte{0x05, 0x01, 0x00}))
	}, attendu: t1Echoue})
	liste = append(liste, cas{nom: "témoin : attribut non signé bien formé", jeton: func(m *materiel, mj *modeleJeton) {
		mj.nonSignes = seq(oidDER(oidEssaiInconnu), set([]byte{0x05, 0x00}))
	}, attendu: tousReussis})
	jouer(t, liste)
	if d := verifierProfil([]byte{0x30, 0x04, 0x02, 0x02, 0x00, 0x03}, 0); d != nil {
		t.Fatalf("INTEGER non minimal refusé par le profil (EX-9.6) : %s", d.fr)
	}
}

// TestCRLExtensionCritiqueInconnueP : CT-6 EX-9.16. Une CRL de l'ancre, complète et
// bien signée, qui porte une extension critique non lue sur la liste ou sur
// une entrée, est écartée (AV-T-3) : T-10 non exécutée, ancre_absente ; la
// même extension non critique laisse la CRL en preuve.
func TestCRLExtensionCritiqueInconnueP(t *testing.T) {
	quand := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	revoc := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	crlDe := func(m *materiel, critique int, surEntree bool) []byte {
		x := extTest{oidEssaiInconnu, critique, []byte{0x05, 0x00}}
		mc := modeleCRL{emetteur: m.ac.sujet, thisUpdate: quand, sign: signeurRSA(m.cleAC)}
		if surEntree {
			mc.entrees = []entreeTest{{serie: 99, date: revoc, raison: 4}}
			mc.extsEntrees = map[int][]extTest{0: {x}}
		} else {
			mc.exts = []extTest{x}
		}
		return fabriquerCRL(t, mc)
	}
	avec := func(critique int, surEntree bool) func(m *materiel, a *ancres.Ancres) *ancres.Ancres {
		return func(m *materiel, a *ancres.Ancres) *ancres.Ancres {
			a.CRLs = []ancres.CRL{{Pointeur: "/revocation/crls/0", DER: crlDe(m, critique, surEntree)}}
			return a
		}
	}
	ecartee := "re re re re re re re re re ne:aa ne:aa"
	jouer(t, []cas{
		{nom: "extension critique non lue sur la liste", ancres: avec(1, false), attendu: ecartee, avert: []string{"AV-T-3"}, verif: func(t *testing.T, r Resultat) {
			if r.Verifications[9].Raison != commun.AncreAbsente {
				t.Errorf("T-10 : raison %s", r.Verifications[9].Raison)
			}
		}},
		{nom: "extension critique non lue sur une entrée", ancres: avec(1, true), attendu: ecartee, avert: []string{"AV-T-3"}},
		{nom: "témoin : extension non critique inconnue sur la liste", ancres: avec(0, false), attendu: tousReussis},
		{nom: "témoin : extension non critique inconnue sur une entrée", ancres: avec(0, true), attendu: tousReussis},
		// Certificat de l'autorité (EX-9.16) : une CRL du fichier d'ancres à extension critique non lue qui le révoque
		// n'est pas consultée ; la révocation n'est pas vue, la CRL est écartée (AV-T-3) et les certificats du chemin
		// restent sans preuve.
		{nom: "CRL non lue qui révoque le certificat de l'autorité : non consultée", ancres: func(m *materiel, a *ancres.Ancres) *ancres.Ancres {
			serieAC := append([]byte{0x02, byte(len(m.ac.serie))}, m.ac.serie...)
			a.CRLs = []ancres.CRL{{Pointeur: "/revocation/crls/0", DER: fabriquerCRL(t, modeleCRL{emetteur: m.ac.sujet, thisUpdate: quand, sign: signeurRSA(m.cleAC),
				entrees: []entreeTest{{serie: 0, date: revoc, raison: 1}}, seriesBrutes: map[int][]byte{0: serieAC},
				exts: []extTest{{oidEssaiInconnu, 1, []byte{0x05, 0x00}}}})}}
			return a
		}, attendu: ecartee, avert: []string{"AV-T-3"}},
	})
}
