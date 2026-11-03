package horodatage

// Règles de la révision 0.4 de CT-6 propres au contrôle 4 : borne des clés
// RSA (EX-9.23) et clé ou algorithme hors de la version 0 (EX-9.24), en
// réussite et en échec. EX-9.10 (sid introuvable) est dans
// TestT4CertificatSignataire.

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"

	casn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/noorfinances-eng/noortrace/verificateur/ancres"
	"github.com/noorfinances-eng/noortrace/verificateur/commun"
)

// moduleImpair rend un module RSA impair d'exactement n bits (non premier
// en général : la clé n'est jamais employée, la borne est contrôlée avant
// tout calcul).
func moduleImpair(t *testing.T, n int) *big.Int {
	t.Helper()
	b := make([]byte, (n+7)/8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	m := new(big.Int).SetBytes(b)
	m.SetBit(m, n-1, 1)
	for i := n; i < len(b)*8; i++ {
		m.SetBit(m, i, 0)
	}
	m.SetBit(m, 0, 1)
	return m
}

func spkiRSA(t *testing.T, n *big.Int, e int) []byte {
	t.Helper()
	b, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n, E: e})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestEX923BornesRSA : module de 2048 à 8192 bits, exposant impair de 3 à
// 2³¹ − 1, contrôlés sur la clé, avant tout calcul.
func TestEX923BornesRSA(t *testing.T) {
	cas := []struct {
		nom    string
		bits   int
		e      int
		adm    admission
		detail string
	}{
		{"2048 bits", 2048, 65537, admis, ""},
		{"8192 bits", 8192, 65537, admis, ""},
		{"8193 bits", 8193, 65537, refuse, "8193 bits, au-delà de 8192 (EX-9.23)"},
		{"8200 bits", 8200, 65537, refuse, "8200 bits, au-delà de 8192 (EX-9.23)"},
		{"2047 bits", 2047, 65537, refuse, "moins de 2048"},
		{"exposant 3", 3072, 3, admis, ""},
		{"exposant 2³¹ − 1", 3072, 1<<31 - 1, admis, ""},
		{"exposant pair", 3072, 65536, refuse, "exposant public hors de 3 à 2³¹ − 1, ou pair (EX-9.23)"},
		{"exposant 2³¹ + 1", 3072, 1<<31 + 1, refuse, "exposant public"},
		{"exposant 1", 3072, 1, refuse, "exposant public"},
	}
	for _, c := range cas {
		t.Run(c.nom, func(t *testing.T) {
			k, adm, d := lireCle(spkiRSA(t, moduleImpair(t, c.bits), c.e))
			if adm != c.adm {
				t.Fatalf("admission %d, attendu %d", adm, c.adm)
			}
			if c.adm == admis && k.bits != c.bits {
				t.Errorf("bits %d", k.bits)
			}
			if c.detail != "" && (d == nil || !strings.Contains(d.fr, c.detail)) {
				t.Errorf("détail : %v", d)
			}
		})
	}
	// T-7 et T-10 : une signature de certificat ou de CRL sous une clé
	// hors bornes ne compte pas, sans calcul.
	if signatureAdmise(algo{oid: oidSHA256RSA}, spkiRSA(t, moduleImpair(t, 8200), 65537), []byte("m"), make([]byte, 1025)) {
		t.Error("signature admise sous une clé de 8200 bits")
	}
}

// TestEX923T5 : clé de S hors des bornes : T-5 échoue (et non
// hors_perimetre_version), T-6, T-7, T-10 et T-11 prerequis_en_echec, T-8
// et T-9 exécutées.
func TestEX923T5(t *testing.T) {
	m := mat(t)
	echec := "re re re re ec ne:pe ne:pe re re ne:pe ne:pe"
	cle := func(n *big.Int, e int) func(m *materiel, mj *modeleJeton) {
		return func(m *materiel, mj *modeleJeton) {
			c := m.unite(t, &rsa.PublicKey{N: n, E: e}, nil)
			mj.certs, mj.certESS = [][]byte{c}, c
		}
	}
	jouer(t, []cas{
		{nom: "unité RSA de 8200 bits", jeton: cle(moduleImpair(t, 8200), 65537), attendu: echec,
			verif: func(t *testing.T, r Resultat) {
				if !strings.Contains(r.Verifications[4].Detail.Fr, "clé RSA de 8200 bits, au-delà de 8192") {
					t.Errorf("T-5 : %s", r.Verifications[4].Detail.Fr)
				}
			}},
		{nom: "unité d'exposant 2³¹ + 1", jeton: cle(m.cleTSA.N, 1<<31+1), attendu: echec},
		{nom: "unité d'exposant pair", jeton: cle(m.cleTSA.N, 65536), attendu: echec},
	})
}

// TestEX924HorsVersion : clé de S d'un type que la version 0 ne vérifie pas
// (Ed25519), sous un algorithme qui ne l'est pas non plus (cas 2 et 3
// d'EX-9.24).
func TestEX924HorsVersion(t *testing.T) {
	m := mat(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	algoEd := algoDER(asn1.ObjectIdentifier{1, 3, 101, 112}, false)
	rattachee := func(m *materiel, mj *modeleJeton) {
		c := m.unite(t, pub, nil)
		mj.certs, mj.certESS = [][]byte{c}, c
		mj.sign = signeur{cle: priv, algo: algoEd, hash: crypto.SHA256}
	}
	nonRattachee := func(m *materiel, mj *modeleJeton) {
		c := m.unite(t, pub, func(c *modeleCert) {
			c.emetteur = m.tsa.sujet
			c.sign = signeurRSA(m.cleTSA)
		})
		mj.certs, mj.certESS = [][]byte{c}, c
		mj.sidEmetteur = m.tsa.sujet
		mj.sign = signeur{cle: priv, algo: algoEd, hash: crypto.SHA256}
	}
	sansAncres := func(*materiel, *ancres.Ancres) *ancres.Ancres { return nil }
	jouer(t, []cas{
		{nom: "cas 2, rattachement à l'autorité", jeton: rattachee,
			attendu: "re re re re ne:hp ne:hp ne:hp re re ne:hp ne:hp", verif: func(t *testing.T, r Resultat) {
				if r.Statut != commun.NonExecute || r.Raison != commun.HorsPerimetreVersion || r.Faits != nil || len(r.AncresEmployees) != 0 {
					t.Errorf("statut %s/%s, faits %v, ancres %v", r.Statut, r.Raison, r.Faits, r.AncresEmployees)
				}
				fr := "clé Ed25519 et algorithme 1.3.101.112 hors de la version 0 : signature du jeton non vérifiée ; certificat de l'unité rattaché à l'autorité AC de test CT-6 ; aucune date n'est établie"
				en := "Ed25519 key and algorithm 1.3.101.112 outside version 0: token signature not verified; unit certificate attached to authority AC de test CT-6; no time is established"
				if d := r.Verifications[4].Detail; d.Fr != fr || d.En != en {
					t.Errorf("détail de T-5 :\n%s\n%s", d.Fr, d.En)
				}
				if r.Resume.Fr != "signature hors de la version 0, non vérifiée : aucune date établie" || r.Resume.En != "signature outside version 0, not verified: no time established" {
					t.Errorf("résumé : %v", r.Resume)
				}
			}},
		{nom: "cas 2, sans rattachement (certificat auto-émis)", jeton: nonRattachee,
			attendu: "re re re re ec ne:pe ne:pe re re ne:pe ne:pe", verif: func(t *testing.T, r Resultat) {
				if r.Statut != commun.Echoue || !strings.Contains(r.Verifications[4].Detail.Fr, "EX-9.24, cas 2") {
					t.Errorf("T-5 : %s", r.Verifications[4].Detail.Fr)
				}
			}},
		{nom: "cas 2, rattachement refusé par la politique", jeton: rattachee,
			ancres: func(m *materiel, a *ancres.Ancres) *ancres.Ancres {
				a.Autorites[0].PolitiquesAdmises = []string{"1.2.3"}
				return a
			}, attendu: "re re re re ec ne:pe ne:pe re re ne:pe ne:pe"},
		{nom: "cas 3, sans fichier d'ancres", jeton: rattachee, ancres: sansAncres,
			attendu: "re re re re ne:aa ne:aa ne:aa re re ne:aa ne:aa", verif: func(t *testing.T, r Resultat) {
				if r.Statut != commun.NonExecute || r.Raison != commun.AncreAbsente {
					t.Errorf("statut %s/%s", r.Statut, r.Raison)
				}
			}},
		{nom: "Ed25519 sous sha256WithRSAEncryption (cas 1)", jeton: func(m *materiel, mj *modeleJeton) {
			rattachee(m, mj)
			mj.sigAlgo = algoDER(oidSHA256RSA, true)
		}, attendu: "re re re re ec ne:pe ne:pe re re ne:pe ne:pe"},
	})
	_ = m
}

// TestEX915NumeroDeSerie : serialNumber de plus de 160 bits, ou négatif :
// aucun effet sur T-9 (EX-9.15, révision 0.4), rapporté tel qu'encodé. Le
// binaire était déjà conforme ; ce test le fixe.
func TestEX915NumeroDeSerie(t *testing.T) {
	long := append([]byte{0x01}, []byte(strings.Repeat("\xab", 20))...)
	jouer(t, []cas{
		{nom: "numéro de 168 bits", jeton: func(m *materiel, mj *modeleJeton) { mj.serie = elem(casn1.INTEGER, long) }, attendu: tousReussis,
			verif: func(t *testing.T, r Resultat) {
				if r.Faits.SerialNumber != "0x01"+strings.Repeat("ab", 20) {
					t.Errorf("serial_number %s", r.Faits.SerialNumber)
				}
			}},
		{nom: "numéro négatif", jeton: func(m *materiel, mj *modeleJeton) { mj.serie = elem(casn1.INTEGER, []byte{0xff}) }, attendu: tousReussis},
	})
}

// TestEX924GenTimeIllisible : cas 2 d'EX-9.24 avec un genTime illisible :
// aucun rattachement (règle 4 d'EX-9.13), T-5 et T-9 en échec (point 25 des
// décisions).
func TestEX924GenTimeIllisible(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jouer(t, []cas{{nom: "Ed25519 rattachable, genTime illisible", jeton: func(m *materiel, mj *modeleJeton) {
		c := m.unite(t, pub, nil)
		mj.certs, mj.certESS = [][]byte{c}, c
		mj.sign = signeur{cle: priv, algo: algoDER(asn1.ObjectIdentifier{1, 3, 101, 112}, false), hash: crypto.SHA256}
		mj.genTime = "2026"
	}, attendu: "re re re re ec ne:pe ne:pe re ec ne:pe ne:pe"}})
}
