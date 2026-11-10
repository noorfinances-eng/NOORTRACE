package horodatage

// Règles de la révision 0.5 de CT-6 propres au contrôle 4 : la lecture selon
// §9.3 (EX-9.4, EX-9.7) d'un certificat comprend son SubjectPublicKeyInfo (et,
// pour rsaEncryption, la RSAPublicKey de la BIT STRING) et les valeurs des
// extensions basicConstraints, keyUsage, extKeyUsage et subjectKeyIdentifier :
// une longueur non minimale ou une structure fausse met T-1 en échec, non T-5
// ni T-8. Vecteurs de l'annexe A.3 : tsa-cle-longueur-non-minimale.pem,
// tsa-extension-mal-formee.pem et les jetons t1-* qui les portent.

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/noorfinances-eng/noortrace/verificateur/commun"
)

func TestRevision05CertificatIllisible(t *testing.T) {
	dir := filepath.Join(racineCT6, "rfc3161")
	for _, c := range []struct{ fichier, motif string }{
		{"cles/tsa-cle-longueur-non-minimale.pem", "RSAPublicKey"},
		{"cles/tsa-extension-mal-formee.pem", "valeur de l'extension 2.5.29.15"},
	} {
		der := lirePEM(t, filepath.Join(dir, c.fichier))
		_, d := lireCertificat(der)
		if d == nil {
			t.Fatalf("%s : lu, refus attendu (%s)", c.fichier, c.motif)
		}
		if !strings.Contains(d.fr, c.motif) {
			t.Errorf("%s : %q, %q attendu", c.fichier, d.fr, c.motif)
		}
		// Le fichier d'ancres le refuse aussi (N-1, EX-12.2).
		if err := controlerCertificat(der); err == nil {
			t.Errorf("%s : admis comme ancre", c.fichier)
		}
	}
	// Le certificat de l'unité de test, lu comme avant.
	if _, d := lireCertificat(lirePEM(t, filepath.Join(dir, "cles/tsa-test.pem"))); d != nil {
		t.Fatal(d.fr)
	}
}

func TestRevision05JetonT1(t *testing.T) {
	m := mat(t)
	for _, f := range []string{"t1-cle-longueur-non-minimale.der", "t1-extension-mal-formee.der"} {
		b := lire(t, filepath.Join(racineCT6, "rfc3161", "jetons", f))
		if _, d := lireJeton(b); d == nil {
			t.Fatalf("%s : lu, T-1 en échec attendu", f)
		}
		r := Verifier(m.entree(t, b, m.ancresTest()))
		if got := abrege(r); got != "ec ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe ne:pe" {
			t.Fatalf("%s : %s", f, got)
		}
		if r.Statut != commun.Echoue {
			t.Errorf("%s : contrôle %s", f, r.Statut)
		}
	}
}
