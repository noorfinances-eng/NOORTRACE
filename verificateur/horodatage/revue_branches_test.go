package horodatage

// Essais de la revue de sécurité interne de l'étape 8, suite : CT-6 EX-9.11
// (la vérification du sel vide compare bien H : une signature au sel vide
// d'un autre message, ou altérée, est refusée ; ce cas tue le mutant
// « comparaison de H toujours vraie » qui survivait) et N-1 (branches
// restantes de la lecture des paramètres RSASSA-PSS : OID d'empreinte
// inconnu de T-3, paramètres de MGF1 qui ne sont pas un AlgorithmIdentifier).

import (
	"crypto"
	"crypto/sha256"
	"encoding/asn1"
	"testing"
)

// TestPSSSelVideAutreMessage : CT-6 EX-9.11. verifierPSSSelVide n'accepte une
// signature au sel vide que sur le message qu'elle signe : la structure de
// EM (PS nul, 0x01, 0xbc) ne suffit pas, H est comparée.
func TestPSSSelVideAutreMessage(t *testing.T) {
	k := mat(t).cleAC
	h1 := sha256.Sum256([]byte("message signé"))
	h2 := sha256.Sum256([]byte("autre message"))
	sig := signerPSSSelVide(k, crypto.SHA256, h1[:])
	if !verifierPSSSelVide(&k.PublicKey, crypto.SHA256, h1[:], sig) {
		t.Fatal("signature au sel vide refusée sur son propre message")
	}
	if verifierPSSSelVide(&k.PublicKey, crypto.SHA256, h2[:], sig) {
		t.Fatal("signature au sel vide acceptée sur un autre message : H n'est pas comparée")
	}
	alteree := append([]byte{}, sig...)
	alteree[len(alteree)/2] ^= 0x01
	if verifierPSSSelVide(&k.PublicKey, crypto.SHA256, h1[:], alteree) {
		t.Fatal("signature altérée acceptée")
	}
	if verifierPSSSelVide(&k.PublicKey, crypto.SHA256, h1[:], sig[:len(sig)-1]) {
		t.Fatal("signature tronquée acceptée")
	}
}

// TestPSSParametresBranchesSupplement : CT-6 N-1. Branches de refus de la
// lecture des paramètres RSASSA-PSS que TestPSSParametresBranches ne
// déclenchait pas : hashAlgorithm d'un OID qu'aucune empreinte de T-3 ne
// porte (MD5 et SHA-1 sont connus, puis refusés par EX-9.11), MGF1 à
// paramètres qui ne sont pas un AlgorithmIdentifier, MGF1 sur un tel OID.
func TestPSSParametresBranchesSupplement(t *testing.T) {
	t5Echoue := "re re re re ec ne:pe ne:pe re re ne:pe ne:pe"
	oidInconnu := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 9, 9}
	hashA := func(h []byte) []byte { return elem(ctx(0, true), h) }
	mgf := func(h []byte) []byte { return elem(ctx(1, true), seq(oidDER(oidMGF1), h)) }
	tableau := []struct {
		nom    string
		params []byte
	}{
		{"hashAlgorithm d'OID inconnu", seq(oidDER(oidPSS), seq(hashA(algoDER(oidInconnu, true)), mgf(algoDER(oidInconnu, true))))},
		{"MGF1 à paramètres qui ne sont pas un AlgorithmIdentifier", seq(oidDER(oidPSS), seq(hashA(algoDER(oidSHA256, true)), elem(ctx(1, true), seq(oidDER(oidMGF1), oct([]byte{1})))))},
		{"MGF1 sur un OID d'empreinte inconnu", seq(oidDER(oidPSS), seq(hashA(algoDER(oidSHA256, true)), mgf(algoDER(oidInconnu, true))))},
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
