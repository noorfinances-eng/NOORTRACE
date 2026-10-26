// Hachage SHA-256 à préfixe de domaine (CT-1 §6, §10.2), encodage
// hexadécimal 0x minuscule (§3), et vérification Ed25519 stricte (§6.2) :
// signature R || S avec S réduit modulo l'ordre du groupe, clé publique
// canonique et hors des points de petit ordre.

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
)

// Préfixes de domaine, octet par octet (CT-1 annexe B).
var (
	PrefixeEvenement          = []byte("noortrace/evenement/v0\n")
	PrefixeSignatureEvenement = []byte("noortrace/signature-evenement/v0\n")
	PrefixeManifeste          = []byte("noortrace/manifeste/v0\n")
	PrefixeSignatureManifeste = []byte("noortrace/signature-manifeste/v0\n")
	PrefixeApprobation        = []byte("noortrace/approbation/v0\n")
	PrefixeSignatureRotation  = []byte("noortrace/signature-rotation/v0\n")
	// Révision 0.3 (§10.6) : point de contrôle.
	PrefixePoint          = []byte("noortrace/point-de-controle/v0\n")
	PrefixeSignaturePoint = []byte("noortrace/signature-point-de-controle/v0\n")
)

// Préfixes de dérivation des clés et nonces de test (§13).
const (
	GraineCleEnregistreur = "noortrace/vecteurs/v0/cle-enregistreur/"
	GraineNonce           = "noortrace/vecteurs/v0/nonce/"
)

// Zero32 est la chaîne hexadécimale de 32 octets nuls.
const Zero32 = "0x0000000000000000000000000000000000000000000000000000000000000000"

var reHex = regexp.MustCompile(`^0x([0-9a-f][0-9a-f])*$`)

// SHA256Prefixe calcule SHA-256(prefixe || data).
func SHA256Prefixe(prefixe, data []byte) []byte {
	h := sha256.New()
	h.Write(prefixe)
	h.Write(data)
	return h.Sum(nil)
}

// SHA256 calcule SHA-256(data).
func SHA256(data []byte) []byte {
	s := sha256.Sum256(data)
	return s[:]
}

// Hex0x encode des octets en hexadécimal minuscule préfixé 0x.
func Hex0x(b []byte) string { return "0x" + hex.EncodeToString(b) }

// EstHex dit si s est de l'hexadécimal minuscule préfixé 0x de n octets
// (n < 0 : longueur quelconque, paire).
func EstHex(s string, n int) bool {
	if !reHex.MatchString(s) {
		return false
	}
	return n < 0 || len(s) == 2+2*n
}

// OctetsHex décode une chaîne hexadécimale 0x minuscule de n octets.
func OctetsHex(s string, n int) ([]byte, error) {
	if !EstHex(s, n) {
		if n >= 0 {
			return nil, fmt.Errorf("attendu %d octets en hexadécimal minuscule préfixé 0x, reçu %q", n, s)
		}
		return nil, fmt.Errorf("attendu de l'hexadécimal minuscule préfixé 0x, reçu %q", s)
	}
	return hex.DecodeString(s[2:])
}

// ordreEd25519 est L = 2^252 + 27742317777372353535851937790883648493.
var ordreEd25519, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)

// pEd25519 est 2^255 - 19.
var pEd25519 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

// dEd25519 est -121665/121666 mod p.
var dEd25519 = func() *big.Int {
	inv := new(big.Int).ModInverse(big.NewInt(121666), pEd25519)
	d := new(big.Int).Mul(big.NewInt(-121665), inv)
	return d.Mod(d, pEd25519)
}()

// Raisons de refus d'une signature ou d'une clé Ed25519.
var (
	ErrSignatureEd25519 = errors.New("signature Ed25519 invalide")
	ErrSNonReduit       = errors.New("signature Ed25519 refusée : S non réduit modulo l'ordre du groupe (RFC 8032 §5.1.7)")
	ErrClePetitOrdre    = errors.New("clé publique Ed25519 refusée : point de petit ordre")
	ErrCleNonCanonique  = errors.New("clé publique Ed25519 refusée : encodage non canonique (RFC 8032 §5.1.3)")
)

// VerifierEd25519 vérifie une signature Ed25519 pure (RFC 8032 §5.1) avec les
// refus imposés par CT-1 §6.2.
func VerifierEd25519(pub, msg, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("clé publique Ed25519 de %d octets, 32 attendus", len(pub))
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("signature Ed25519 de %d octets, 64 attendus", len(sig))
	}
	s := new(big.Int).SetBytes(inverser(sig[32:]))
	if s.Cmp(ordreEd25519) >= 0 {
		return ErrSNonReduit
	}
	if err := ControlerClePubliqueEd25519(pub); err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return ErrSignatureEd25519
	}
	return nil
}

// ControlerClePubliqueEd25519 décode la clé (RFC 8032 §5.1.3) et refuse un
// encodage non canonique ou un point de petit ordre ([8]A = identité).
func ControlerClePubliqueEd25519(pub []byte) error {
	x, y, err := decoderPointEd25519(pub)
	if err != nil {
		return err
	}
	for i := 0; i < 3; i++ {
		x, y = doublerEd25519(x, y)
	}
	if x.Sign() == 0 && y.Cmp(big.NewInt(1)) == 0 {
		return ErrClePetitOrdre
	}
	return nil
}

func inverser(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

func modP(z *big.Int) *big.Int { return z.Mod(z, pEd25519) }

// decoderPointEd25519 applique le décodage de la RFC 8032 §5.1.3.
func decoderPointEd25519(enc []byte) (*big.Int, *big.Int, error) {
	if len(enc) != 32 {
		return nil, nil, ErrCleNonCanonique
	}
	b := inverser(enc)
	signe := b[0] >> 7
	b[0] &= 0x7f
	y := new(big.Int).SetBytes(b)
	if y.Cmp(pEd25519) >= 0 {
		return nil, nil, ErrCleNonCanonique
	}
	y2 := modP(new(big.Int).Mul(y, y))
	u := modP(new(big.Int).Sub(y2, big.NewInt(1)))
	v := modP(new(big.Int).Add(new(big.Int).Mul(dEd25519, y2), big.NewInt(1)))
	// x = u v^3 (u v^7)^((p-5)/8)
	v3 := modP(new(big.Int).Mul(modP(new(big.Int).Mul(v, v)), v))
	v7 := modP(new(big.Int).Mul(modP(new(big.Int).Mul(v3, v3)), v))
	exp := new(big.Int).Div(new(big.Int).Sub(pEd25519, big.NewInt(5)), big.NewInt(8))
	x := modP(new(big.Int).Mul(modP(new(big.Int).Mul(u, v3)), new(big.Int).Exp(modP(new(big.Int).Mul(u, v7)), exp, pEd25519)))
	vx2 := modP(new(big.Int).Mul(v, modP(new(big.Int).Mul(x, x))))
	switch {
	case vx2.Cmp(u) == 0:
	case vx2.Cmp(modP(new(big.Int).Neg(u))) == 0:
		// x = x * 2^((p-1)/4)
		e := new(big.Int).Div(new(big.Int).Sub(pEd25519, big.NewInt(1)), big.NewInt(4))
		x = modP(new(big.Int).Mul(x, new(big.Int).Exp(big.NewInt(2), e, pEd25519)))
	default:
		return nil, nil, ErrCleNonCanonique
	}
	if x.Sign() == 0 && signe == 1 {
		return nil, nil, ErrCleNonCanonique
	}
	if byte(x.Bit(0)) != signe {
		x = modP(new(big.Int).Sub(pEd25519, x))
	}
	return x, y, nil
}

// doublerEd25519 double un point affine de la courbe tordue d'Edwards
// -x^2 + y^2 = 1 + d x^2 y^2.
func doublerEd25519(x, y *big.Int) (*big.Int, *big.Int) {
	x2 := modP(new(big.Int).Mul(x, x))
	y2 := modP(new(big.Int).Mul(y, y))
	dx2y2 := modP(new(big.Int).Mul(dEd25519, modP(new(big.Int).Mul(x2, y2))))
	num := modP(new(big.Int).Mul(big.NewInt(2), modP(new(big.Int).Mul(x, y))))
	den := modP(new(big.Int).Add(big.NewInt(1), dx2y2))
	x3 := modP(new(big.Int).Mul(num, new(big.Int).ModInverse(den, pEd25519)))
	num2 := modP(new(big.Int).Add(y2, x2))
	den2 := modP(new(big.Int).Sub(big.NewInt(1), dx2y2))
	y3 := modP(new(big.Int).Mul(num2, new(big.Int).ModInverse(den2, pEd25519)))
	return x3, y3
}

// ClePubliqueDepuisGraine dérive la clé publique Ed25519 d'une graine de 32
// octets (RFC 8032 §5.1.5).
func ClePubliqueDepuisGraine(graine []byte) []byte {
	priv := ed25519.NewKeyFromSeed(graine)
	return []byte(priv.Public().(ed25519.PublicKey))
}

// GraineCleTest rend la graine d'une clé d'enregistreur de test (§13).
func GraineCleTest(keyID string) []byte {
	return SHA256([]byte(GraineCleEnregistreur + keyID))
}

// NonceTest rend le nonce de test d'une période nommée (§13).
func NonceTest(nom string) []byte {
	return SHA256([]byte(GraineNonce + nom))
}
