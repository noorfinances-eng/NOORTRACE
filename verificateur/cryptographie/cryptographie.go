// Paquet cryptographie : primitives employées par les contrôles de CT-1 et
// de CT-6 que ce paquet sert (SHA-256, Keccak-256, Ed25519 strict de CT-1
// §6.2, recouvrement EIP-191 de CT-1 §6.3, base64 canonique de CT-1 §3,
// arbres de Merkle de CT-1 §9 et §10.7, codage hexadécimal de CT-1 §3).
package cryptographie

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// Prefixes de domaine de CT-1 (annexe B) et de CT-7 §7.2.
var (
	PrefixeEvenement          = []byte("noortrace/evenement/v0\n")
	PrefixeSignatureEvenement = []byte("noortrace/signature-evenement/v0\n")
	PrefixeManifeste          = []byte("noortrace/manifeste/v0\n")
	PrefixeSignatureManifeste = []byte("noortrace/signature-manifeste/v0\n")
	PrefixeApprobation        = []byte("noortrace/approbation/v0\n")
	PrefixeRotation           = []byte("noortrace/signature-rotation/v0\n")
	PrefixePoint              = []byte("noortrace/point-de-controle/v0\n")
	PrefixeSignaturePoint     = []byte("noortrace/signature-point-de-controle/v0\n")
	PrefixeAttestation        = []byte("noortrace/attestation-perimetre/v0\n")
)

// Sha256 rend SHA-256 de la concaténation des morceaux.
func Sha256(morceaux ...[]byte) [32]byte {
	h := sha256.New()
	for _, m := range morceaux {
		h.Write(m)
	}
	var s [32]byte
	copy(s[:], h.Sum(nil))
	return s
}

// Hex écrit des octets en hexadécimal minuscule préfixé de « 0x » (CT-1 §3).
func Hex(b []byte) string { return "0x" + hex.EncodeToString(b) }

// Hex32 écrit 32 octets selon CT-1 §3.
func Hex32(b [32]byte) string { return Hex(b[:]) }

// LireHex lit « 0x » suivi d'hexadécimal minuscule de longueur n octets
// (n < 0 : toute longueur paire). Les majuscules sont refusées (CT-1 §3).
func LireHex(s string, n int) ([]byte, bool) {
	if !strings.HasPrefix(s, "0x") {
		return nil, false
	}
	h := s[2:]
	if n >= 0 && len(h) != 2*n {
		return nil, false
	}
	for _, c := range h {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return nil, false
		}
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, false
	}
	return b, true
}

// p = 2^255 - 19
var pEd25519 = func() *big.Int {
	p := new(big.Int).Lsh(big.NewInt(1), 255)
	return p.Sub(p, big.NewInt(19))
}()

// Les huit points de petit ordre (CT-1 annexe B), encodages canoniques.
var petitOrdre = []string{
	"0100000000000000000000000000000000000000000000000000000000000000",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0000000000000000000000000000000000000000000000000000000000000080",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
}

// ClePubliqueEd25519Admise dit si une clé publique Ed25519 de 32 octets est
// un encodage canonique (y < p, et pas de bit de signe sur x = 0) d'un point
// qui n'est pas de petit ordre (CT-1 §6.2).
func ClePubliqueEd25519Admise(a []byte) bool {
	if len(a) != 32 {
		return false
	}
	h := hex.EncodeToString(a)
	for _, p := range petitOrdre {
		if h == p {
			return false
		}
	}
	y := make([]byte, 32)
	for i := 0; i < 32; i++ {
		y[31-i] = a[i]
	}
	signe := y[0] >> 7
	y[0] &= 0x7f
	yy := new(big.Int).SetBytes(y)
	if yy.Cmp(pEd25519) >= 0 {
		return false
	}
	// x = 0 n'a lieu que pour y = 1 et y = p - 1 : le bit de signe 1 y est
	// interdit (RFC 8032 §5.1.3).
	pm1 := new(big.Int).Sub(pEd25519, big.NewInt(1))
	if signe == 1 && (yy.Cmp(big.NewInt(1)) == 0 || yy.Cmp(pm1) == 0) {
		return false
	}
	return true
}

// VerifierEd25519 vérifie une signature Ed25519 « pure » selon CT-1 §6.2 :
// équation sans cofacteur, `S` réduit, `R` et `A` canoniques, `A` hors des
// points de petit ordre. crypto/ed25519 de la bibliothèque standard applique
// l'équation sans cofacteur, refuse un `S` non réduit et compare l'encodage
// canonique de `R` ; la canonicité de `A` et le petit ordre sont contrôlés
// ici avant l'appel.
func VerifierEd25519(cle, message, signature []byte) bool {
	if len(signature) != 64 || !ClePubliqueEd25519Admise(cle) {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(cle), message, signature)
}

var demiOrdreSecp256k1 = func() *big.Int {
	n, _ := new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	return n.Rsh(n, 1)
}()

// ErrSignatureNonCanonique : signature secp256k1 refusée par CT-1 §6.3.
var ErrSignatureNonCanonique = errors.New("signature non canonique (s haut ou v hors de {27, 28})")

// MessageEIP191 rend keccak256("\x19Ethereum Signed Message:\n32" ‖ d).
func MessageEIP191(d [32]byte) [32]byte {
	return Keccak256([]byte("\x19Ethereum Signed Message:\n32"), d[:])
}

// RecouvrerEIP191 recouvre l'adresse (20 octets) qui a signé `d` (32
// octets) en EIP-191 (`personal_sign`), à partir d'une signature `r ‖ s ‖
// v` de 65 octets, `v` dans {27, 28} et `s` bas (CT-1 §6.3, CT-6 EX-14.2).
func RecouvrerEIP191(d [32]byte, sig []byte) ([20]byte, error) {
	var adresse [20]byte
	if len(sig) != 65 {
		return adresse, errors.New("signature EIP-191 de longueur différente de 65 octets")
	}
	v := sig[64]
	if v != 27 && v != 28 {
		return adresse, ErrSignatureNonCanonique
	}
	s := new(big.Int).SetBytes(sig[32:64])
	if s.Cmp(demiOrdreSecp256k1) > 0 {
		return adresse, ErrSignatureNonCanonique
	}
	m := MessageEIP191(d)
	compacte := make([]byte, 65)
	compacte[0] = 27 + (v - 27)
	copy(compacte[1:], sig[:64])
	cle, _, err := ecdsa.RecoverCompact(compacte, m[:])
	if err != nil {
		return adresse, err
	}
	return AdresseDeCle(cle), nil
}

// AdresseDeCle rend l'adresse Ethereum d'une clé publique secp256k1.
func AdresseDeCle(cle *secp256k1.PublicKey) [20]byte {
	nc := cle.SerializeUncompressed()
	h := Keccak256(nc[1:])
	var a [20]byte
	copy(a[:], h[12:])
	return a
}

// LireCleSecp256k1 lit une clé publique secp256k1 (33 octets compressée ou
// 65 octets non compressée) et vérifie qu'elle est sur la courbe.
func LireCleSecp256k1(b []byte) (*secp256k1.PublicKey, error) {
	if len(b) != 33 && len(b) != 65 {
		return nil, errors.New("clé secp256k1 ni de 33 ni de 65 octets")
	}
	return secp256k1.ParsePubKey(b)
}

// Base64Canonique décode une chaîne base64 de la RFC 4648 §4 (alphabet
// standard, remplissage « = » exact, aucun saut de ligne) et exige que le
// réencodage des octets décodés redonne la chaîne (bits de bourrage nuls ;
// CT-1 §3, CT-6 EX-4.14).
func Base64Canonique(s string) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, errors.New("base64 illisible")
	}
	if base64.StdEncoding.EncodeToString(b) != s {
		return nil, errors.New("base64 non canonique")
	}
	return b, nil
}

// FeuilleMerkle rend L = SHA-256(0x00 ‖ d) (CT-1 §9.1).
func FeuilleMerkle(d []byte) [32]byte { return Sha256([]byte{0}, d) }

func noeud(g, d []byte) []byte {
	h := Sha256([]byte{1}, g, d)
	return h[:]
}

// VerifierInclusion applique l'algorithme de CT-1 §9.3 (RFC 9162 §2.1.3.2).
func VerifierInclusion(feuille []byte, m, n uint64, chemin [][]byte, racine []byte) bool {
	if m >= n {
		return false
	}
	fn, sn := m, n-1
	r := feuille
	for _, h := range chemin {
		if sn == 0 {
			return false
		}
		if fn%2 == 1 || fn == sn {
			r = noeud(h, r)
			for fn%2 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = noeud(r, h)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && bytes.Equal(r, racine)
}

// VerifierCoherence applique l'algorithme de CT-1 §10.7 (RFC 9162
// §2.1.4.2).
func VerifierCoherence(m, n uint64, premiere, seconde []byte, chemin [][]byte) bool {
	if m == 0 || n < m {
		return false
	}
	if m == n {
		return len(chemin) == 0 && bytes.Equal(premiere, seconde)
	}
	if len(chemin) == 0 {
		return false
	}
	p := chemin
	if m&(m-1) == 0 {
		p = append([][]byte{premiere}, chemin...)
	}
	fn, sn := m-1, n-1
	for fn%2 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := p[0], p[0]
	for _, h := range p[1:] {
		if sn == 0 {
			return false
		}
		if fn%2 == 1 || fn == sn {
			fr = noeud(h, fr)
			sr = noeud(h, sr)
			for fn%2 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = noeud(sr, h)
		}
		fn >>= 1
		sn >>= 1
	}
	return bytes.Equal(fr, premiere) && bytes.Equal(sr, seconde) && sn == 0
}
