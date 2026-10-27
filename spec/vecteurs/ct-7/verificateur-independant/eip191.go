// Signature EIP-191 (personal_sign, version 0x45) de CT-1 §6.3, que CT-7
// reprend pour le procès-verbal (EX-5.7, D_C à la place de D_A) et pour
// l'attestation (EX-7.6, D_P) : M = keccak256("\x19Ethereum Signed
// Message:\n32" ‖ D), signature r (32) ‖ s (32) ‖ v (1), v ∈ {27, 28}.
// Le texte d'inscription de CT-3, signé avec sa longueur décimale dans le
// préfixe (CT-7 EX-5.7, table d'EX-7.7), sert aux signatures croisées.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Hex0x rend des octets en hexadécimal minuscule préfixé de 0x (CT-1 §3).
func Hex0x(b []byte) string { return "0x" + hex.EncodeToString(b) }

// OctetsHex décode une chaîne 0x… en hexadécimal minuscule (CT-1 §3 refuse
// les majuscules) ; n > 0 impose la longueur en octets.
func OctetsHex(s string, n int) ([]byte, error) {
	if !strings.HasPrefix(s, "0x") {
		return nil, errors.New("préfixe 0x absent")
	}
	corps := s[2:]
	if corps != strings.ToLower(corps) {
		return nil, errors.New("hexadécimal en majuscules")
	}
	b, err := hex.DecodeString(corps)
	if err != nil {
		return nil, err
	}
	if n > 0 && len(b) != n {
		return nil, fmt.Errorf("%d octets, %d attendus", len(b), n)
	}
	return b, nil
}

// SHA256 rend le SHA-256 des octets.
func SHA256(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// MessageEIP191 rend M = keccak256("\x19Ethereum Signed Message:\n32" ‖ d)
// pour un condensé de 32 octets (CT-1 §6.3).
func MessageEIP191(d []byte) []byte {
	return Keccak256(append([]byte("\x19Ethereum Signed Message:\n32"), d...))
}

// MessageEIP191Texte rend M pour un message texte : sa longueur en octets,
// écrite en décimal, entre dans le préfixe (EIP-191 version 0x45).
func MessageEIP191Texte(t string) []byte {
	return Keccak256([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(t), t)))
}

// SignatureEIP191 est une signature décodée r ‖ s ‖ v.
type SignatureEIP191 struct {
	R, S *big.Int
	V    int
}

// DecoderSignatureEIP191 décode une signature et dit si elle est canonique
// au sens de CT-1 §6.3 et de CR-11 : 65 octets, v ∈ {27, 28}, r et s dans
// [1, n − 1], s ≤ ⌊n/2⌋. Une signature non canonique n'est jamais recouvrée.
func DecoderSignatureEIP191(hexsig string) (SignatureEIP191, error) {
	b, err := OctetsHex(hexsig, 0)
	if err != nil {
		return SignatureEIP191{}, err
	}
	if len(b) != 65 {
		return SignatureEIP191{}, fmt.Errorf("signature de %d octets, 65 attendus", len(b))
	}
	s := SignatureEIP191{R: new(big.Int).SetBytes(b[:32]), S: new(big.Int).SetBytes(b[32:64]), V: int(b[64])}
	switch {
	case s.V != 27 && s.V != 28:
		return s, fmt.Errorf("v = %d hors de {27, 28}", s.V)
	case s.R.Sign() <= 0 || s.R.Cmp(secpN) >= 0:
		return s, errors.New("r hors de [1, n − 1]")
	case s.S.Sign() <= 0 || s.S.Cmp(secpN) >= 0:
		return s, errors.New("s hors de [1, n − 1]")
	case s.S.Cmp(secpDemiN) > 0:
		return s, errors.New("s dans la moitié haute de l'ordre")
	}
	return s, nil
}

// RecouvrerAdresse rend l'adresse (0x…, 20 octets) qui a produit une
// signature canonique sur M ; une signature non canonique est refusée avant
// tout recouvrement.
func RecouvrerAdresse(m []byte, hexsig string) (string, error) {
	s, err := DecoderSignatureEIP191(hexsig)
	if err != nil {
		return "", err
	}
	pub, err := Recouvrer(m, s.R, s.S, s.V-27)
	if err != nil {
		return "", err
	}
	return Hex0x(AdresseDeCle(pub)), nil
}

// RecouvrerSansForme recouvre l'adresse d'une signature de 65 octets sans
// exiger la forme canonique (v de 27 ou 28 seulement) ; pour les sondes des
// signatures croisées, dont l'attendu donne l'adresse recouvrée.
func RecouvrerSansForme(m []byte, hexsig string) (string, error) {
	b, err := OctetsHex(hexsig, 65)
	if err != nil {
		return "", err
	}
	v := int(b[64])
	if v != 27 && v != 28 {
		return "", fmt.Errorf("v = %d hors de {27, 28}", v)
	}
	pub, err := Recouvrer(m, new(big.Int).SetBytes(b[:32]), new(big.Int).SetBytes(b[32:64]), v-27)
	if err != nil {
		return "", err
	}
	return Hex0x(AdresseDeCle(pub)), nil
}

// Signer produit la signature canonique déterministe (RFC 6979) d'une clé
// privée sur M ; elle sert à reproduire les signatures des vecteurs, que
// CT-7 annonce produites par RFC 6979 (A.1, 7.2).
func Signer(prive, m []byte) (string, error) {
	r, s, recid, err := SignerDeterministe(prive, m)
	if err != nil {
		return "", err
	}
	if recid > 1 {
		return "", errors.New("indice de recouvrement hors de {0, 1}")
	}
	b := append(octets32(r), octets32(s)...)
	b = append(b, byte(27+recid))
	return Hex0x(b), nil
}

// ClePubliqueNonCompressee rend 0x04 ‖ X ‖ Y (65 octets, CT-7 §5.6).
func ClePubliqueNonCompressee(prive []byte) ([]byte, error) {
	xy, err := ClePublique(prive)
	if err != nil {
		return nil, err
	}
	return append([]byte{0x04}, xy...), nil
}

// AdresseDeCleNonCompressee rend l'adresse d'une clé publique 0x04 ‖ X ‖ Y
// après avoir vérifié que le point est sur la courbe (CR-5).
func AdresseDeCleNonCompressee(pub []byte) (string, error) {
	if len(pub) != 65 || pub[0] != 0x04 {
		return "", errors.New("clé secp256k1 non compressée de 65 octets attendue (0x04 ‖ X ‖ Y)")
	}
	x := new(big.Int).SetBytes(pub[1:33])
	y := new(big.Int).SetBytes(pub[33:])
	if x.Cmp(secpP) >= 0 || y.Cmp(secpP) >= 0 || !surLaCourbe(x, y) {
		return "", errors.New("point hors de la courbe secp256k1")
	}
	return Hex0x(AdresseDeCle(pub[1:])), nil
}
