// Clés et signatures secp256k1 propres à CT-4 : formes des clés publiques des
// validateurs (65 octets non compressée, 64 octets X ‖ Y, 33 octets
// compressée, CT-6 EX-11.7 et EX-11.8), adresse d'une clé (CT-4 EX-6.15),
// hachage signé EIP-191 (CT-4 §6.6.3), forme canonique d'une signature
// (RG-12) et dérivation des comptes Hardhat (BIP-39 puis BIP-32, chemin
// m/44'/60'/0'/0/i, CT-4 EX-7.3 et A.2), écrite ici depuis les deux BIP.

package main

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// PrefixeEIP191 est "\x19Ethereum Signed Message:\n32" (28 octets, CT-4
// §6.6.3).
var PrefixeEIP191 = []byte("\x19Ethereum Signed Message:\n32")

// HachageSigne rend keccak256(P ‖ condensé interne) (CT-4 §6.6.3).
func HachageSigne(condense []byte) []byte { return Keccak256(concat(PrefixeEIP191, condense)) }

// ClePubliqueXY lit une clé publique secp256k1 sous l'une des trois formes
// admises par le schéma (pubKeyHex) et rend X ‖ Y (64 octets), après avoir
// vérifié que le point est sur la courbe.
func ClePubliqueXY(b []byte) ([]byte, error) {
	var x, y *big.Int
	switch {
	case len(b) == 65 && b[0] == 0x04:
		x = new(big.Int).SetBytes(b[1:33])
		y = new(big.Int).SetBytes(b[33:])
	case len(b) == 64:
		x = new(big.Int).SetBytes(b[:32])
		y = new(big.Int).SetBytes(b[32:])
	case len(b) == 33 && (b[0] == 0x02 || b[0] == 0x03):
		x = new(big.Int).SetBytes(b[1:])
		if x.Cmp(secpP) >= 0 {
			return nil, errors.New("abscisse hors du corps")
		}
		c := new(big.Int).Exp(x, big.NewInt(3), secpP)
		c.Add(c, secpSept)
		modP(c)
		exp := new(big.Int).Add(secpP, big.NewInt(1))
		exp.Rsh(exp, 2)
		y = new(big.Int).Exp(c, exp, secpP)
		if modP(new(big.Int).Mul(y, y)).Cmp(c) != 0 {
			return nil, errors.New("abscisse sans point sur la courbe")
		}
		if y.Bit(0) != uint(b[0]&1) {
			y.Sub(secpP, y)
		}
	default:
		return nil, fmt.Errorf("clé publique de %d octets : forme inconnue", len(b))
	}
	if x.Cmp(secpP) >= 0 || y.Cmp(secpP) >= 0 || !surLaCourbe(x, y) {
		return nil, errors.New("point hors de la courbe secp256k1")
	}
	return concat32(x, y), nil
}

// AdresseHex rend l'adresse (0x…, minuscules) d'une clé publique X ‖ Y.
func AdresseHex(xy []byte) string { return Hex0x(AdresseDeCle(xy)) }

// SignatureEVM est une signature (v, r, s) au sens de CT-4 EX-6.15.
type SignatureEVM struct {
	V    int
	R, S *big.Int
}

// LireSignature lit un objet { v, r, s } (et signer, s'il est présent).
func LireSignature(o *Value) (SignatureEVM, string, error) {
	var sig SignatureEVM
	if o == nil || o.Kind != KindObject {
		return sig, "", errors.New("signature : objet attendu")
	}
	v, err := EntierChamp(o, "v")
	if err != nil {
		return sig, "", err
	}
	if !v.IsInt64() || v.Int64() < -1<<31 || v.Int64() > 1<<31 {
		return sig, "", errors.New("v hors de toute borne")
	}
	sig.V = int(v.Int64())
	rs, err := Champ(o, "r")
	if err != nil {
		return sig, "", err
	}
	rb, err := DecoderHexN(rs, 32)
	if err != nil {
		return sig, "", err
	}
	ss, err := Champ(o, "s")
	if err != nil {
		return sig, "", err
	}
	sb, err := DecoderHexN(ss, 32)
	if err != nil {
		return sig, "", err
	}
	sig.R = new(big.Int).SetBytes(rb)
	sig.S = new(big.Int).SetBytes(sb)
	signer := ""
	if o.Has("signer") {
		signer, err = Champ(o, "signer")
		if err != nil {
			return sig, "", err
		}
	}
	return sig, signer, nil
}

// Canonique dit si la signature a la forme canonique de RG-12 : r dans
// [1, n − 1], s dans [1, n/2], v égal à 27 ou 28 (CT-4 EX-6.15).
func (s SignatureEVM) Canonique() bool {
	if s.V != 27 && s.V != 28 {
		return false
	}
	if s.R.Sign() <= 0 || s.R.Cmp(secpN) >= 0 {
		return false
	}
	return s.S.Sign() > 0 && s.S.Cmp(secpDemiN) <= 0
}

// Octets65 écrit la signature sur 65 octets r ‖ s ‖ u8(v) (CT-4 EX-6.15).
func (s SignatureEVM) Octets65() []byte {
	return concat(octets32(s.R), octets32(s.S), []byte{byte(s.V)})
}

// Recouvrir rend l'adresse recouvrée du hachage signé h, avec l'identifiant
// de récupération v − 27 (CT-4 EX-6.15).
func (s SignatureEVM) Recouvrir(h []byte) (string, error) {
	pub, err := Recouvrer(h, s.R, s.S, s.V-27)
	if err != nil {
		return "", err
	}
	return AdresseHex(pub), nil
}

// SignerEVM signe le hachage h par RFC 6979 et rend (v, r, s), v dans
// {27, 28}.
func SignerEVM(prive, h []byte) (SignatureEVM, error) {
	r, s, recid, err := SignerDeterministe(prive, h)
	if err != nil {
		return SignatureEVM{}, err
	}
	if recid > 1 {
		return SignatureEVM{}, errors.New("identifiant de récupération hors de {0, 1}")
	}
	return SignatureEVM{V: 27 + recid, R: r, S: s}, nil
}

// ------------------------------------------------------------ BIP-39, BIP-32

// GraineBIP39 rend la graine de 64 octets d'une phrase mnémonique sans
// phrase de passe (BIP-39 : PBKDF2-HMAC-SHA512, 2048 itérations, sel
// "mnemonic").
func GraineBIP39(phrase string) ([]byte, error) {
	return pbkdf2.Key(sha512.New, phrase, []byte("mnemonic"), 2048, 64)
}

// clePubliqueCompressee rend la clé publique compressée (33 octets).
func clePubliqueCompressee(prive []byte) ([]byte, error) {
	xy, err := ClePublique(prive)
	if err != nil {
		return nil, err
	}
	pre := byte(0x02)
	if xy[63]&1 == 1 {
		pre = 0x03
	}
	return append([]byte{pre}, xy[:32]...), nil
}

// DeriverBIP32 dérive la clé privée du chemin donné (« m/44'/60'/0'/0/1 »)
// depuis une graine (BIP-32, dérivation privée).
func DeriverBIP32(graine []byte, chemin string) ([]byte, error) {
	m := hmac.New(sha512.New, []byte("Bitcoin seed"))
	m.Write(graine)
	I := m.Sum(nil)
	cle, code := I[:32], I[32:]
	parts := strings.Split(chemin, "/")
	if len(parts) == 0 || parts[0] != "m" {
		return nil, fmt.Errorf("chemin %q : « m » attendu en tête", chemin)
	}
	for _, p := range parts[1:] {
		durci := strings.HasSuffix(p, "'")
		p = strings.TrimSuffix(p, "'")
		n, err := strconv.ParseUint(p, 10, 31)
		if err != nil {
			return nil, fmt.Errorf("chemin %q : indice %q", chemin, p)
		}
		idx := uint32(n)
		var donnees []byte
		if durci {
			idx |= 0x80000000
			donnees = append([]byte{0}, cle...)
		} else {
			pub, err := clePubliqueCompressee(cle)
			if err != nil {
				return nil, err
			}
			donnees = pub
		}
		var ib [4]byte
		binary.BigEndian.PutUint32(ib[:], idx)
		donnees = append(donnees, ib[:]...)
		h := hmac.New(sha512.New, code)
		h.Write(donnees)
		J := h.Sum(nil)
		il := new(big.Int).SetBytes(J[:32])
		if il.Cmp(secpN) >= 0 {
			return nil, errors.New("dérivation invalide (IL ≥ n)")
		}
		k := new(big.Int).Add(il, new(big.Int).SetBytes(cle))
		k.Mod(k, secpN)
		if k.Sign() == 0 {
			return nil, errors.New("dérivation invalide (clé nulle)")
		}
		cle, code = octets32(k), J[32:]
	}
	return cle, nil
}

// Sha256 rend SHA-256 de b.
func Sha256(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
