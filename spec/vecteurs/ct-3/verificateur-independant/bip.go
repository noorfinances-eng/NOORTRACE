// Dérivation des comptes de test (CT-3 annexe A.2 : « comptes 1 à 4 du
// mnémonique Hardhat (test test … junk, m/44'/60'/0'/0/i) ») : graine
// BIP-39 (PBKDF2-HMAC-SHA512, 2048 itérations, sel « mnemonic » sans phrase
// secrète) puis dérivation BIP-32 sur secp256k1. Le mnémonique est en ASCII :
// la normalisation NFKD de BIP-39 ne le change pas.

package main

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// GraineBIP39 rend la graine de 64 octets d'un mnémonique (phrase secrète
// vide).
func GraineBIP39(mnemonique string) ([]byte, error) {
	return pbkdf2.Key(sha512.New, mnemonique, []byte("mnemonic"), 2048, 64)
}

// cleCompressee rend la clé publique compressée (33 octets) d'une clé
// privée.
func cleCompressee(prive []byte) ([]byte, error) {
	pub, err := ClePublique(prive)
	if err != nil {
		return nil, err
	}
	pref := byte(0x02)
	if pub[63]&1 == 1 {
		pref = 0x03
	}
	return append([]byte{pref}, pub[:32]...), nil
}

// DeriverBIP32 dérive la clé privée du chemin donné (« m/44'/60'/0'/0/1 »)
// depuis une graine.
func DeriverBIP32(graine []byte, chemin string) ([]byte, error) {
	m := hmac.New(sha512.New, []byte("Bitcoin seed"))
	m.Write(graine)
	i := m.Sum(nil)
	cle, code := i[:32], i[32:]
	parties := strings.Split(chemin, "/")
	if len(parties) == 0 || parties[0] != "m" {
		return nil, fmt.Errorf("chemin %q : « m » attendu en tête", chemin)
	}
	for _, p := range parties[1:] {
		durci := strings.HasSuffix(p, "'")
		n, err := strconv.ParseUint(strings.TrimSuffix(p, "'"), 10, 31)
		if err != nil {
			return nil, fmt.Errorf("chemin %q : indice %q illisible", chemin, p)
		}
		idx := uint32(n)
		var donnees []byte
		if durci {
			idx |= 0x80000000
			donnees = append([]byte{0x00}, cle...)
		} else {
			pub, err := cleCompressee(cle)
			if err != nil {
				return nil, err
			}
			donnees = pub
		}
		donnees = binary.BigEndian.AppendUint32(donnees, idx)
		h := hmac.New(sha512.New, code)
		h.Write(donnees)
		i := h.Sum(nil)
		il := new(big.Int).SetBytes(i[:32])
		if il.Cmp(secpN) >= 0 {
			return nil, errors.New("dérivation BIP-32 : IL ≥ n")
		}
		k := new(big.Int).Add(il, new(big.Int).SetBytes(cle))
		k.Mod(k, secpN)
		if k.Sign() == 0 {
			return nil, errors.New("dérivation BIP-32 : clé nulle")
		}
		cle, code = octets32(k), i[32:]
	}
	return cle, nil
}
