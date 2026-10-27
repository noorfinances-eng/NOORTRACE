// Dérivation des comptes de test : les vecteurs de CT-7 signent avec les
// comptes Hardhat du mnémonique public de spec/vecteurs/ct-3/constantes.json,
// chemin m/44'/60'/0'/0/i (CT-7 EX-A.1, EX-4.10). Graine BIP-39 :
// PBKDF2-HMAC-SHA512(mnémonique, "mnemonic", 2048 itérations, 64 octets) ;
// dérivation BIP-32 : clé maîtresse HMAC-SHA512("Bitcoin seed", graine),
// enfant durci sur 0x00 ‖ k ‖ i, enfant normal sur la clé publique
// compressée ‖ i, k_i = IL + k mod n. Ces clés sont publiques et sans
// valeur ; elles ne servent qu'à reproduire les signatures déterministes des
// vecteurs et à recalculer cles-de-test.json.

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

// GraineBIP39 rend la graine de 64 octets d'un mnémonique ASCII (la
// normalisation NFKD est sans effet sur un texte ASCII).
func GraineBIP39(mnemonique, phrase string) ([]byte, error) {
	for _, r := range mnemonique + phrase {
		if r > 0x7F {
			return nil, errors.New("mnémonique non ASCII : normalisation NFKD non prise en charge")
		}
	}
	return pbkdf2.Key(sha512.New, mnemonique, []byte("mnemonic"+phrase), 2048, 64)
}

// compressee rend la clé publique compressée (33 octets) d'une clé privée.
func compressee(prive []byte) ([]byte, error) {
	xy, err := ClePublique(prive)
	if err != nil {
		return nil, err
	}
	pref := byte(0x02)
	if xy[63]&1 == 1 {
		pref = 0x03
	}
	return append([]byte{pref}, xy[:32]...), nil
}

// DeriverChemin rend la clé privée au chemin donné (« m/44'/60'/0'/0/1 »).
func DeriverChemin(graine []byte, chemin string) ([]byte, error) {
	mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	mac.Write(graine)
	i := mac.Sum(nil)
	k, c := i[:32], i[32:]
	parts := strings.Split(chemin, "/")
	if len(parts) == 0 || parts[0] != "m" {
		return nil, fmt.Errorf("chemin %q : « m » attendu en tête", chemin)
	}
	for _, p := range parts[1:] {
		durci := strings.HasSuffix(p, "'")
		n, err := strconv.ParseUint(strings.TrimSuffix(p, "'"), 10, 31)
		if err != nil {
			return nil, fmt.Errorf("chemin %q : indice %q", chemin, p)
		}
		idx := uint32(n)
		var data []byte
		if durci {
			idx |= 0x80000000
			data = append([]byte{0x00}, k...)
		} else {
			pub, err := compressee(k)
			if err != nil {
				return nil, err
			}
			data = pub
		}
		data = binary.BigEndian.AppendUint32(data, idx)
		mac := hmac.New(sha512.New, c)
		mac.Write(data)
		i := mac.Sum(nil)
		il := new(big.Int).SetBytes(i[:32])
		if il.Cmp(secpN) >= 0 {
			return nil, errors.New("IL ≥ n : indice à sauter (BIP-32)")
		}
		ki := new(big.Int).Add(il, new(big.Int).SetBytes(k))
		ki.Mod(ki, secpN)
		if ki.Sign() == 0 {
			return nil, errors.New("clé enfant nulle (BIP-32)")
		}
		k, c = octets32(ki), i[32:]
	}
	return k, nil
}

// Comptes rend les clés privées des comptes m/44'/60'/0'/0/i, i de 0 à n−1.
func Comptes(mnemonique string, n int) ([][]byte, error) {
	graine, err := GraineBIP39(mnemonique, "")
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for i := 0; i < n; i++ {
		k, err := DeriverChemin(graine, fmt.Sprintf("m/44'/60'/0'/0/%d", i))
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}
