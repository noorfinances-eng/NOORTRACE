// scrypt (RFC 7914) pour le fichier de clé chiffré du parcours d (CT-3
// EX-13.28) : la bibliothèque standard de Go n'en a pas. Écrit ici :
// Salsa20/8 (RFC 7914 §3), BlockMix (§4), ROMix (§5), puis
// scrypt(P, S, N, r, p, dkLen) = PBKDF2-HMAC-SHA256(P, B, 1, dkLen) avec
// B = PBKDF2-HMAC-SHA256(P, S, 1, p · 128 · r) mélangé bloc par bloc (§6).
// Les bornes d'EX-13.28 (n ≤ 2^18, r ≤ 8, p ≤ 4) sont contrôlées avant
// l'appel.

package main

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/bits"
)

// salsa208 applique Salsa20/8 au bloc de 16 mots (RFC 7914 §3).
func salsa208(b *[16]uint32) {
	x := *b
	for i := 0; i < 8; i += 2 {
		x[4] ^= bits.RotateLeft32(x[0]+x[12], 7)
		x[8] ^= bits.RotateLeft32(x[4]+x[0], 9)
		x[12] ^= bits.RotateLeft32(x[8]+x[4], 13)
		x[0] ^= bits.RotateLeft32(x[12]+x[8], 18)
		x[9] ^= bits.RotateLeft32(x[5]+x[1], 7)
		x[13] ^= bits.RotateLeft32(x[9]+x[5], 9)
		x[1] ^= bits.RotateLeft32(x[13]+x[9], 13)
		x[5] ^= bits.RotateLeft32(x[1]+x[13], 18)
		x[14] ^= bits.RotateLeft32(x[10]+x[6], 7)
		x[2] ^= bits.RotateLeft32(x[14]+x[10], 9)
		x[6] ^= bits.RotateLeft32(x[2]+x[14], 13)
		x[10] ^= bits.RotateLeft32(x[6]+x[2], 18)
		x[3] ^= bits.RotateLeft32(x[15]+x[11], 7)
		x[7] ^= bits.RotateLeft32(x[3]+x[15], 9)
		x[11] ^= bits.RotateLeft32(x[7]+x[3], 13)
		x[15] ^= bits.RotateLeft32(x[11]+x[7], 18)
		x[1] ^= bits.RotateLeft32(x[0]+x[3], 7)
		x[2] ^= bits.RotateLeft32(x[1]+x[0], 9)
		x[3] ^= bits.RotateLeft32(x[2]+x[1], 13)
		x[0] ^= bits.RotateLeft32(x[3]+x[2], 18)
		x[6] ^= bits.RotateLeft32(x[5]+x[4], 7)
		x[7] ^= bits.RotateLeft32(x[6]+x[5], 9)
		x[4] ^= bits.RotateLeft32(x[7]+x[6], 13)
		x[5] ^= bits.RotateLeft32(x[4]+x[7], 18)
		x[11] ^= bits.RotateLeft32(x[10]+x[9], 7)
		x[8] ^= bits.RotateLeft32(x[11]+x[10], 9)
		x[9] ^= bits.RotateLeft32(x[8]+x[11], 13)
		x[10] ^= bits.RotateLeft32(x[9]+x[8], 18)
		x[12] ^= bits.RotateLeft32(x[15]+x[14], 7)
		x[13] ^= bits.RotateLeft32(x[12]+x[15], 9)
		x[14] ^= bits.RotateLeft32(x[13]+x[12], 13)
		x[15] ^= bits.RotateLeft32(x[14]+x[13], 18)
	}
	for i := range b {
		b[i] += x[i]
	}
}

// blockMix applique scryptBlockMix (RFC 7914 §4) à b (2r blocs de 16
// mots), résultat dans y.
func blockMix(b, y []uint32, r int) {
	var x [16]uint32
	copy(x[:], b[(2*r-1)*16:])
	for i := 0; i < 2*r; i++ {
		for j := 0; j < 16; j++ {
			x[j] ^= b[i*16+j]
		}
		salsa208(&x)
		// Y_i rangé aux positions paires puis impaires.
		dst := (i/2)*16 + (i%2)*r*16
		copy(y[dst:dst+16], x[:])
	}
}

// roMix applique scryptROMix (RFC 7914 §5) au bloc de 128·r octets.
func roMix(blk []byte, n, r int) {
	l := 32 * r
	x := make([]uint32, l)
	for i := range x {
		x[i] = binary.LittleEndian.Uint32(blk[4*i:])
	}
	v := make([]uint32, n*l)
	y := make([]uint32, l)
	for i := 0; i < n; i++ {
		copy(v[i*l:], x)
		blockMix(x, y, r)
		x, y = y, x
	}
	for i := 0; i < n; i++ {
		j := int(x[(2*r-1)*16] & uint32(n-1))
		for k := 0; k < l; k++ {
			x[k] ^= v[j*l+k]
		}
		blockMix(x, y, r)
		x, y = y, x
	}
	for i := range x {
		binary.LittleEndian.PutUint32(blk[4*i:], x[i])
	}
}

// Scrypt dérive dkLen octets du mot de passe et du sel (RFC 7914 §6) ; n
// doit être une puissance de 2 supérieure à 1.
func Scrypt(motDePasse string, sel []byte, n, r, p, dkLen int) ([]byte, error) {
	if n < 2 || n&(n-1) != 0 || r < 1 || p < 1 {
		return nil, errors.New("paramètres scrypt hors domaine")
	}
	b, err := pbkdf2.Key(sha256.New, motDePasse, sel, 1, p*128*r)
	if err != nil {
		return nil, err
	}
	for i := 0; i < p; i++ {
		roMix(b[i*128*r:(i+1)*128*r], n, r)
	}
	return pbkdf2.Key(sha256.New, motDePasse, b, 1, dkLen)
}
