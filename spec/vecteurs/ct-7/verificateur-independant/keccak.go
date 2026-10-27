// Copié sans modification de spec/vecteurs/ct-3/verificateur-independant/keccak.go
//
// Keccak-256 (variante héritée, remplissage 0x01, celle de l'EVM), employé
// là où CT-1 et CT-3 l'imposent : org_id = keccak256("assureur-demo"),
// journal_id = keccak256("journal-approbations") (CT-3 annexe A.2), adresse
// Ethereum d'une clé secp256k1 (20 derniers octets du keccak256 de la clé
// publique non compressée) et préfixe EIP-191 de la signature des
// approbateurs (CT-1 §6.3).
//
// Copié tel quel du vérificateur indépendant CT-1
// (spec/vecteurs/ct-1/verificateur-independant/keccak.go), que CT-3 EX-A.10
// permet de reprendre ; seule la fonction AnchorFingerprint, propre à CT-1,
// est retirée. crypto/sha3 de la bibliothèque standard n'expose que SHA3
// (remplissage 0x06) ; la permutation Keccak-f[1600] est donc écrite ici et
// confrontée à crypto/sha3 dans les tests.

package main

import "encoding/binary"

var constantesRondeKeccak = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
	0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

// decalagesRho[x][y] : décalages de rotation de l'étape rho.
var decalagesRho = [5][5]uint{
	{0, 36, 3, 41, 18},
	{1, 44, 10, 45, 2},
	{62, 6, 43, 15, 61},
	{28, 55, 25, 21, 56},
	{27, 20, 39, 8, 14},
}

func rotl64(v uint64, n uint) uint64 { return v<<n | v>>(64-n) }

// keccakF1600 applique les 24 rondes à l'état A[x + 5y].
func keccakF1600(a *[25]uint64) {
	for ronde := 0; ronde < 24; ronde++ {
		// theta
		var c [5]uint64
		for x := 0; x < 5; x++ {
			c[x] = a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20]
		}
		for x := 0; x < 5; x++ {
			d := c[(x+4)%5] ^ rotl64(c[(x+1)%5], 1)
			for y := 0; y < 5; y++ {
				a[x+5*y] ^= d
			}
		}
		// rho et pi : B[y, 2x + 3y] = rot(A[x, y], r[x, y])
		var b [25]uint64
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				b[y+5*((2*x+3*y)%5)] = rotl64(a[x+5*y], decalagesRho[x][y])
			}
		}
		// chi
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				a[x+5*y] = b[x+5*y] ^ (^b[(x+1)%5+5*y] & b[(x+2)%5+5*y])
			}
		}
		// iota
		a[0] ^= constantesRondeKeccak[ronde]
	}
}

// eponge256 absorbe data avec le débit de 1088 bits et l'octet de domaine
// donné (0x01 pour Keccak hérité, 0x06 pour SHA3-256) et presse 32 octets.
func eponge256(data []byte, domaine byte) []byte {
	const debit = 136
	var etat [25]uint64
	bloc := make([]byte, debit)
	absorber := func(b []byte) {
		for i := 0; i < debit/8; i++ {
			etat[i] ^= binary.LittleEndian.Uint64(b[8*i:])
		}
		keccakF1600(&etat)
	}
	for len(data) >= debit {
		absorber(data[:debit])
		data = data[debit:]
	}
	for i := range bloc {
		bloc[i] = 0
	}
	copy(bloc, data)
	bloc[len(data)] ^= domaine
	bloc[debit-1] ^= 0x80
	absorber(bloc)
	out := make([]byte, 32)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(out[8*i:], etat[i])
	}
	return out
}

// Keccak256 calcule le keccak256 hérité (EVM).
func Keccak256(data []byte) []byte { return eponge256(data, 0x01) }
