package cryptographie

import "math/bits"

// Keccak-256 « d'origine » (celui de l'EVM, bourrage 0x01…0x80), écrit
// d'après la spécification de Keccak (permutation Keccak-f[1600], 24 tours).
//
// Pourquoi pas golang.org/x/crypto/sha3 : dans x/crypto v0.58.0,
// sha3.NewLegacyKeccak256 importe golang.org/x/sys/cpu, ce qui ajouterait
// golang.org/x/sys v0.49.0 aux dépendances et deux lignes à go.sum, contre
// la liste fermée de CT-6 EX-14.1 (voir LISEZMOI.md, « Lectures »). La
// fonction est contrôlée par les vecteurs publics (chaîne vide, adresses des
// comptes de test, empreintes de CT-1 et de CT-6).

var constantesTour = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
	0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

// Décalages de rotation r[x][y] de Keccak.
var rotations = [5][5]int{
	{0, 36, 3, 41, 18},
	{1, 44, 10, 45, 2},
	{62, 6, 43, 15, 61},
	{28, 55, 25, 21, 56},
	{27, 20, 39, 8, 14},
}

func keccakF(a *[25]uint64) {
	var c, d [5]uint64
	var b [25]uint64
	for tour := 0; tour < 24; tour++ {
		// θ
		for x := 0; x < 5; x++ {
			c[x] = a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20]
		}
		for x := 0; x < 5; x++ {
			d[x] = c[(x+4)%5] ^ bits.RotateLeft64(c[(x+1)%5], 1)
		}
		for i := 0; i < 25; i++ {
			a[i] ^= d[i%5]
		}
		// ρ et π
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				b[y+5*((2*x+3*y)%5)] = bits.RotateLeft64(a[x+5*y], rotations[x][y])
			}
		}
		// χ
		for y := 0; y < 5; y++ {
			for x := 0; x < 5; x++ {
				a[x+5*y] = b[x+5*y] ^ (^b[(x+1)%5+5*y] & b[(x+2)%5+5*y])
			}
		}
		// ι
		a[0] ^= constantesTour[tour]
	}
}

// Keccak256 rend keccak256 de la concaténation des morceaux.
func Keccak256(morceaux ...[]byte) [32]byte {
	const taux = 136
	var etat [25]uint64
	var bloc []byte
	for _, m := range morceaux {
		bloc = append(bloc, m...)
	}
	absorber := func(p []byte) {
		for i := 0; i < taux/8; i++ {
			var w uint64
			for k := 0; k < 8; k++ {
				w |= uint64(p[8*i+k]) << (8 * k)
			}
			etat[i] ^= w
		}
		keccakF(&etat)
	}
	for len(bloc) >= taux {
		absorber(bloc[:taux])
		bloc = bloc[taux:]
	}
	dernier := make([]byte, taux)
	copy(dernier, bloc)
	dernier[len(bloc)] ^= 0x01
	dernier[taux-1] ^= 0x80
	absorber(dernier)
	var sortie [32]byte
	for i := 0; i < 4; i++ {
		for k := 0; k < 8; k++ {
			sortie[8*i+k] = byte(etat[i] >> (8 * k))
		}
	}
	return sortie
}
