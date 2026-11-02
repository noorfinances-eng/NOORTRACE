package ots

// Constructeurs de preuves .ots et de chaînes d'en-têtes regtest
// synthétiques pour les tests.

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/noorfinances-eng/noortrace/verificateur/ancres"
	"github.com/noorfinances-eng/noortrace/verificateur/entree"
)

// enc concatène des morceaux d'octets.
func enc(morceaux ...[]byte) []byte {
	var r []byte
	for _, m := range morceaux {
		r = append(r, m...)
	}
	return r
}

// varuintTest encode n en LEB128 minimal.
func varuintTest(n uint64) []byte {
	var r []byte
	for {
		c := byte(n & 0x7f)
		n >>= 7
		if n == 0 {
			return append(r, c)
		}
		r = append(r, c|0x80)
	}
}

func vb(b []byte) []byte { return enc(varuintTest(uint64(len(b))), b) }

// fichierOTS : en-tête magique, version 01, opération 08, empreinte, arbre.
func fichierOTS(empreinte [32]byte, arbre ...[]byte) []byte {
	return enc(enteteMagique, []byte{0x01, 0x08}, empreinte[:], enc(arbre...))
}

func attBitcoin(h uint64) []byte {
	return enc([]byte{0x00}, etiquetteBitcoin[:], vb(varuintTest(h)))
}

func attAttente(uri string) []byte {
	return enc([]byte{0x00}, etiquetteAttente[:], vb(vb([]byte(uri))))
}

func attInconnue(tag [8]byte, charge []byte) []byte {
	return enc([]byte{0x00}, tag[:], vb(charge))
}

func opAp(arg []byte) []byte  { return enc([]byte{opAppend}, vb(arg)) }
func opPre(arg []byte) []byte { return enc([]byte{opPrepend}, vb(arg)) }
func opSHA() []byte           { return []byte{opSHA256} }
func fourche() []byte         { return []byte{marqueBranche} }

// spécifications d'un en-tête synthétique.
type specEntete struct {
	racine [32]byte
	nTime  uint32
	nBits  uint32
	// sansTravail : le nNonce est choisi pour ne pas satisfaire la cible.
	sansTravail bool
	// prev : remplace hashPrevBlock quand non nil.
	prev *[32]byte
}

// cibleDe rend la cible de nBits, pour miner.
func cibleDe(nbits uint32) *big.Int {
	n, _, _ := SetCompact(nbits)
	return n
}

func satisfait(h []byte, cible *big.Int) bool {
	d := inverse(dSHA(h))
	return new(big.Int).SetBytes(d[:]).Cmp(cible) <= 0
}

// chaineRegtest mine des en-têtes contigus de hauteur debut à debut+n-1 ;
// spec(i) fixe la racine, l'heure, nBits et les défauts de l'en-tête i.
func chaineRegtest(t *testing.T, reseau string, debut uint32, n int, spec func(i uint64) specEntete) *ancres.Entetes {
	t.Helper()
	e := &ancres.Entetes{Reseau: reseau, Debut: debut}
	var precedent [32]byte
	for k := 0; k < n; k++ {
		i := uint64(debut) + uint64(k)
		s := spec(i)
		var h [80]byte
		binary.LittleEndian.PutUint32(h[0:4], 0x20000000)
		if k > 0 {
			copy(h[4:36], precedent[:])
		}
		if s.prev != nil {
			copy(h[4:36], s.prev[:])
		}
		copy(h[36:68], s.racine[:])
		binary.LittleEndian.PutUint32(h[68:72], s.nTime)
		binary.LittleEndian.PutUint32(h[72:76], s.nBits)
		cible := cibleDe(s.nBits)
		trouve := false
		for nonce := uint32(0); nonce < 1<<20; nonce++ {
			binary.LittleEndian.PutUint32(h[76:80], nonce)
			if satisfait(h[:], cible) != s.sansTravail {
				trouve = true
				break
			}
		}
		if !trouve {
			t.Fatalf("aucun nNonce pour l'en-tête %d", i)
		}
		e.Entetes = append(e.Entetes, h)
		precedent = dSHA(h[:])
	}
	return e
}

// racineSynthetique : racine des en-têtes non attestés.
func racineSynthetique(i uint64) [32]byte {
	return sha256.Sum256(binary.BigEndian.AppendUint64([]byte("racine/"), i))
}

// scenario : une preuve de la période synthétique, attestée en 1001, et une
// chaîne regtest de 990 à 1020 dont la racine 1001 porte son résultat.
type scenario struct {
	empreinte [32]byte
	preuve    []byte
	resultat  [32]byte
	entetes   *ancres.Entetes
	ancre     *ancres.Bitcoin
}

var nonceTest = []byte("nonce-de-test-16")

// resultatChemin rend sha256(empreinte ‖ nonce), résultat du chemin
// f0(nonce) 08.
func resultatChemin(empreinte [32]byte) [32]byte {
	return sha256.Sum256(enc(empreinte[:], nonceTest))
}

// nouveauScenario construit le cas nominal (huit lignes de 10.4 réussies).
// modif peut changer la spécification d'un en-tête.
func nouveauScenario(t *testing.T, modif func(i uint64, s *specEntete)) *scenario {
	t.Helper()
	sc := &scenario{empreinte: sha256.Sum256([]byte("manifeste de test"))}
	sc.resultat = resultatChemin(sc.empreinte)
	sc.preuve = fichierOTS(sc.empreinte, opAp(nonceTest), opSHA(), attBitcoin(1001))
	sc.entetes = chaineRegtest(t, ReseauRegtest, 990, 31, func(i uint64) specEntete {
		s := specEntete{racine: racineSynthetique(i), nTime: 1793880000 + uint32(i-990)*600, nBits: NBitsRegtest}
		if i == 1001 {
			s.racine = sc.resultat
		}
		if modif != nil {
			modif(i, &s)
		}
		return s
	})
	c := nouvelleChaine(sc.entetes)
	sc.ancre = &ancres.Bitcoin{Reseau: ReseauRegtest, Hauteur: 1000, Hachage: c.hachageAffiche(1000), MinConfirmations: 6}
	return sc
}

func (sc *scenario) entree() Entree {
	return Entree{Usage: Cloture, Etat: entree.Lu, Preuve: sc.preuve, EmpreinteAttendue: sc.empreinte, EmpreinteDisponible: true,
		Entetes: sc.entetes, Ancre: sc.ancre}
}

func sha256Test(s string) [32]byte { return sha256.Sum256([]byte(s)) }
