// RLP selon CT-6 EX-11.5, règle 1, que CT-4 §6.7.3 reprend : une chaîne
// d'un octet inférieur à 0x80 s'écrit telle quelle, une chaîne d'au plus 55
// octets est précédée de 0x80 + longueur, au-delà de 0xb7 + longueur de la
// longueur ; une liste de charge P de 0xc0 + |P| ou 0xf7 + longueur de la
// longueur ; un entier est la chaîne de ses octets grand-boutistes minimaux
// (zéro : chaîne vide).
//
// Le décodeur est strict : il refuse un encodage non minimal (longueur
// écrite sur plus d'octets que nécessaire, chaîne d'un octet < 0x80 précédée
// de 0x81, forme longue pour une longueur ≤ 55), ce que fait aussi le
// décodeur de go-ethereum ; il rend les éléments sous forme d'arbre.

package main

import (
	"errors"
	"fmt"
	"math/big"
)

// RLPElem est un élément RLP décodé : une chaîne (Liste nil) ou une liste.
type RLPElem struct {
	Octets []byte
	Liste  []RLPElem
	EstLst bool
}

func rlpLongueur(base byte, n int) []byte {
	if n <= 55 {
		return []byte{base + byte(n)}
	}
	l := octetsMinimaux(uint64(n))
	return append([]byte{base + 55 + byte(len(l))}, l...)
}

func octetsMinimaux(x uint64) []byte {
	var b []byte
	for x > 0 {
		b = append([]byte{byte(x)}, b...)
		x >>= 8
	}
	return b
}

// RLPChaine encode une chaîne d'octets.
func RLPChaine(b []byte) []byte {
	if len(b) == 1 && b[0] < 0x80 {
		return []byte{b[0]}
	}
	return append(rlpLongueur(0x80, len(b)), b...)
}

// RLPEntier encode un entier non signé.
func RLPEntier(x *big.Int) []byte {
	if x.Sign() == 0 {
		return RLPChaine(nil)
	}
	return RLPChaine(x.Bytes())
}

// RLPEntierU encode un petit entier.
func RLPEntierU(x uint64) []byte { return RLPChaine(octetsMinimaux(x)) }

// RLPListe encode une liste dont les éléments sont déjà encodés.
func RLPListe(elts ...[]byte) []byte {
	p := concat(elts...)
	return append(rlpLongueur(0xc0, len(p)), p...)
}

// DecoderRLP décode un élément qui occupe exactement b.
func DecoderRLP(b []byte) (RLPElem, error) {
	e, n, err := decoderRLP(b, 0)
	if err != nil {
		return RLPElem{}, err
	}
	if n != len(b) {
		return RLPElem{}, fmt.Errorf("RLP : %d octets après l'élément", len(b)-n)
	}
	return e, nil
}

func lireLongueur(b []byte, pos, ll int) (int, error) {
	if pos+ll > len(b) {
		return 0, errors.New("RLP : longueur tronquée")
	}
	if b[pos] == 0 {
		return 0, errors.New("RLP : longueur à zéro de tête")
	}
	n := 0
	for i := 0; i < ll; i++ {
		if n > 1<<40 {
			return 0, errors.New("RLP : longueur démesurée")
		}
		n = n<<8 | int(b[pos+i])
	}
	if n <= 55 {
		return 0, errors.New("RLP : forme longue pour une longueur ≤ 55")
	}
	return n, nil
}

func decoderRLP(b []byte, prof int) (RLPElem, int, error) {
	if prof > 64 {
		return RLPElem{}, 0, errors.New("RLP : imbrication trop profonde")
	}
	if len(b) == 0 {
		return RLPElem{}, 0, errors.New("RLP : entrée vide")
	}
	c := b[0]
	switch {
	case c < 0x80:
		return RLPElem{Octets: []byte{c}}, 1, nil
	case c <= 0xb7:
		n := int(c - 0x80)
		if 1+n > len(b) {
			return RLPElem{}, 0, errors.New("RLP : chaîne tronquée")
		}
		if n == 1 && b[1] < 0x80 {
			return RLPElem{}, 0, errors.New("RLP : octet < 0x80 encodé en chaîne")
		}
		return RLPElem{Octets: append([]byte{}, b[1:1+n]...)}, 1 + n, nil
	case c <= 0xbf:
		ll := int(c - 0xb7)
		n, err := lireLongueur(b, 1, ll)
		if err != nil {
			return RLPElem{}, 0, err
		}
		if 1+ll+n > len(b) {
			return RLPElem{}, 0, errors.New("RLP : chaîne tronquée")
		}
		return RLPElem{Octets: append([]byte{}, b[1+ll:1+ll+n]...)}, 1 + ll + n, nil
	default:
		var debut, n int
		if c <= 0xf7 {
			debut, n = 1, int(c-0xc0)
		} else {
			ll := int(c - 0xf7)
			var err error
			n, err = lireLongueur(b, 1, ll)
			if err != nil {
				return RLPElem{}, 0, err
			}
			debut = 1 + ll
		}
		if debut+n > len(b) {
			return RLPElem{}, 0, errors.New("RLP : liste tronquée")
		}
		charge := b[debut : debut+n]
		e := RLPElem{EstLst: true, Liste: []RLPElem{}}
		for p := 0; p < len(charge); {
			s, k, err := decoderRLP(charge[p:], prof+1)
			if err != nil {
				return RLPElem{}, 0, err
			}
			e.Liste = append(e.Liste, s)
			p += k
		}
		return e, debut + n, nil
	}
}

// EntierRLP lit un élément chaîne comme entier minimal (refuse un zéro de
// tête).
func EntierRLP(e RLPElem) (*big.Int, error) {
	if e.EstLst {
		return nil, errors.New("RLP : entier attendu, liste lue")
	}
	if len(e.Octets) > 0 && e.Octets[0] == 0 {
		return nil, errors.New("RLP : entier à zéro de tête")
	}
	return new(big.Int).SetBytes(e.Octets), nil
}
