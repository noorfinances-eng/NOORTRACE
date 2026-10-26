// Arbre de Merkle RFC 6962 §2.1 (CT-1 §9) : feuilles SHA-256(0x00 || d),
// nœuds SHA-256(0x01 || g || d), découpage à la plus grande puissance de deux
// strictement inférieure à n, chemin d'audit §2.1.1 et vérification par
// l'algorithme de la RFC 9162 §2.1.3.2 reproduit en CT-1 §9.3 ; révision
// 0.3 : preuve de cohérence RFC 9162 §2.1.4 (génération et vérification
// reproduites en CT-1 §10.7).
//
// Période vide : racine de 32 octets nuls (convention NOORTRACE imposée par
// PeriodRegistry), et non SHA-256("") de la RFC 6962.

package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
)

// RacineVide est la racine d'une période vide (convention NOORTRACE).
var RacineVide = make([]byte, 32)

// RacineVideRFC6962 est MTH({}) = SHA-256("") de la RFC 6962, donnée pour
// que la distinction soit explicite ; elle n'est jamais une racine valide.
var RacineVideRFC6962 = func() []byte { s := sha256.Sum256(nil); return s[:] }()

// Feuille calcule L = SHA-256(0x00 || d).
func Feuille(d []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(d)
	return h.Sum(nil)
}

// Noeud calcule N = SHA-256(0x01 || g || d).
func Noeud(g, d []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(g)
	h.Write(d)
	return h.Sum(nil)
}

// plusGrandePuissanceDeDeuxInferieure rend k, la plus grande puissance de
// deux strictement inférieure à n (n > 1).
func plusGrandePuissanceDeDeuxInferieure(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

// MTH calcule la racine RFC 6962 de D[0..n-1], n ≥ 1.
func MTH(D [][]byte) []byte {
	n := len(D)
	if n == 1 {
		return Feuille(D[0])
	}
	k := plusGrandePuissanceDeDeuxInferieure(n)
	return Noeud(MTH(D[:k]), MTH(D[k:]))
}

// Racine calcule la racine d'une période : 32 octets nuls si n = 0, MTH sinon.
func Racine(D [][]byte) []byte {
	if len(D) == 0 {
		return append([]byte{}, RacineVide...)
	}
	return MTH(D)
}

// Chemin calcule PATH(m, D[0..n-1]) de la RFC 6962 §2.1.1, du bas vers le haut.
func Chemin(m int, D [][]byte) [][]byte {
	n := len(D)
	if n <= 1 {
		return [][]byte{}
	}
	k := plusGrandePuissanceDeDeuxInferieure(n)
	if m < k {
		return append(Chemin(m, D[:k]), MTH(D[k:]))
	}
	return append(Chemin(m-k, D[k:]), MTH(D[:k]))
}

// Erreurs de la vérification d'inclusion.
var (
	ErrIndiceHorsArbre  = errors.New("indice de feuille ≥ taille de l'arbre")
	ErrCheminTropLong   = errors.New("chemin d'audit trop long pour (indice, taille)")
	ErrCheminTropCourt  = errors.New("chemin d'audit trop court pour (indice, taille)")
	ErrRacineDifferente = errors.New("racine recalculée différente de la racine attendue")
)

// VerifierInclusion exécute l'algorithme de CT-1 §9.3 (RFC 9162 §2.1.3.2).
func VerifierInclusion(leafHash []byte, m, n uint64, path [][]byte, root []byte) error {
	if m >= n {
		return ErrIndiceHorsArbre
	}
	fn, sn := m, n-1
	r := leafHash
	for _, h := range path {
		if sn == 0 {
			return ErrCheminTropLong
		}
		if fn&1 == 1 || fn == sn {
			r = Noeud(h, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = Noeud(r, h)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return ErrCheminTropCourt
	}
	if !bytes.Equal(r, root) {
		return ErrRacineDifferente
	}
	return nil
}

// Erreurs de la vérification de cohérence (CT-1 §10.7).
var (
	ErrCoherenceHorsDefinition = errors.New("m = 0 ou n < m : hors de la définition")
	ErrCoherenceCheminVide     = errors.New("chemin vide")
	ErrCoherenceCheminNonVide  = errors.New("m = n avec un chemin non vide")
	ErrCoherenceRacines        = errors.New("m = n et racines différentes")
	ErrCoherenceTropLong       = errors.New("chemin trop long")
	ErrCoherenceTropCourt      = errors.New("chemin trop court")
	ErrCoherencePremiereRacine = errors.New("première racine recalculée différente")
	ErrCoherenceSecondeRacine  = errors.New("seconde racine recalculée différente")
)

// sousPreuve est SUBPROOF(m, D[0..n-1], b) de la RFC 9162 §2.1.4.1.
func sousPreuve(m int, D [][]byte, b bool) [][]byte {
	n := len(D)
	if m == n {
		if b {
			return [][]byte{}
		}
		return [][]byte{MTH(D)}
	}
	k := plusGrandePuissanceDeDeuxInferieure(n)
	if m <= k {
		return append(sousPreuve(m, D[:k], b), MTH(D[k:]))
	}
	return append(sousPreuve(m-k, D[k:], false), MTH(D[:k]))
}

// PreuveCoherence calcule PROOF(m, D[0..n-1]) de CT-1 §10.7, 0 < m ≤ n ;
// m = n donne la preuve vide. Erreur hors de la définition.
func PreuveCoherence(m int, D [][]byte) ([][]byte, error) {
	n := len(D)
	if m <= 0 || m > n {
		return nil, ErrCoherenceHorsDefinition
	}
	return sousPreuve(m, D, true), nil
}

// VerifierCoherence exécute l'algorithme de vérification de CT-1 §10.7
// (RFC 9162 §2.1.4.2) sur (m, n, first_root, second_root, path).
func VerifierCoherence(m, n uint64, firstRoot, secondRoot []byte, path [][]byte) error {
	if m == 0 || n < m {
		return ErrCoherenceHorsDefinition
	}
	if m == n {
		if len(path) != 0 {
			return ErrCoherenceCheminNonVide
		}
		if !bytes.Equal(firstRoot, secondRoot) {
			return ErrCoherenceRacines
		}
		return nil
	}
	if len(path) == 0 {
		return ErrCoherenceCheminVide
	}
	chemin := path
	if m&(m-1) == 0 {
		chemin = append([][]byte{firstRoot}, path...)
	}
	fn, sn := m-1, n-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := chemin[0], chemin[0]
	for _, h := range chemin[1:] {
		if sn == 0 {
			return ErrCoherenceTropLong
		}
		if fn&1 == 1 || fn == sn {
			fr = Noeud(h, fr)
			sr = Noeud(h, sr)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = Noeud(sr, h)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return ErrCoherenceTropCourt
	}
	if !bytes.Equal(fr, firstRoot) {
		return ErrCoherencePremiereRacine
	}
	if !bytes.Equal(sr, secondRoot) {
		return ErrCoherenceSecondeRacine
	}
	return nil
}
