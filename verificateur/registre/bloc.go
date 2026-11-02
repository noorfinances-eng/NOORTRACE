package registre

// Recalculs de 11.3.1 et 11.3.2 : hachage BFT du bloc (EX-11.4), encodage
// RLP, bloom, encodage de consensus d'un reçu et racine du trie
// Merkle-Patricia des reçus (EX-11.5). Keccak-256 est celui de l'EVM
// (cryptographie.Keccak256).

import (
	"encoding/binary"

	"github.com/noorfinances-eng/noortrace/verificateur/cryptographie"
)

// domaineBloc : les 20 premiers octets de la préimage de BFTBlockHash.
const domaineBloc = "noor/v1/bftblockhash"

// preimageBFT rend la préimage de 212 octets de EX-11.4.
func preimageBFT(e *entete) []byte {
	p := make([]byte, 0, 212)
	p = append(p, domaineBloc...)
	p = append(p, e.parent[:]...)
	p = binary.BigEndian.AppendUint64(p, e.numero)
	p = binary.BigEndian.AppendUint64(p, e.horodatage)
	p = append(p, e.etat[:]...)
	p = append(p, e.transactions[:]...)
	p = append(p, e.recus[:]...)
	p = binary.BigEndian.AppendUint64(p, e.gazUtilise)
	p = binary.BigEndian.AppendUint64(p, e.gazLimite)
	p = append(p, e.baseFee[:]...)
	return p
}

// hachageBFT rend BFTBlockHash (EX-11.4).
func hachageBFT(e *entete) [32]byte { return cryptographie.Keccak256(preimageBFT(e)) }

// longueurBE : un entier en grand-boutiste minimal (règle 1 de EX-11.5).
func longueurBE(n uint64) []byte {
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n)}, b...)
		n >>= 8
	}
	return b
}

// rlpChaine encode une chaîne d'octets (règle 1).
func rlpChaine(b []byte) []byte {
	switch {
	case len(b) == 1 && b[0] < 0x80:
		return []byte{b[0]}
	case len(b) <= 55:
		return append([]byte{0x80 + byte(len(b))}, b...)
	}
	l := longueurBE(uint64(len(b)))
	out := append([]byte{0xb7 + byte(len(l))}, l...)
	return append(out, b...)
}

// rlpListe encode une liste dont la charge est la concaténation des
// encodages des éléments (règle 1).
func rlpListe(charge []byte) []byte {
	if len(charge) <= 55 {
		return append([]byte{0xc0 + byte(len(charge))}, charge...)
	}
	l := longueurBE(uint64(len(charge)))
	out := append([]byte{0xf7 + byte(len(l))}, l...)
	return append(out, charge...)
}

// rlpEntier encode un entier : la chaîne de ses octets minimaux.
func rlpEntier(n uint64) []byte { return rlpChaine(longueurBE(n)) }

// bloom calcule le bloom d'un reçu (règle 2 de EX-11.5).
func bloom(journaux []journal) [256]byte {
	var b [256]byte
	ajouter := func(d []byte) {
		h := cryptographie.Keccak256(d)
		for k := 0; k < 6; k += 2 {
			n := (uint(h[k])<<8 | uint(h[k+1])) & 0x7ff
			b[255-n>>3] |= 1 << (n & 7)
		}
	}
	for _, j := range journaux {
		ajouter(j.adresse[:])
		for _, s := range j.sujets {
			ajouter(s[:])
		}
	}
	return b
}

// encoderRecu rend l'encodage de consensus d'un reçu (règle 3 de EX-11.5).
func encoderRecu(r *recu) []byte {
	var statut []byte
	if r.statut == 1 {
		statut = []byte{1}
	}
	var journaux []byte
	for _, j := range r.journaux {
		var sujets []byte
		for _, s := range j.sujets {
			sujets = append(sujets, rlpChaine(s[:])...)
		}
		var c []byte
		c = append(c, rlpChaine(j.adresse[:])...)
		c = append(c, rlpListe(sujets)...)
		c = append(c, rlpChaine(j.donnees)...)
		journaux = append(journaux, rlpListe(c)...)
	}
	bl := bloom(r.journaux)
	var c []byte
	c = append(c, rlpChaine(statut)...)
	c = append(c, rlpEntier(r.cumul)...)
	c = append(c, rlpChaine(bl[:])...)
	c = append(c, rlpListe(journaux)...)
	enc := rlpListe(c)
	if r.genre == 0 {
		return enc
	}
	return append([]byte{r.genre}, enc...)
}

// couple : clé du trie en quartets et valeur.
type couple struct {
	cle    []byte
	valeur []byte
}

// hexPrefixe applique HP (règle 4) à une suite de quartets.
func hexPrefixe(q []byte, feuille bool) []byte {
	f := byte(0)
	if feuille {
		f = 2
	}
	var out []byte
	if len(q)%2 == 1 {
		out = append(out, (f+1)<<4|q[0])
		q = q[1:]
	} else {
		out = append(out, f<<4)
	}
	for i := 0; i+1 < len(q); i += 2 {
		out = append(out, q[i]<<4|q[i+1])
	}
	return out
}

// reference : réf(n) de la règle 4, n étant déjà encodé en RLP.
func reference(n []byte) []byte {
	if len(n) < 32 {
		return n
	}
	h := cryptographie.Keccak256(n)
	return rlpChaine(h[:])
}

// profondeurTrieMax borne la récursion du trie (EX-15.2) : les clés RLP(i)
// de 256 reçus au plus ont 4 quartets au plus.
const profondeurTrieMax = 64

// noeudTrie rend l'encodage RLP du nœud de couples de clés distinctes, non
// vide. Il rend nil si la profondeur dépasse la borne.
func noeudTrie(couples []couple, prof int) []byte {
	if prof > profondeurTrieMax || len(couples) == 0 {
		return nil
	}
	if len(couples) == 1 {
		c := couples[0]
		return rlpListe(append(rlpChaine(hexPrefixe(c.cle, true)), rlpChaine(c.valeur)...))
	}
	// Préfixe commun.
	p := len(couples[0].cle)
	for _, c := range couples[1:] {
		k := 0
		for k < p && k < len(c.cle) && c.cle[k] == couples[0].cle[k] {
			k++
		}
		p = k
	}
	if p > 0 {
		suffixes := make([]couple, len(couples))
		for i, c := range couples {
			suffixes[i] = couple{cle: c.cle[p:], valeur: c.valeur}
		}
		enfant := noeudTrie(suffixes, prof+1)
		if enfant == nil {
			return nil
		}
		return rlpListe(append(rlpChaine(hexPrefixe(couples[0].cle[:p], false)), reference(enfant)...))
	}
	// Branche de 17 éléments.
	var charge []byte
	for d := byte(0); d < 16; d++ {
		var sous []couple
		for _, c := range couples {
			if len(c.cle) > 0 && c.cle[0] == d {
				sous = append(sous, couple{cle: c.cle[1:], valeur: c.valeur})
			}
		}
		if len(sous) == 0 {
			charge = append(charge, 0x80)
			continue
		}
		enfant := noeudTrie(sous, prof+1)
		if enfant == nil {
			return nil
		}
		charge = append(charge, reference(enfant)...)
	}
	valeur := []byte{0x80}
	for _, c := range couples {
		if len(c.cle) == 0 {
			valeur = rlpChaine(c.valeur)
		}
	}
	charge = append(charge, valeur...)
	return rlpListe(charge)
}

// quartets découpe des octets en quartets.
func quartets(b []byte) []byte {
	q := make([]byte, 0, 2*len(b))
	for _, x := range b {
		q = append(q, x>>4, x&0x0f)
	}
	return q
}

// racineRecus rend la racine du trie des reçus (EX-11.5) : clés RLP(i),
// valeurs les encodages de consensus ; sans reçu, keccak256(80).
func racineRecus(recus []recu) ([32]byte, bool) {
	if len(recus) == 0 {
		return cryptographie.Keccak256([]byte{0x80}), true
	}
	couples := make([]couple, len(recus))
	for i := range recus {
		couples[i] = couple{cle: quartets(rlpEntier(uint64(i))), valeur: encoderRecu(&recus[i])}
	}
	n := noeudTrie(couples, 0)
	if n == nil {
		return [32]byte{}, false
	}
	return cryptographie.Keccak256(n), true
}
