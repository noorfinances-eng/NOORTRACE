// Racines des reçus et des transactions d'un bloc.
//
// CT-6 EX-11.5 (que CT-4 CP-3 reprend) : receiptsRoot est la racine du trie
// Merkle-Patricia dont les clés sont RLP(i) et les valeurs l'encodage de
// consensus du reçu i (règles 2 à 4 : bloom recalculé, encodage typé, trie
// hex-prefix). CT-4 EX-6.22 (RG-19, et CP-4) : la racine des transactions se
// calcule de même, la valeur de rang i étant l'encodage binaire de la
// transaction i (6.7.3).

package main

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
)

type couple struct {
	cle    []byte // en quartets
	valeur []byte
}

func quartets(b []byte) []byte {
	q := make([]byte, 0, 2*len(b))
	for _, c := range b {
		q = append(q, c>>4, c&0x0f)
	}
	return q
}

// hexPrefixe encode un chemin de quartets (CT-6 EX-11.5, règle 4).
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

// reference rend réf(n) : n si |RLP(n)| < 32, sinon keccak256(RLP(n)),
// encodé comme élément d'un nœud parent.
func reference(noeud []byte) []byte {
	if len(noeud) < 32 {
		return noeud
	}
	return RLPChaine(Keccak256(noeud))
}

// noeudTrie rend l'encodage RLP du nœud de l'ensemble de couples.
func noeudTrie(cs []couple) []byte {
	if len(cs) == 1 {
		return RLPListe(RLPChaine(hexPrefixe(cs[0].cle, true)), RLPChaine(cs[0].valeur))
	}
	// préfixe commun
	p := 0
	for {
		if p >= len(cs[0].cle) {
			break
		}
		c := cs[0].cle[p]
		ok := true
		for _, x := range cs[1:] {
			if p >= len(x.cle) || x.cle[p] != c {
				ok = false
				break
			}
		}
		if !ok {
			break
		}
		p++
	}
	if p > 0 {
		sous := make([]couple, len(cs))
		for i, x := range cs {
			sous[i] = couple{x.cle[p:], x.valeur}
		}
		return RLPListe(RLPChaine(hexPrefixe(cs[0].cle[:p], false)), reference(noeudTrie(sous)))
	}
	elts := make([][]byte, 17)
	for d := 0; d < 16; d++ {
		var sous []couple
		for _, x := range cs {
			if len(x.cle) > 0 && int(x.cle[0]) == d {
				sous = append(sous, couple{x.cle[1:], x.valeur})
			}
		}
		if len(sous) == 0 {
			elts[d] = RLPChaine(nil)
		} else {
			elts[d] = reference(noeudTrie(sous))
		}
	}
	elts[16] = RLPChaine(nil)
	for _, x := range cs {
		if len(x.cle) == 0 {
			elts[16] = RLPChaine(x.valeur)
		}
	}
	return RLPListe(elts...)
}

// RacineIndexee rend la racine du trie des valeurs indexées par RLP(i)
// (types.DeriveSha) ; sans valeur, keccak256(0x80).
func RacineIndexee(valeurs [][]byte) []byte {
	if len(valeurs) == 0 {
		return Keccak256([]byte{0x80})
	}
	cs := make([]couple, len(valeurs))
	for i, v := range valeurs {
		cs[i] = couple{quartets(RLPEntierU(uint64(i))), v}
	}
	return Keccak256(noeudTrie(cs))
}

// Journal est un journal d'événement d'un reçu.
type Journal struct {
	Adresse []byte
	Sujets  [][]byte
	Donnees []byte
}

// Recu est un reçu réduit aux champs que l'encodage de consensus engage.
type Recu struct {
	Type       int
	Statut     int
	GazCumule  *big.Int
	Journaux   []Journal
	TxHash     string // transactionHash servi (déclaratif)
	BlockHash  string
	BlockNum   *big.Int
	TxIndex    *big.Int
	Contrat    string // contractAddress servi, s'il est présent
	Destinat   *string
	Expediteur string
}

// bloom calcule le filtre de 256 octets d'un reçu (CT-6 EX-11.5, règle 2).
func bloom(js []Journal) []byte {
	b := make([]byte, 256)
	ajouter := func(d []byte) {
		h := Keccak256(d)
		for k := 0; k < 6; k += 2 {
			n := (int(h[k])<<8 | int(h[k+1])) & 0x7ff
			b[255-(n>>3)] |= 1 << (n & 7)
		}
	}
	for _, j := range js {
		ajouter(j.Adresse)
		for _, s := range j.Sujets {
			ajouter(s)
		}
	}
	return b
}

// EncodageRecu rend l'encodage de consensus d'un reçu (règle 3).
func EncodageRecu(r Recu) []byte {
	statut := []byte{}
	if r.Statut == 1 {
		statut = []byte{1}
	}
	var js [][]byte
	for _, j := range r.Journaux {
		var sujets [][]byte
		for _, s := range j.Sujets {
			sujets = append(sujets, RLPChaine(s))
		}
		js = append(js, RLPListe(RLPChaine(j.Adresse), RLPListe(sujets...), RLPChaine(j.Donnees)))
	}
	c := RLPListe(RLPChaine(statut), RLPEntier(r.GazCumule), RLPChaine(bloom(r.Journaux)), RLPListe(js...))
	if r.Type == 0 {
		return c
	}
	return append([]byte{byte(r.Type)}, c...)
}

// RacineRecus rend receiptsRoot recalculée sur tous les reçus.
func RacineRecus(rs []Recu) []byte {
	vals := make([][]byte, len(rs))
	for i, r := range rs {
		vals[i] = EncodageRecu(r)
	}
	return RacineIndexee(vals)
}

// LireRecu lit un reçu sous la forme d'eth_getTransactionReceipt (champ
// result d'une réponse brute, ou objet réduit de registre.json). Les adresses
// sont mises en minuscules (casse mixte EIP-55 servie, CT-6 §11.2.1).
func LireRecu(v *Value) (Recu, error) {
	var r Recu
	if v == nil || v.Kind != KindObject {
		return r, errors.New("reçu : objet attendu")
	}
	ts, err := Champ(v, "type")
	if err != nil {
		return r, err
	}
	t, err := Quantite(ts)
	if err != nil || t.Cmp(big.NewInt(4)) > 0 {
		return r, fmt.Errorf("reçu : type %q", ts)
	}
	r.Type = int(t.Int64())
	ss, err := Champ(v, "status")
	if err != nil {
		return r, err
	}
	switch ss {
	case "0x0":
		r.Statut = 0
	case "0x1":
		r.Statut = 1
	default:
		return r, fmt.Errorf("reçu : status %q", ss)
	}
	gs, err := Champ(v, "cumulativeGasUsed")
	if err != nil {
		return r, err
	}
	if r.GazCumule, err = Quantite(gs); err != nil {
		return r, err
	}
	logs := v.Get("logs")
	if logs == nil || logs.Kind != KindArray {
		return r, errors.New("reçu : logs attendus")
	}
	for _, l := range logs.Arr {
		var j Journal
		as, err := Champ(l, "address")
		if err != nil {
			return r, err
		}
		if j.Adresse, err = DecoderHexLibre(as); err != nil || len(j.Adresse) != 20 {
			return r, fmt.Errorf("journal : adresse %q", as)
		}
		tp := l.Get("topics")
		if tp == nil || tp.Kind != KindArray {
			return r, errors.New("journal : topics attendus")
		}
		for _, s := range tp.Arr {
			b, err := DecoderHexLibre(s.S())
			if err != nil || len(b) != 32 {
				return r, fmt.Errorf("journal : sujet %q", s.S())
			}
			j.Sujets = append(j.Sujets, b)
		}
		ds, err := Champ(l, "data")
		if err != nil {
			return r, err
		}
		if j.Donnees, err = DecoderHexLibre(ds); err != nil {
			return r, fmt.Errorf("journal : data %q", ds)
		}
		r.Journaux = append(r.Journaux, j)
	}
	r.TxHash = strings.ToLower(v.Get("transactionHash").S())
	r.BlockHash = strings.ToLower(v.Get("blockHash").S())
	if bn := v.Get("blockNumber"); bn != nil {
		r.BlockNum, _ = Quantite(strings.ToLower(bn.S()))
	}
	if ti := v.Get("transactionIndex"); ti != nil {
		r.TxIndex, _ = Quantite(strings.ToLower(ti.S()))
	}
	r.Contrat = strings.ToLower(v.Get("contractAddress").S())
	if to := v.Get("to"); to != nil && to.Kind == KindString {
		s := strings.ToLower(to.Str)
		r.Destinat = &s
	}
	r.Expediteur = strings.ToLower(v.Get("from").S())
	return r, nil
}
