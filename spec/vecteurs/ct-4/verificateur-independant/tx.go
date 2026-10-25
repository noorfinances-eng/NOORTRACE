// Transactions de type 2 (EIP-1559, enveloppe EIP-2718) selon CT-4 §6.7.3 :
// sérialisation 0x02 ‖ RLP([chainId, nonce, maxPriorityFeePerGas,
// maxFeePerGas, gasLimit, to, value, data, accessList, yParity, r, s]),
// charge signée keccak256(0x02 ‖ RLP([… , accessList])), `to` sur 20 octets
// ou chaîne vide pour une création, liste d'accès vide 0xc0 ; hachage de la
// transaction = keccak256 de sa sérialisation ; adresse de création
// keccak256(RLP([a20(a), x]))[12:].

package main

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
)

// Tx2 est une transaction de type 2.
type Tx2 struct {
	ChainID, Nonce, Pourboire, Plafond, Gaz, Valeur *big.Int
	Dest                                            []byte // nil pour une création
	Donnees                                         []byte
	ListeAcces                                      RLPElem
	ListeVide                                       bool
	YParity                                         *big.Int
	R, S                                            *big.Int
}

func (t Tx2) champsRLP() [][]byte {
	dest := RLPChaine(t.Dest)
	if t.Dest == nil {
		dest = RLPChaine(nil)
	}
	return [][]byte{RLPEntier(t.ChainID), RLPEntier(t.Nonce), RLPEntier(t.Pourboire), RLPEntier(t.Plafond),
		RLPEntier(t.Gaz), dest, RLPEntier(t.Valeur), RLPChaine(t.Donnees), RLPListe()}
}

// ChargeSignee rend 0x02 ‖ RLP([chainId, …, accessList]).
func (t Tx2) ChargeSignee() []byte {
	return append([]byte{0x02}, RLPListe(t.champsRLP()...)...)
}

// Serialiser rend la transaction signée.
func (t Tx2) Serialiser() []byte {
	f := append(t.champsRLP(), RLPEntier(t.YParity), RLPEntier(t.R), RLPEntier(t.S))
	return append([]byte{0x02}, RLPListe(f...)...)
}

// SignerTx2 signe la charge par RFC 6979 et remplit yParity, r, s.
func SignerTx2(t Tx2, prive []byte) (Tx2, error) {
	h := Keccak256(t.ChargeSignee())
	r, s, recid, err := SignerDeterministe(prive, h)
	if err != nil {
		return t, err
	}
	if recid > 1 {
		return t, errors.New("identifiant de récupération hors de {0, 1}")
	}
	t.YParity, t.R, t.S = big.NewInt(int64(recid)), r, s
	return t, nil
}

// DecoderTx2 lit une transaction de type 2 sérialisée ; ErrPasType2 si le
// premier octet n'est pas 0x02.
func DecoderTx2(b []byte) (Tx2, error) {
	var t Tx2
	if len(b) == 0 || b[0] != 0x02 {
		return t, ErrPasType2
	}
	e, err := DecoderRLP(b[1:])
	if err != nil {
		return t, err
	}
	if !e.EstLst || len(e.Liste) != 12 {
		return t, errors.New("transaction de type 2 : liste de 12 éléments attendue")
	}
	ints := []**big.Int{&t.ChainID, &t.Nonce, &t.Pourboire, &t.Plafond, &t.Gaz}
	for i, p := range ints {
		if *p, err = EntierRLP(e.Liste[i]); err != nil {
			return t, err
		}
	}
	d := e.Liste[5]
	if d.EstLst {
		return t, errors.New("destinataire : chaîne attendue")
	}
	switch len(d.Octets) {
	case 0:
		t.Dest = nil
	case 20:
		t.Dest = d.Octets
	default:
		return t, fmt.Errorf("destinataire de %d octets", len(d.Octets))
	}
	if t.Valeur, err = EntierRLP(e.Liste[6]); err != nil {
		return t, err
	}
	if e.Liste[7].EstLst {
		return t, errors.New("données : chaîne attendue")
	}
	t.Donnees = e.Liste[7].Octets
	t.ListeAcces = e.Liste[8]
	if !t.ListeAcces.EstLst {
		return t, errors.New("liste d'accès : liste attendue")
	}
	t.ListeVide = len(t.ListeAcces.Liste) == 0
	if t.YParity, err = EntierRLP(e.Liste[9]); err != nil {
		return t, err
	}
	if t.R, err = EntierRLP(e.Liste[10]); err != nil {
		return t, err
	}
	if t.S, err = EntierRLP(e.Liste[11]); err != nil {
		return t, err
	}
	// La charge signée se recalcule sur la liste d'accès telle qu'elle est.
	return t, nil
}

// ErrPasType2 signale une transaction d'un autre type.
var ErrPasType2 = errors.New("transaction d'un autre type que 2")

// chargeSigneeDecodee recalcule la charge d'une transaction lue, liste
// d'accès comprise telle qu'elle est encodée.
func chargeSigneeDecodee(b []byte) ([]byte, error) {
	e, err := DecoderRLP(b[1:])
	if err != nil {
		return nil, err
	}
	var parts [][]byte
	for _, x := range e.Liste[:9] {
		parts = append(parts, reencoder(x))
	}
	return append([]byte{0x02}, RLPListe(parts...)...), nil
}

func reencoder(e RLPElem) []byte {
	if !e.EstLst {
		return RLPChaine(e.Octets)
	}
	var parts [][]byte
	for _, x := range e.Liste {
		parts = append(parts, reencoder(x))
	}
	return RLPListe(parts...)
}

// Expediteur recouvre l'expéditeur d'une transaction sérialisée.
func Expediteur(b []byte, t Tx2) (string, error) {
	charge, err := chargeSigneeDecodee(b)
	if err != nil {
		return "", err
	}
	if t.YParity.Cmp(big.NewInt(1)) > 0 {
		return "", errors.New("yParity hors de {0, 1}")
	}
	pub, err := Recouvrer(Keccak256(charge), t.R, t.S, int(t.YParity.Int64()))
	if err != nil {
		return "", err
	}
	return AdresseHex(pub), nil
}

// AdresseCreation rend l'adresse d'un contrat créé par a à son nonce x
// (CT-4 §6.7.3, RG-19).
func AdresseCreation(a []byte, x *big.Int) []byte {
	return Keccak256(RLPListe(RLPChaine(a), RLPEntier(x)))[12:]
}

// egal compare deux tranches d'octets.
func egal(a, b []byte) bool { return bytes.Equal(a, b) }

// ExpediteurAncien recouvre l'expéditeur d'une transaction de type 0 non
// protégée (EX-4.8 : v dans {27, 28}, charge RLP([nonce, gasPrice, gas, to,
// value, data]) sans identifiant de chaîne) ; une transaction protégée
// (EIP-155, v ≥ 35) est signalée comme telle.
func ExpediteurAncien(b []byte) (string, bool, error) {
	e, err := DecoderRLP(b)
	if err != nil {
		return "", false, err
	}
	if !e.EstLst || len(e.Liste) != 9 {
		return "", false, errors.New("transaction de type 0 : liste de 9 éléments attendue")
	}
	v, err := EntierRLP(e.Liste[6])
	if err != nil {
		return "", false, err
	}
	r, _ := EntierRLP(e.Liste[7])
	s, _ := EntierRLP(e.Liste[8])
	if v.Cmp(big.NewInt(35)) >= 0 {
		return "", true, nil
	}
	if v.Cmp(big.NewInt(27)) != 0 && v.Cmp(big.NewInt(28)) != 0 {
		return "", false, fmt.Errorf("v = %s", v)
	}
	var parts [][]byte
	for _, x := range e.Liste[:6] {
		parts = append(parts, reencoder(x))
	}
	pub, err := Recouvrer(Keccak256(RLPListe(parts...)), r, s, int(v.Int64()-27))
	if err != nil {
		return "", false, err
	}
	return AdresseHex(pub), false, nil
}
