// Signature d'une décision d'approbation (CT-1 §6.3, CT-3 §9.1) :
//
//	A   = { decision, journal_id, org_id, request_hash, ticket }
//	D_A = SHA-256( "noortrace/approbation/v0\n" ‖ JCS(A) )
//	M   = keccak256( "\x19Ethereum Signed Message:\n32" ‖ D_A )
//	sig = r (32) ‖ s (32) ‖ v (1), v ∈ {27, 28}, s dans la moitié basse
//
// et normalisation d'une signature reçue par le service (CT-3 EX-9.3).

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
)

// PrefixeApprobation est P_A (CT-1 §6.3).
var PrefixeApprobation = []byte("noortrace/approbation/v0\n")

var (
	reHex32    = regexp.MustCompile(`^0x[0-9a-f]{64}$`)
	reAdresse  = regexp.MustCompile(`^0x[0-9a-f]{40}$`)
	reHexPaire = regexp.MustCompile(`^0x([0-9a-f]{2})*$`)
)

// Hex0x encode des octets en hexadécimal minuscule préfixé 0x.
func Hex0x(b []byte) string { return "0x" + hex.EncodeToString(b) }

// DecoderHex décode une chaîne 0x… en minuscules (CT-1 §3).
func DecoderHex(s string) ([]byte, error) {
	if !reHexPaire.MatchString(s) {
		return nil, fmt.Errorf("hexadécimal 0x minuscule attendu : %q", s)
	}
	return hex.DecodeString(s[2:])
}

// ObjetA construit l'objet signé A (CT-1 §6.3).
func ObjetA(decision, journalID, orgID, requestHash, ticket string) *Value {
	return Objet(
		"decision", Chaine(decision),
		"journal_id", Chaine(journalID),
		"org_id", Chaine(orgID),
		"request_hash", Chaine(requestHash),
		"ticket", Chaine(ticket),
	)
}

// CondenseA rend D_A = SHA-256(P_A ‖ JCS(A)).
func CondenseA(a *Value) ([]byte, error) {
	c, err := Canonique(a)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(PrefixeApprobation)
	h.Write(c)
	return h.Sum(nil), nil
}

// CondenseEIP191 rend M = keccak256("\x19Ethereum Signed Message:\n<len>" ‖ msg)
// pour un message en octets (personal_sign, version 0x45).
func CondenseEIP191(msg []byte) []byte {
	pref := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(msg))
	return Keccak256(append([]byte(pref), msg...))
}

// Signature est une signature r ‖ s ‖ v décodée.
type Signature struct {
	R, S *big.Int
	V    int
}

// DecoderSignature décode 65 octets r ‖ s ‖ v, sans contrôle de canonicité.
func DecoderSignature(hexsig string) (Signature, error) {
	b, err := DecoderHex(hexsig)
	if err != nil {
		return Signature{}, err
	}
	if len(b) != 65 {
		return Signature{}, fmt.Errorf("signature de %d octets, 65 attendus", len(b))
	}
	return Signature{R: new(big.Int).SetBytes(b[:32]), S: new(big.Int).SetBytes(b[32:64]), V: int(b[64])}, nil
}

// Encoder rend r ‖ s ‖ v en hexadécimal 0x minuscule.
func (s Signature) Encoder() string {
	b := append(octets32(s.R), octets32(s.S)...)
	b = append(b, byte(s.V))
	return Hex0x(b)
}

// Canonique dit si la signature a la forme exigée par CT-1 E-9 : v ∈ {27,
// 28} et s dans la moitié basse de l'ordre (r, s non nuls et sous n).
func (s Signature) Canonique() bool {
	return (s.V == 27 || s.V == 28) && s.R.Sign() > 0 && s.R.Cmp(secpN) < 0 &&
		s.S.Sign() > 0 && s.S.Cmp(secpDemiN) <= 0
}

// ErrSignatureInvalide porte la raison signature_invalide (table 12.8).
var ErrSignatureInvalide = errors.New("signature_invalide")

// NormaliserSignature applique CT-3 EX-9.3 sans la clé : longueur de 65
// octets, v ∈ {0, 1} devient v + 27, toute autre valeur que 27 ou 28 est
// refusée ; un s de la moitié haute devient n − s et v est inversé.
// r ou s nul, ou ≥ n, est refusé aussi (aucune clé ne peut l'avoir produit ;
// la spécification ne le dit pas, aucun vecteur ne l'exerce).
func NormaliserSignature(hexsig string) (Signature, error) {
	s, err := DecoderSignature(hexsig)
	if err != nil {
		return Signature{}, ErrSignatureInvalide
	}
	if s.V == 0 || s.V == 1 {
		s.V += 27
	}
	if s.V != 27 && s.V != 28 {
		return Signature{}, ErrSignatureInvalide
	}
	if s.R.Sign() == 0 || s.R.Cmp(secpN) >= 0 || s.S.Sign() == 0 || s.S.Cmp(secpN) >= 0 {
		return Signature{}, ErrSignatureInvalide
	}
	if s.S.Cmp(secpDemiN) > 0 {
		s.S = new(big.Int).Sub(secpN, s.S)
		if s.V == 27 {
			s.V = 28
		} else {
			s.V = 27
		}
	}
	return s, nil
}

// AdresseRecouvree rend l'adresse (0x…, 20 octets) recouvrée d'une
// signature sur un condensé EIP-191 M ; v ∈ {0, 1, 27, 28} est accepté, s
// des deux moitiés aussi (le contrôle de forme est fait par l'appelant).
func AdresseRecouvree(m []byte, s Signature) (string, error) {
	recid := s.V
	if recid >= 27 {
		recid -= 27
	}
	pub, err := Recouvrer(m, s.R, s.S, recid)
	if err != nil {
		return "", err
	}
	return Hex0x(AdresseDeCle(pub)), nil
}

// AdresseVote rend l'adresse recouvrée d'une signature sur le D_A de A
// (CT-3 EX-9.10 : signature normalisée recouvrée sur D_A).
func AdresseVote(a *Value, s Signature) (string, error) {
	d, err := CondenseA(a)
	if err != nil {
		return "", err
	}
	return AdresseRecouvree(CondenseEIP191(d), s)
}

// SignerA signe D_A de A avec une clé privée (tests et reproduction des
// vecteurs) et rend la signature canonique r ‖ s ‖ v.
func SignerA(prive []byte, a *Value) (string, error) {
	d, err := CondenseA(a)
	if err != nil {
		return "", err
	}
	return SignerMessage(prive, d)
}

// SignerMessage signe un message en octets par personal_sign (EIP-191).
func SignerMessage(prive, msg []byte) (string, error) {
	r, s, recid, err := SignerDeterministe(prive, CondenseEIP191(msg))
	if err != nil {
		return "", err
	}
	return Signature{R: r, S: s, V: 27 + (recid & 1)}.Encoder(), nil
}
