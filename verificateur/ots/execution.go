package ots

// Exécution des opérations du profil v0 (CT-6 EX-10.7 : O-3).
//
// Les opérations sont rejouées depuis l'empreinte du fichier, branche par
// branche, dans l'ordre du fichier : f0 rend m ‖ argument, f1 rend
// argument ‖ m, 08 rend SHA-256(m). Chaque message d'entrée et chaque
// résultat a de 1 à 4096 octets, sinon O-3 échoue et rien n'est calculé sous
// l'opération fautive. Une opération reconnue hors du profil (02, 03, 67,
// f2, f3) n'est pas exécutée, ni rien sous elle. Seul le chemin courant est
// gardé en mémoire (255 messages de 4096 octets au plus) ; de chaque
// attestation, on ne retient que le résultat de 32 octets, le seul que O-4
// peut comparer.

import (
	"crypto/sha256"
	"fmt"

	"github.com/noorfinances-eng/noortrace/verificateur/commun"
)

// attestationExecutee : une attestation de l'arbre, dans l'ordre du
// fichier, avec ce que O-3 a établi sur son chemin.
type attestationExecutee struct {
	attestationLue
	// OpHorsProfil : première opération hors profil du chemin, ou 0.
	OpHorsProfil byte
	// EnDefaut : une opération du chemin a enfreint la borne de 1 à 4096
	// octets ; le résultat n'est pas calculé.
	EnDefaut bool
	// Calcule : le résultat des opérations du chemin est connu ; Longueur
	// est sa longueur, Resultat sa valeur quand elle vaut 32.
	Calcule  bool
	Longueur int
	Resultat [32]byte
}

// execution : résultat de O-3 sur une preuve lue.
type execution struct {
	Attestations []attestationExecutee
	// Defaut : premier défaut d'exécution (O-3 échoue), ou nil.
	Defaut *commun.Texte
	// Operations : nombre d'opérations du profil exécutées.
	Operations int
	// HorsProfil : nombre d'opérations hors profil rencontrées (non
	// exécutées).
	HorsProfil int
}

// executer rejoue les opérations de la preuve (O-3).
func executer(p *Preuve) *execution {
	x := &execution{}
	m := make([]byte, 32)
	copy(m, p.Empreinte[:])
	x.parcourir(p.Arbre, m, 0, false)
	return x
}

// parcourir descend dans un arbre depuis le message m. La profondeur est
// bornée par l'analyseur (255 opérations par chemin).
func (x *execution) parcourir(bs []branche, m []byte, opHP byte, enDefaut bool) {
	for i := range bs {
		br := &bs[i]
		if br.Op == opAttestation {
			a := attestationExecutee{attestationLue: *br.Attestation, OpHorsProfil: opHP, EnDefaut: enDefaut}
			if opHP == 0 && !enDefaut {
				a.Calcule, a.Longueur = true, len(m)
				if len(m) == 32 {
					copy(a.Resultat[:], m)
				}
			}
			x.Attestations = append(x.Attestations, a)
			continue
		}
		switch {
		case opHP != 0 || enDefaut:
			x.parcourir(br.Sous, nil, opHP, enDefaut)
		case horsProfil(br.Op):
			x.HorsProfil++
			x.parcourir(br.Sous, nil, br.Op, false)
		default:
			r, d := appliquer(br.Op, br.Argument, m)
			if d != nil {
				if x.Defaut == nil {
					x.Defaut = d
				}
				x.parcourir(br.Sous, nil, 0, true)
				continue
			}
			x.Operations++
			x.parcourir(br.Sous, r, 0, false)
		}
	}
}

// appliquer exécute une opération du profil sur m, avec les bornes de
// 1 à 4096 octets pour le message et le résultat (R2-F13).
func appliquer(op byte, arg, m []byte) ([]byte, *commun.Texte) {
	if len(m) < 1 || len(m) > MaxMessage {
		t := commun.T(fmt.Sprintf("message de %d octets en entrée de l'opération %s, hors de [1, 4096]", len(m), nomOperation(op)),
			fmt.Sprintf("message of %d bytes input to operation %s, outside [1, 4096]", len(m), nomOperation(op)))
		return nil, &t
	}
	var n int
	switch op {
	case opAppend, opPrepend:
		n = len(m) + len(arg)
	case opSHA256:
		n = sha256.Size
	}
	if n < 1 || n > MaxMessage {
		t := commun.T(fmt.Sprintf("résultat de %d octets de l'opération %s, hors de [1, 4096]", n, nomOperation(op)),
			fmt.Sprintf("result of %d bytes from operation %s, outside [1, 4096]", n, nomOperation(op)))
		return nil, &t
	}
	r := make([]byte, 0, n)
	switch op {
	case opAppend:
		r = append(append(r, m...), arg...)
	case opPrepend:
		r = append(append(r, arg...), m...)
	case opSHA256:
		s := sha256.Sum256(m)
		r = append(r, s[:]...)
	}
	return r, nil
}
