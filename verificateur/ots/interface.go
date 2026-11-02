// Paquet ots : contrôle 5 de CT-6, preuve OpenTimestamps de periodHash
// contre les en-têtes Bitcoin (section 10, vérifications O-1 à O-7), et sa
// réutilisation par K-9 sur le checkpoint_hash d'un point de contrôle du
// journal (section 10.9).
//
// Ce fichier fixe l'interface que le moteur appelle. Elle est stable : le
// développeur du contrôle 5 remplace l'implémentation provisoire
// (provisoire.go) sans changer ces types ni ces signatures. Le contrat
// complet est dans INTERFACES.md, section « Contrôle 5 ».
package ots

import (
	"time"

	"github.com/noorfinances-eng/noortrace/verificateur/ancres"
	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/entree"
)

// Usage : sur quoi porte la preuve.
type Usage int

const (
	// Cloture : partie preuve.ots, empreinte de fichier periodHash
	// (contrôle 5).
	Cloture Usage = iota
	// Point : preuve embarquée dans points-de-controle.json, empreinte
	// checkpoint_hash (K-9, EX-10.16).
	Point
)

// Entree : tout ce que la vérification d'une preuve peut lire. Le paquet ne
// lit aucun fichier ni le réseau (EX-3.3) ; il ne fait jamais `ots upgrade`.
type Entree struct {
	Usage Usage
	// Preuve : octets du fichier .ots tels que lus. Pour Cloture, lus dans
	// la limite de 256 Kio ; pour Point, décodés du base64 canonique (le
	// moteur a déjà refusé un base64 non canonique ou de plus de 256 Kio
	// décodés : K-9 échoue alors sans appel, EX-10.16).
	Preuve []byte
	// Etat : état de la lecture (Cloture seulement) : entree.Lu ;
	// entree.TropGrand (O-1 échoue, EX-10.2) ; entree.Absent ou
	// entree.Illisible (D-2 porte l'échec, O-1 non_execute
	// prerequis_en_echec). Toujours entree.Lu pour Point.
	Etat entree.Etat
	// EmpreinteAttendue : periodHash recalculé (Cloture) ou checkpoint_hash
	// recalculé par K-2 (Point). EmpreinteDisponible faux quand P-1 ou K-2
	// n'a pas réussi : O-2 est non_execute, prerequis_en_echec, et O-3 à
	// O-7 s'exécutent (EX-5.4, EX-10.6).
	EmpreinteAttendue   [32]byte
	EmpreinteDisponible bool
	// Entetes : le fichier --entetes-bitcoin contrôlé par N-2, ou nil s'il
	// n'est pas fourni (O-4 à O-6 non_execute, partie_absente, EX-4.5). Le
	// même fichier sert à la clôture et au point (EX-10.16).
	Entetes *ancres.Entetes
	// Ancre : l'ancre bitcoin du fichier d'ancres, ou nil (sans fichier
	// d'ancres, ou bitcoin nul : ancre_absente, EX-4.9).
	Ancre *ancres.Bitcoin
}

// Resultat : ce que la vérification d'une preuve rend au moteur.
type Resultat struct {
	// Verifications : O-1 à O-7, toutes les sept, dans l'ordre, chacune avec
	// Controles = []int{5}.
	Verifications []commun.Verification
	// Statut, Raison : statut d'EX-10.12 sur ces sept résultats (echoue si
	// O-1, O-2, O-3, O-4 ou O-5 échoue ; reussi si O-2, O-4, O-6 et O-7
	// réussissent ; sinon non_execute avec la raison d'EX-6.5). Pour
	// Cloture : statut du contrôle 5 avant K-9 ; pour Point : statut de K-9.
	Statut commun.Statut
	Raison commun.Raison
	// Faits : valeurs d'EX-10.14, non nil si et seulement si Statut vaut
	// reussi (facts.bitcoin, ou facts.checkpoint.bitcoin pour Point).
	Faits *Faits
	// Avertissements : AV-O-1 à AV-O-3 dans l'ordre d'EX-6.15, avec
	// Verification = l'identifiant O- qui le lève ; le moteur le remplace
	// par « K-9 » pour une preuve de point (EX-10.16).
	Avertissements []commun.Avertissement
	// AncresEmployees : « /bitcoin » quand O-5 a employé l'ancre.
	AncresEmployees []string
	// Resume : summary du contrôle 5, par exemple « bloc Bitcoin 1001 du
	// réseau regtest, 20 confirmations (réseau d'essai) ».
	Resume commun.Texte
	// Proposition : proposition d'EX-10.15 sans « ; » de tête, suffixe
	// regtest compris, quand Statut vaut reussi (Cloture) ; fragment F5.
	Proposition commun.Texte
}

// Attestation : une attestation de l'arbre, dans l'ordre du fichier .ots.
type Attestation struct {
	// Kind : « bitcoin », « en_attente » ou « inconnue ».
	Kind   string  `json:"kind"`
	Height *int64  `json:"height"`
	URI    *string `json:"uri"`
	// Tag : étiquette en « 0x » + 16 chiffres hexadécimaux, pour une
	// attestation inconnue.
	Tag    *string       `json:"tag"`
	Status commun.Statut `json:"status"`
}

// PointBitcoin : point de contrôle Bitcoin de l'ancre.
type PointBitcoin struct {
	Height int64  `json:"height"`
	Hash   string `json:"hash"`
}

// Faits : valeurs rapportées du contrôle 5 (EX-10.14), dans l'ordre du
// schéma (#/$defs/faits_bitcoin).
type Faits struct {
	FileDigest     string        `json:"file_digest"`
	Network        string        `json:"network"`
	Checkpoint     PointBitcoin  `json:"checkpoint"`
	Attestations   []Attestation `json:"attestations"`
	RetainedHeight int64         `json:"retained_height"`
	// BlockHash : ordre d'affichage (EX-6.11).
	BlockHash string `json:"block_hash"`
	BlockTime string `json:"block_time"`
	// MedianBound : nil si t < h + 11.
	MedianBound   *string `json:"median_bound"`
	Confirmations int64   `json:"confirmations"`
	// CumulativeWork : chaîne décimale.
	CumulativeWork string `json:"cumulative_work"`
	// BlockTimeInstant : nTime(h), décodé, pour le moteur. Non sérialisé.
	BlockTimeInstant time.Time `json:"-"`
}

// IDs : les sept vérifications du contrôle 5.
var IDs = []string{"O-1", "O-2", "O-3", "O-4", "O-5", "O-6", "O-7"}

// Verifier vérifie une preuve (contrôle 5 ou K-9).
func Verifier(e Entree) Resultat { return verifier(e) }

// Construit dit si l'implémentation de ce contrôle est construite. Le
// fichier provisoire.go fixe la constante construit à faux ; l'implémentation
// réelle la fixe à vrai. Les tests de rejeu des vecteurs s'en servent : un
// dossier dont l'attendu dépend de ce contrôle reste « en attente » tant
// qu'elle vaut faux, et il est rejoué en entier dès qu'elle vaut vrai.
func Construit() bool { return construit }
