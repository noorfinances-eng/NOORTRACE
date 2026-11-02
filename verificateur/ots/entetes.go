package ots

// Chaîne d'en-têtes Bitcoin (CT-6 §10.3, EX-10.9 : O-5 ; EX-10.13 et
// EX-10.14 : temps du bloc, borne médiane, travail cumulé).
//
// Le fichier d'en-têtes a déjà été lu et contrôlé par N-2 (paquet ancres :
// schéma, 200 000 en-têtes au plus, start_height + n − 1 < 2³²). Ce fichier
// en fait la lecture que CT-6 confie au contrôle 5 : H(i), prev(i),
// racine(i), nTime(i), nBits(i), dSHA, SetCompact et GetCompact de Bitcoin
// Core, puis les six règles d'EX-10.9. Aucune boucle n'est récursive ; toutes
// sont bornées par le nombre d'en-têtes.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"sort"

	"github.com/noorfinances-eng/noortrace/verificateur/ancres"
	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/cryptographie"
)

// Constantes de Bitcoin Core (R2-F49, R2-F51, R2-F53).
const (
	// IntervalleAjustement : 2016 blocs entre deux réajustements.
	IntervalleAjustement = 2016
	// DureeCible : 1 209 600 s (deux semaines).
	DureeCible = 1209600
	// NBitsRegtest : nBits constant du réseau regtest.
	NBitsRegtest = 0x207fffff
	// FenetreMediane : onze blocs pour l'heure médiane (R2-F38).
	FenetreMediane = 11
)

// Réseaux admis (schémas ancres-confiance-v0 et entetes-bitcoin-v0).
const (
	ReseauPrincipal = "mainnet"
	ReseauRegtest   = "regtest"
)

// LimitePuissance rend powLimit du réseau (table d'EX-10.9), ou nil pour un
// réseau inconnu.
func LimitePuissance(reseau string) *big.Int {
	switch reseau {
	case ReseauPrincipal:
		// 0x00000000ffff…ff : 2^224 − 1.
		n := new(big.Int).Lsh(big.NewInt(1), 224)
		return n.Sub(n, big.NewInt(1))
	case ReseauRegtest:
		// 0x7fff…ff : 2^255 − 1.
		n := new(big.Int).Lsh(big.NewInt(1), 255)
		return n.Sub(n, big.NewInt(1))
	}
	return nil
}

// SetCompact décode un nBits comme arith_uint256::SetCompact de Bitcoin
// Core (EX-10.9) : valeur, négative, débordement.
func SetCompact(x uint32) (n *big.Int, negatif, debordement bool) {
	taille := x >> 24
	mot := x & 0x007fffff
	if taille <= 3 {
		mot >>= 8 * (3 - taille)
		n = new(big.Int).SetUint64(uint64(mot))
	} else {
		n = new(big.Int).Lsh(new(big.Int).SetUint64(uint64(mot)), uint(8*(taille-3)))
	}
	negatif = mot != 0 && x&0x00800000 != 0
	debordement = mot != 0 && (taille > 34 || (mot > 0xff && taille > 33) || (mot > 0xffff && taille > 32))
	return n, negatif, debordement
}

// GetCompact encode un entier positif comme arith_uint256::GetCompact de
// Bitcoin Core (EX-10.9).
func GetCompact(n *big.Int) uint32 {
	taille := uint32((n.BitLen() + 7) / 8)
	var compact uint64
	if taille <= 3 {
		compact = n.Uint64() << (8 * (3 - taille))
	} else {
		compact = new(big.Int).Rsh(n, uint(8*(taille-3))).Uint64()
	}
	if compact&0x00800000 != 0 {
		compact >>= 8
		taille++
	}
	return uint32(compact) | taille<<24
}

// deuxPuissance256 : 2^256, numérateur du travail d'un bloc (R2-F47).
var deuxPuissance256 = new(big.Int).Lsh(big.NewInt(1), 256)

// travail rend ⌊2^256 ÷ (cible + 1)⌋ (EX-10.14).
func travail(cible *big.Int) *big.Int {
	d := new(big.Int).Add(cible, big.NewInt(1))
	return new(big.Int).Quo(deuxPuissance256, d)
}

// dSHA rend SHA-256(SHA-256(x)) (R2-F44).
func dSHA(x []byte) [32]byte {
	a := sha256.Sum256(x)
	return sha256.Sum256(a[:])
}

// inverse rend les 32 octets dans l'ordre inverse (ordre d'affichage d'un
// hachage de bloc, R2-F28).
func inverse(b [32]byte) [32]byte {
	var r [32]byte
	for i := range b {
		r[i] = b[31-i]
	}
	return r
}

// chaine : le fichier d'en-têtes vu par le contrôle 5. s et t sont les
// hauteurs du premier et du dernier en-tête.
type chaine struct {
	reseau string
	s, t   uint64
	h      [][80]byte
}

// nouvelleChaine : nil si le fichier est absent ou vide (un fichier conforme
// au schéma porte au moins un en-tête).
func nouvelleChaine(e *ancres.Entetes) *chaine {
	if e == nil || len(e.Entetes) == 0 {
		return nil
	}
	s := uint64(e.Debut)
	return &chaine{reseau: e.Reseau, s: s, t: s + uint64(len(e.Entetes)) - 1, h: e.Entetes}
}

func (c *chaine) contient(i uint64) bool { return c != nil && i >= c.s && i <= c.t }

// H rend l'en-tête de hauteur i (à n'appeler que si contient(i)).
func (c *chaine) H(i uint64) []byte { return c.h[i-c.s][:] }

func (c *chaine) prev(i uint64) []byte   { return c.H(i)[4:36] }
func (c *chaine) racine(i uint64) []byte { return c.H(i)[36:68] }
func (c *chaine) nTime(i uint64) uint32  { return binary.LittleEndian.Uint32(c.H(i)[68:72]) }
func (c *chaine) nBits(i uint64) uint32  { return binary.LittleEndian.Uint32(c.H(i)[72:76]) }

// hachageAffiche : hachage du bloc i dans l'ordre d'affichage.
func (c *chaine) hachageAffiche(i uint64) [32]byte { return inverse(dSHA(c.H(i))) }

// cible rend SetCompact(nBits(i)) si elle est valable pour le réseau
// (règle 4 d'EX-10.9 : ni négative, ni nulle, ni en débordement, ≤ powLimit).
func cibleValable(nbits uint32, limite *big.Int) (*big.Int, string) {
	n, neg, deb := SetCompact(nbits)
	switch {
	case neg:
		return nil, "négative"
	case deb:
		return nil, "en débordement"
	case n.Sign() == 0:
		return nil, "nulle"
	case n.Cmp(limite) > 0:
		return nil, "supérieure à powLimit"
	}
	return n, ""
}

var traductionCible = map[string]string{"négative": "negative", "en débordement": "overflowing", "nulle": "zero", "supérieure à powLimit": "above powLimit"}

// mediane rend la sixième des onze heures nTime(a) … nTime(a + 10), triées.
func (c *chaine) mediane(a uint64) uint32 {
	var v [FenetreMediane]uint32
	for k := range v {
		v[k] = c.nTime(a + uint64(k))
	}
	sort.Slice(v[:], func(i, j int) bool { return v[i] < v[j] })
	return v[FenetreMediane/2]
}

// resultatO5 : statut de O-5 et son détail.
type resultatO5 struct {
	Statut commun.Statut
	Raison commun.Raison
	Detail commun.Texte
}

func echecO5(fr, en string) resultatO5 {
	return resultatO5{Statut: commun.Echoue, Detail: commun.T(fr, en)}
}

// verifierChaine applique les six règles d'EX-10.9. Les règles 1 et 2 sont
// examinées d'abord : une contradiction de la chaîne fait échouer O-5 même
// quand le point de contrôle est hors du fichier. La règle 3 rend O-5
// non exécutée (ancre_absente) si c est hors de [s, t]. Les règles 4 à 6
// portent sur c + 1 … t ; un échec y prévaut sur la règle 5 non applicable
// (réajustement dont l'en-tête i − 2016 manque), qui rend O-5 non exécutée
// (ancre_absente).
func verifierChaine(c *chaine, a *ancres.Bitcoin) resultatO5 {
	// Règle 1 : réseau.
	if c.reseau != a.Reseau {
		return echecO5(fmt.Sprintf("règle 1 : réseau du fichier d'en-têtes %s, réseau de l'ancre %s (/bitcoin)", c.reseau, a.Reseau),
			fmt.Sprintf("rule 1: headers file network %s, anchor network %s (/bitcoin)", c.reseau, a.Reseau))
	}
	limite := LimitePuissance(a.Reseau)
	if limite == nil {
		return echecO5("règle 1 : réseau "+a.Reseau+" inconnu", "rule 1: unknown network "+a.Reseau)
	}
	// Règle 2 : chaînage.
	for i := c.s + 1; i <= c.t; i++ {
		d := dSHA(c.H(i - 1))
		if !bytes.Equal(c.prev(i), d[:]) {
			return echecO5(fmt.Sprintf("règle 2 : hashPrevBlock de l'en-tête %d différent du double SHA-256 de l'en-tête %d", i, i-1),
				fmt.Sprintf("rule 2: hashPrevBlock of header %d differs from the double SHA-256 of header %d", i, i-1))
		}
	}
	// Règle 3 : point de contrôle.
	cp := uint64(a.Hauteur)
	if !c.contient(cp) {
		return resultatO5{Statut: commun.NonExecute, Raison: commun.AncreAbsente, Detail: commun.T(
			fmt.Sprintf("règle 3 : le fichier d'en-têtes (%d à %d) ne contient pas la hauteur %d du point de contrôle de l'ancre (/bitcoin)", c.s, c.t, cp),
			fmt.Sprintf("rule 3: the headers file (%d to %d) does not contain the height %d of the anchor's checkpoint (/bitcoin)", c.s, c.t, cp))}
	}
	if h := c.hachageAffiche(cp); h != a.Hachage {
		return echecO5(fmt.Sprintf("règle 3 : hachage de l'en-tête %d %s, point de contrôle de l'ancre %s", cp, cryptographie.Hex32(h), cryptographie.Hex32(a.Hachage)),
			fmt.Sprintf("rule 3: hash of header %d %s, anchor checkpoint %s", cp, cryptographie.Hex32(h), cryptographie.Hex32(a.Hachage)))
	}
	// Règles 4 à 6, de c + 1 à t.
	var nonApplicable *resultatO5
	for i := cp + 1; i <= c.t; i++ {
		nb := c.nBits(i)
		// Règle 4 : cible et preuve de travail.
		cible, motif := cibleValable(nb, limite)
		if cible == nil {
			return echecO5(fmt.Sprintf("règle 4 : cible de nBits 0x%08x de l'en-tête %d %s", nb, i, motif),
				fmt.Sprintf("rule 4: target of nBits 0x%08x of header %d is %s", nb, i, traductionCible[motif]))
		}
		hh := inverse(dSHA(c.H(i)))
		if new(big.Int).SetBytes(hh[:]).Cmp(cible) > 0 {
			return echecO5(fmt.Sprintf("règle 4 : double SHA-256 de l'en-tête %d au-dessus de sa cible (nBits 0x%08x) : preuve de travail absente", i, nb),
				fmt.Sprintf("rule 4: double SHA-256 of header %d above its target (nBits 0x%08x): no proof of work", i, nb))
		}
		// Règle 5 : difficulté.
		echec, na := difficulte(c, i, a.Reseau, limite)
		if echec != nil {
			return *echec
		}
		if na != nil && nonApplicable == nil {
			nonApplicable = na
		}
		// Règle 6 : heure médiane des onze blocs précédents.
		if i >= c.s+FenetreMediane {
			if m, t := c.mediane(i-FenetreMediane), c.nTime(i); t <= m {
				return echecO5(fmt.Sprintf("règle 6 : nTime de l'en-tête %d (%d) non supérieur à la médiane des onze précédents (%d)", i, t, m),
					fmt.Sprintf("rule 6: nTime of header %d (%d) not above the median of the eleven previous ones (%d)", i, t, m))
			}
		}
	}
	if nonApplicable != nil {
		return *nonApplicable
	}
	fr := fmt.Sprintf("en-têtes %d à %d du réseau %s rattachés au point de contrôle %d de l'ancre (/bitcoin)", c.s, c.t, c.reseau, cp)
	en := fmt.Sprintf("headers %d to %d of network %s connected to the anchor's checkpoint %d (/bitcoin)", c.s, c.t, c.reseau, cp)
	switch {
	case c.t == cp:
		fr += " ; aucun en-tête au-dessus du point de contrôle, aucun travail recalculé"
		en += "; no header above the checkpoint, no work recomputed"
	case a.Reseau == ReseauRegtest:
		fr += " ; preuve de travail sous la cible de nBits 0x207fffff vérifiée"
		en += "; proof of work under the nBits 0x207fffff target verified"
	default:
		fr += fmt.Sprintf(" ; preuve de travail, difficulté et heure médiane vérifiées de %d à %d", cp+1, c.t)
		en += fmt.Sprintf("; proof of work, difficulty and median time verified from %d to %d", cp+1, c.t)
	}
	return resultatO5{Statut: commun.Reussi, Detail: commun.T(fr, en)}
}

// difficulte applique la règle 5 d'EX-10.9 à l'en-tête i (c < i ≤ t) :
// rend l'échec, ou la non-applicabilité (réajustement dont l'en-tête
// i − 2016 manque au fichier : ancre_absente), ou deux nil.
func difficulte(c *chaine, i uint64, reseau string, limite *big.Int) (echec, nonApplicable *resultatO5) {
	nb := c.nBits(i)
	switch reseau {
	case ReseauRegtest:
		if nb != NBitsRegtest {
			r := echecO5(fmt.Sprintf("règle 5 : nBits 0x%08x de l'en-tête %d, 0x207fffff attendu sur regtest", nb, i),
				fmt.Sprintf("rule 5: nBits 0x%08x of header %d, 0x207fffff expected on regtest", nb, i))
			return &r, nil
		}
	case ReseauPrincipal:
		switch {
		case i%IntervalleAjustement != 0:
			if p := c.nBits(i - 1); nb != p {
				r := echecO5(fmt.Sprintf("règle 5 : nBits 0x%08x de l'en-tête %d différent de celui de l'en-tête %d (0x%08x), hors réajustement", nb, i, i-1, p),
					fmt.Sprintf("rule 5: nBits 0x%08x of header %d differs from header %d (0x%08x), outside a retarget", nb, i, i-1, p))
				return &r, nil
			}
		case i < c.s+IntervalleAjustement:
			return nil, &resultatO5{Statut: commun.NonExecute, Raison: commun.AncreAbsente, Detail: commun.T(
				fmt.Sprintf("règle 5 : réajustement à la hauteur %d, l'en-tête %d manque au fichier (début %d)", i, i-IntervalleAjustement, c.s),
				fmt.Sprintf("rule 5: retarget at height %d, header %d is missing from the file (start %d)", i, i-IntervalleAjustement, c.s))}
		default:
			if attendu, ok := reajustement(c, i, limite); !ok || nb != attendu {
				r := echecO5(fmt.Sprintf("règle 5 : nBits 0x%08x de l'en-tête %d, 0x%08x attendu par le réajustement", nb, i, attendu),
					fmt.Sprintf("rule 5: nBits 0x%08x of header %d, 0x%08x expected by the retarget", nb, i, attendu))
				return &r, nil
			}
		}
	}
	return nil, nil
}

// reajustement rend le nBits attendu à la hauteur i (i mod 2016 = 0,
// i − 2016 ≥ s) sur le réseau principal (règle 5 d'EX-10.9, R2-F49). Faux si
// la cible précédente ne se décode pas.
func reajustement(c *chaine, i uint64, limite *big.Int) (uint32, bool) {
	delta := int64(c.nTime(i-1)) - int64(c.nTime(i-IntervalleAjustement))
	if delta < DureeCible/4 {
		delta = DureeCible / 4
	}
	if delta > DureeCible*4 {
		delta = DureeCible * 4
	}
	n, neg, deb := SetCompact(c.nBits(i - 1))
	if neg || deb {
		return 0, false
	}
	n.Mul(n, big.NewInt(delta))
	n.Quo(n, big.NewInt(DureeCible))
	if n.Cmp(limite) > 0 {
		n.Set(limite)
	}
	return GetCompact(n), true
}

// travailCumule : somme, de max(h, c + 1) à t, de ⌊2^256 ÷ (cible + 1)⌋
// (EX-10.14). À n'appeler qu'après une O-5 réussie (cibles valables).
func travailCumule(c *chaine, h, cp uint64) *big.Int {
	somme := new(big.Int)
	debut := h
	if cp+1 > debut {
		debut = cp + 1
	}
	for i := debut; i <= c.t; i++ {
		cible, _, _ := SetCompact(c.nBits(i))
		somme.Add(somme, travail(cible))
	}
	return somme
}
