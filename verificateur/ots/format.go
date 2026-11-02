package ots

// Lecture stricte du fichier .ots (CT-6 §10.2, EX-10.2, EX-10.5 : O-1).
//
// L'analyseur construit l'arbre des opérations et des attestations sans rien
// exécuter : l'exécution des opérations relève de O-3 (execution.go). Toutes
// les bornes de §15.1 sont appliquées pendant la lecture : `varuint` de 9
// octets au plus et de forme minimale, arguments de 1 à 4096 octets, charge
// d'attestation de 0 à 8192 octets, URI de 0 à 1000 octets, hauteur
// inférieure à 2³², 255 opérations par chemin, 256 Kio par fichier. La
// récursion est bornée par le nombre d'opérations d'un chemin (EX-15.2).

import (
	"bytes"
	"fmt"

	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/entree"
)

// Constantes du format (§10.2, §15.1).
const (
	// MaxOperationsChemin : opérations d'un chemin de la racine à une
	// attestation (EX-10.2 ; 256 refusées par la bibliothèque de référence).
	MaxOperationsChemin = 255
	// MaxArgument, MaxMessage : arguments, messages et résultats de 1 à 4096
	// octets (EX-10.7, §15.1).
	MaxArgument = 4096
	MaxMessage  = 4096
	// MaxCharge : charge utile d'une attestation, 0 à 8192 octets.
	MaxCharge = 8192
	// MaxURI : URI d'une attestation en attente, 0 à 1000 octets.
	MaxURI = 1000
	// MaxOctetsVaruint : longueur maximale d'un varuint (choix d'EX-10.2).
	MaxOctetsVaruint = 9
	// TailleMax : limite du fichier (EX-10.2, EX-4.13).
	TailleMax = entree.LimitePreuveOTS
)

// enteteMagique : les 31 octets d'en-tête de §10.2 (R2-F01).
var enteteMagique = []byte{
	0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00,
	0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94,
}

// Étiquettes d'attestation connues (§10.2).
var (
	etiquetteBitcoin = [8]byte{0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01}
	etiquetteAttente = [8]byte{0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e}
)

// Codes d'opération (§10.2).
const (
	opAttestation byte = 0x00
	opSHA1        byte = 0x02
	opRIPEMD160   byte = 0x03
	opSHA256      byte = 0x08
	opKeccak256   byte = 0x67
	opAppend      byte = 0xf0
	opPrepend     byte = 0xf1
	opReverse     byte = 0xf2
	opHexlify     byte = 0xf3
	marqueBranche byte = 0xff
)

// dansProfil dit si une opération est du profil v0 {f0, f1, 08} (EX-10.7).
func dansProfil(op byte) bool { return op == opAppend || op == opPrepend || op == opSHA256 }

// horsProfil dit si une opération est reconnue mais hors du profil v0.
func horsProfil(op byte) bool {
	switch op {
	case opSHA1, opRIPEMD160, opKeccak256, opReverse, opHexlify:
		return true
	}
	return false
}

// nomOperation : nom d'une opération pour les textes (hexadécimal et nom de
// la bibliothèque de référence).
func nomOperation(op byte) string {
	noms := map[byte]string{opSHA1: "sha1", opRIPEMD160: "ripemd160", opSHA256: "sha256", opKeccak256: "keccak256",
		opAppend: "append", opPrepend: "prepend", opReverse: "reverse", opHexlify: "hexlify"}
	return fmt.Sprintf("%02x (%s)", op, noms[op])
}

// Genres d'attestation (champ kind d'EX-10.14).
const (
	GenreBitcoin  = "bitcoin"
	GenreAttente  = "en_attente"
	GenreInconnue = "inconnue"
)

// attestationLue : une attestation telle que lue dans le fichier.
type attestationLue struct {
	Genre     string
	Hauteur   uint32  // GenreBitcoin
	URI       string  // GenreAttente
	Etiquette [8]byte // toutes ; utile pour GenreInconnue
}

// branche : une branche de l'arbre, attestation (Op = 00) ou opération
// suivie de son sous-arbre.
type branche struct {
	Op          byte
	Argument    []byte // f0, f1 : argument ; tranche des octets du fichier
	Attestation *attestationLue
	Sous        []branche
}

// Preuve : le fichier .ots lu par O-1.
type Preuve struct {
	// Empreinte : les 32 octets d'empreinte du fichier (comparés par O-2).
	Empreinte [32]byte
	// Arbre : branches de la racine, dans l'ordre du fichier.
	Arbre []branche
}

// Defaut : défaut de lecture, avec la position de l'octet en cause.
type Defaut struct {
	Position int
	Message  commun.Texte
}

func (d *Defaut) Error() string { return d.Message.Fr }

// lecteur : curseur sur les octets du fichier ou d'une charge utile.
type lecteur struct {
	b    []byte
	pos  int
	base int // position du début de b dans le fichier (pour les messages)
}

func (l *lecteur) defaut(fr, en string) *Defaut {
	return &Defaut{Position: l.base + l.pos, Message: commun.T(fr, en)}
}

func (l *lecteur) reste() int { return len(l.b) - l.pos }

func (l *lecteur) octet() (byte, *Defaut) {
	if l.pos >= len(l.b) {
		return 0, l.defaut("fin de fichier prématurée", "premature end of file")
	}
	c := l.b[l.pos]
	l.pos++
	return c, nil
}

func (l *lecteur) octets(n int) ([]byte, *Defaut) {
	if n < 0 || n > l.reste() {
		return nil, l.defaut(fmt.Sprintf("fin de fichier prématurée (%d octets attendus, %d restants)", n, l.reste()),
			fmt.Sprintf("premature end of file (%d bytes expected, %d left)", n, l.reste()))
	}
	s := l.b[l.pos : l.pos+n : l.pos+n]
	l.pos += n
	return s, nil
}

// varuint lit un LEB128 non signé de forme minimale et de 9 octets au plus
// (EX-10.2).
func (l *lecteur) varuint() (uint64, *Defaut) {
	debut := l.pos
	var v uint64
	for i := 0; i < MaxOctetsVaruint; i++ {
		c, d := l.octet()
		if d != nil {
			return 0, d
		}
		v |= uint64(c&0x7f) << (7 * uint(i))
		if c&0x80 == 0 {
			if c == 0 && i > 0 {
				l.pos = debut
				return 0, l.defaut("varuint de forme non minimale (groupe final nul)", "varuint not in minimal form (final zero group)")
			}
			return v, nil
		}
	}
	l.pos = debut
	return 0, l.defaut("varuint de plus de 9 octets", "varuint longer than 9 bytes")
}

// varbytes lit varuint(n) puis n octets, avec min ≤ n ≤ max.
func (l *lecteur) varbytes(min, max int, quoi, what string) ([]byte, *Defaut) {
	debut := l.pos
	n, d := l.varuint()
	if d != nil {
		return nil, d
	}
	if n < uint64(min) || n > uint64(max) {
		l.pos = debut
		return nil, l.defaut(fmt.Sprintf("%s de %d octets, hors de [%d, %d]", quoi, n, min, max),
			fmt.Sprintf("%s of %d bytes, outside [%d, %d]", what, n, min, max))
	}
	return l.octets(int(n))
}

// Analyser applique O-1 (EX-10.5) aux octets d'un fichier .ots : rend la
// preuve lue, ou le défaut qui la rend illisible. Cible de fuzzing
// (EX-15.3) ; ne panique sur aucune entrée.
func Analyser(b []byte) (*Preuve, *Defaut) {
	if len(b) > TailleMax {
		return nil, &Defaut{Position: TailleMax, Message: commun.T(
			fmt.Sprintf("fichier de plus de 256 Kio (%d octets)", len(b)),
			fmt.Sprintf("file larger than 256 KiB (%d bytes)", len(b)))}
	}
	l := &lecteur{b: b}
	m, d := l.octets(len(enteteMagique))
	if d != nil || !bytes.Equal(m, enteteMagique) {
		return nil, &Defaut{Position: 0, Message: commun.T("en-tête magique absent", "magic header missing")}
	}
	v, d := l.octet()
	if d != nil {
		return nil, d
	}
	if v != 0x01 {
		l.pos--
		return nil, l.defaut(fmt.Sprintf("version %02x, seule la version 01 est admise", v), fmt.Sprintf("version %02x, only version 01 is accepted", v))
	}
	op, d := l.octet()
	if d != nil {
		return nil, d
	}
	if op != opSHA256 {
		l.pos--
		return nil, l.defaut(fmt.Sprintf("opération de hachage du fichier %02x, seule 08 (SHA-256) est admise", op),
			fmt.Sprintf("file hash operation %02x, only 08 (SHA-256) is accepted", op))
	}
	e, d := l.octets(32)
	if d != nil {
		return nil, d
	}
	p := &Preuve{}
	copy(p.Empreinte[:], e)
	p.Arbre, d = l.arbre(0)
	if d != nil {
		return nil, d
	}
	if l.reste() != 0 {
		return nil, l.defaut(fmt.Sprintf("%d octet(s) après l'arbre", l.reste()), fmt.Sprintf("%d byte(s) after the tree", l.reste()))
	}
	return p, nil
}

// arbre lit arbre(m) = *( ff branche(m) ) branche(m). profondeur : nombre
// d'opérations du chemin depuis la racine. La boucle consomme au moins un
// octet par tour ; la récursion passe par une opération à chaque niveau et
// s'arrête à 255.
func (l *lecteur) arbre(profondeur int) ([]branche, *Defaut) {
	var bs []branche
	for {
		c, d := l.octet()
		if d != nil {
			return nil, d
		}
		if c == marqueBranche {
			c2, d := l.octet()
			if d != nil {
				return nil, d
			}
			br, d := l.branche(c2, profondeur)
			if d != nil {
				return nil, d
			}
			bs = append(bs, br)
			continue
		}
		br, d := l.branche(c, profondeur)
		if d != nil {
			return nil, d
		}
		return append(bs, br), nil
	}
}

// branche lit une branche dont l'étiquette c vient d'être lue.
func (l *lecteur) branche(c byte, profondeur int) (branche, *Defaut) {
	switch {
	case c == opAttestation:
		a, d := l.attestation()
		if d != nil {
			return branche{}, d
		}
		return branche{Op: opAttestation, Attestation: a}, nil
	case dansProfil(c) || horsProfil(c):
		if profondeur+1 > MaxOperationsChemin {
			l.pos--
			return branche{}, l.defaut("chemin de plus de 255 opérations", "path longer than 255 operations")
		}
		br := branche{Op: c}
		if c == opAppend || c == opPrepend {
			a, d := l.varbytes(1, MaxArgument, "argument", "argument")
			if d != nil {
				return branche{}, d
			}
			br.Argument = a
		}
		sous, d := l.arbre(profondeur + 1)
		if d != nil {
			return branche{}, d
		}
		br.Sous = sous
		return br, nil
	}
	l.pos--
	return branche{}, l.defaut(fmt.Sprintf("étiquette d'opération inconnue %02x", c), fmt.Sprintf("unknown operation tag %02x", c))
}

// attestation lit étiquette(8) varbytes(0..8192) et décode les charges
// utiles connues, consommées exactement.
func (l *lecteur) attestation() (*attestationLue, *Defaut) {
	e, d := l.octets(8)
	if d != nil {
		return nil, d
	}
	a := &attestationLue{}
	copy(a.Etiquette[:], e)
	charge, d := l.varbytes(0, MaxCharge, "charge d'attestation", "attestation payload")
	if d != nil {
		return nil, d
	}
	sous := &lecteur{b: charge, base: l.base + l.pos - len(charge)}
	switch a.Etiquette {
	case etiquetteBitcoin:
		a.Genre = GenreBitcoin
		h, d := sous.varuint()
		if d != nil {
			return nil, d
		}
		if h >= 1<<32 {
			return nil, sous.defaut(fmt.Sprintf("hauteur Bitcoin %d, au moins 2^32", h), fmt.Sprintf("Bitcoin height %d, at least 2^32", h))
		}
		a.Hauteur = uint32(h)
	case etiquetteAttente:
		a.Genre = GenreAttente
		u, d := sous.varbytes(0, MaxURI, "URI", "URI")
		if d != nil {
			return nil, d
		}
		for _, c := range u {
			if !uriAdmis(c) {
				return nil, sous.defaut(fmt.Sprintf("caractère %#02x hors de A-Z a-z 0-9 - . _ / : dans l'URI", c),
					fmt.Sprintf("character %#02x outside A-Z a-z 0-9 - . _ / : in the URI", c))
			}
		}
		a.URI = string(u)
	default:
		a.Genre = GenreInconnue
		return a, nil
	}
	if sous.reste() != 0 {
		return nil, sous.defaut(fmt.Sprintf("charge d'attestation non consommée exactement (%d octet(s) en trop)", sous.reste()),
			fmt.Sprintf("attestation payload not consumed exactly (%d extra byte(s))", sous.reste()))
	}
	return a, nil
}

// uriAdmis : caractères admis dans l'URI d'une attestation en attente
// (§10.2, R2-F20).
func uriAdmis(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '/' || c == ':'
}
