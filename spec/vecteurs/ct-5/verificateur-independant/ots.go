// Fichiers OpenTimestamps (.ots) de CT-5 §6 : lecture stricte du format de
// opentimestamps.core (CT-6 §10.2, O-1), exécution du profil { f0, f1, 08 }
// (O-3), écriture dans l'ordre de la bibliothèque de référence (CT-5 EX-6.4 :
// attestations avant opérations, attestations en attente triées par URI,
// opérations par étiquette puis argument), construction du fichier en
// attente (EX-6.4), fusion d'une réponse de calendrier (EX-6.6) et état de
// la preuve (EX-6.7).

package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"regexp"
	"sort"
)

// EnTeteMagique ouvre tout fichier .ots.
var EnTeteMagique = []byte{0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94}

// Étiquettes des opérations et des attestations.
const (
	OpAppend    = 0xf0
	OpPrepend   = 0xf1
	OpReverse   = 0xf2
	OpHexlify   = 0xf3
	OpSHA1      = 0x02
	OpRIPEMD160 = 0x03
	OpSHA256    = 0x08
	OpKeccak256 = 0x67
	VersionOts  = 0x01
)

var (
	EtiquetteBitcoin   = []byte{0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01}
	EtiquetteEnAttente = []byte{0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e}
	reURI              = regexp.MustCompile(`^[A-Za-z0-9._/:-]*$`)
)

// Bornes de CT-6 EX-10.2.
const (
	borneTaillePreuve        = 256 * 1024
	borneOperationsParChemin = 255
	borneArgument            = 4096
	borneMessage             = 4096
	borneChargeAttestation   = 8192
	borneURI                 = 1000
	borneOctetsVaruint       = 9
)

func estBinaire(op byte) bool { return op == OpAppend || op == OpPrepend }
func estUnaire(op byte) bool {
	switch op {
	case OpReverse, OpHexlify, OpSHA1, OpRIPEMD160, OpSHA256, OpKeccak256:
		return true
	}
	return false
}
func duProfil(op byte) bool { return op == OpAppend || op == OpPrepend || op == OpSHA256 }

// ErreurOts : le fichier .ots est illisible (O-1).
type ErreurOts struct{ msg string }

func (e *ErreurOts) Error() string { return e.msg }

// Attestation : bitcoin (hauteur), en_attente (URI) ou inconnue (étiquette, charge).
type Attestation struct {
	Genre     string
	Hauteur   uint64
	URI       string
	Etiquette []byte
	Charge    []byte
}

// Branche d'un arbre : une attestation ou une opération suivie de son arbre.
type Branche struct {
	Attestation *Attestation
	Op          byte
	Argument    []byte
	Arbre       []*Branche
}

// Preuve est un fichier .ots lu : empreinte et arbre.
type Preuve struct {
	Empreinte []byte
	Arbre     []*Branche
}

type lecteurOts struct {
	buf []byte
	pos int
}

func (l *lecteurOts) octet() (byte, error) {
	if l.pos >= len(l.buf) {
		return 0, &ErreurOts{"fichier tronqué"}
	}
	b := l.buf[l.pos]
	l.pos++
	return b, nil
}
func (l *lecteurOts) octets(n int) ([]byte, error) {
	if l.pos+n > len(l.buf) {
		return nil, &ErreurOts{"fichier tronqué"}
	}
	b := append([]byte{}, l.buf[l.pos:l.pos+n]...)
	l.pos += n
	return b, nil
}
func (l *lecteurOts) varuint() (uint64, error) {
	var valeur uint64
	var decalage uint
	for i := 0; ; i++ {
		if i >= borneOctetsVaruint {
			return 0, &ErreurOts{fmt.Sprintf("varuint de plus de %d octets", borneOctetsVaruint)}
		}
		b, err := l.octet()
		if err != nil {
			return 0, err
		}
		valeur |= uint64(b&0x7f) << decalage
		decalage += 7
		if b&0x80 == 0 {
			if i > 0 && b == 0 {
				return 0, &ErreurOts{"varuint sous forme non minimale"}
			}
			return valeur, nil
		}
	}
}
func (l *lecteurOts) varbytes(min, max int) ([]byte, error) {
	n, err := l.varuint()
	if err != nil {
		return nil, err
	}
	if n > uint64(max) {
		return nil, &ErreurOts{fmt.Sprintf("varbytes de %d octets, au plus %d", n, max)}
	}
	if n < uint64(min) {
		return nil, &ErreurOts{fmt.Sprintf("varbytes de %d octets, au moins %d", n, min)}
	}
	return l.octets(int(n))
}

// LireOts lit un fichier .ots selon O-1 (CT-6 EX-10.5).
func LireOts(octets []byte) (*Preuve, error) {
	if len(octets) > borneTaillePreuve {
		return nil, &ErreurOts{fmt.Sprintf("fichier de %d octets, au-delà de %d", len(octets), borneTaillePreuve)}
	}
	l := &lecteurOts{buf: octets}
	magique, err := l.octets(len(EnTeteMagique))
	if err != nil || !bytes.Equal(magique, EnTeteMagique) {
		return nil, &ErreurOts{"en-tête magique absent"}
	}
	if v, err := l.octet(); err != nil || v != VersionOts {
		return nil, &ErreurOts{"version différente de 01"}
	}
	if op, err := l.octet(); err != nil || op != OpSHA256 {
		return nil, &ErreurOts{"opération de hachage du fichier différente de 08 (SHA-256)"}
	}
	empreinte, err := l.octets(32)
	if err != nil {
		return nil, err
	}
	arbre, err := lireArbre(l, 0)
	if err != nil {
		return nil, err
	}
	if l.pos != len(octets) {
		return nil, &ErreurOts{fmt.Sprintf("%d octet(s) après l'arbre", len(octets)-l.pos)}
	}
	return &Preuve{Empreinte: empreinte, Arbre: arbre}, nil
}

func lireArbre(l *lecteurOts, profondeur int) ([]*Branche, error) {
	var branches []*Branche
	for {
		etiquette, err := l.octet()
		if err != nil {
			return nil, err
		}
		if etiquette == 0xff {
			e, err := l.octet()
			if err != nil {
				return nil, err
			}
			b, err := lireBranche(l, e, profondeur)
			if err != nil {
				return nil, err
			}
			branches = append(branches, b)
			continue
		}
		b, err := lireBranche(l, etiquette, profondeur)
		if err != nil {
			return nil, err
		}
		return append(branches, b), nil
	}
}

func lireBranche(l *lecteurOts, etiquette byte, profondeur int) (*Branche, error) {
	if etiquette == 0x00 {
		a, err := lireAttestation(l)
		if err != nil {
			return nil, err
		}
		return &Branche{Attestation: a}, nil
	}
	if !estBinaire(etiquette) && !estUnaire(etiquette) {
		return nil, &ErreurOts{fmt.Sprintf("étiquette d'opération inconnue 0x%02x", etiquette)}
	}
	if profondeur+1 > borneOperationsParChemin {
		return nil, &ErreurOts{fmt.Sprintf("chemin de plus de %d opérations", borneOperationsParChemin)}
	}
	b := &Branche{Op: etiquette}
	if estBinaire(etiquette) {
		arg, err := l.varbytes(1, borneArgument)
		if err != nil {
			return nil, err
		}
		b.Argument = arg
	}
	arbre, err := lireArbre(l, profondeur+1)
	if err != nil {
		return nil, err
	}
	b.Arbre = arbre
	return b, nil
}

func lireAttestation(l *lecteurOts) (*Attestation, error) {
	etiquette, err := l.octets(8)
	if err != nil {
		return nil, err
	}
	charge, err := l.varbytes(0, borneChargeAttestation)
	if err != nil {
		return nil, err
	}
	c := &lecteurOts{buf: charge}
	if bytes.Equal(etiquette, EtiquetteBitcoin) {
		hauteur, err := c.varuint()
		if err != nil {
			return nil, err
		}
		if c.pos != len(charge) {
			return nil, &ErreurOts{"charge de l'attestation Bitcoin non consommée"}
		}
		if hauteur >= 1<<32 {
			return nil, &ErreurOts{fmt.Sprintf("hauteur Bitcoin %d ≥ 2^32", hauteur)}
		}
		return &Attestation{Genre: "bitcoin", Hauteur: hauteur}, nil
	}
	if bytes.Equal(etiquette, EtiquetteEnAttente) {
		uri, err := c.varbytes(0, borneURI)
		if err != nil {
			return nil, err
		}
		if c.pos != len(charge) {
			return nil, &ErreurOts{"charge de l'attestation en attente non consommée"}
		}
		if !reURI.Match(uri) {
			return nil, &ErreurOts{"URI d'attestation en attente hors des caractères permis"}
		}
		return &Attestation{Genre: "en_attente", URI: string(uri)}, nil
	}
	return &Attestation{Genre: "inconnue", Etiquette: etiquette, Charge: charge}, nil
}

// --- écriture ----------------------------------------------------------------

// EncoderVaruint écrit un varuint LEB128 minimal.
func EncoderVaruint(n uint64) []byte {
	var out []byte
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n > 0 {
			b |= 0x80
		}
		out = append(out, b)
		if n == 0 {
			return out
		}
	}
}

func varbytes(b []byte) []byte { return append(EncoderVaruint(uint64(len(b))), b...) }

// EncoderAttestation écrit une attestation (sans le 00 qui l'introduit).
func EncoderAttestation(a *Attestation) []byte {
	switch a.Genre {
	case "bitcoin":
		return append(append([]byte{}, EtiquetteBitcoin...), varbytes(EncoderVaruint(a.Hauteur))...)
	case "en_attente":
		return append(append([]byte{}, EtiquetteEnAttente...), varbytes(varbytes([]byte(a.URI)))...)
	}
	return append(append([]byte{}, a.Etiquette...), varbytes(a.Charge)...)
}

func etiquetteDe(a *Attestation) []byte {
	switch a.Genre {
	case "bitcoin":
		return EtiquetteBitcoin
	case "en_attente":
		return EtiquetteEnAttente
	}
	return a.Etiquette
}

// ComparerAttestations est l'ordre de la bibliothèque de référence (CT-5
// EX-6.4, règle 2) : étiquette, puis hauteur (Bitcoin), URI (en attente) ou
// charge (inconnue).
func ComparerAttestations(a, b *Attestation) int {
	if c := bytes.Compare(etiquetteDe(a), etiquetteDe(b)); c != 0 {
		return c
	}
	switch a.Genre {
	case "bitcoin":
		switch {
		case a.Hauteur < b.Hauteur:
			return -1
		case a.Hauteur > b.Hauteur:
			return 1
		}
		return 0
	case "en_attente":
		switch {
		case a.URI < b.URI:
			return -1
		case a.URI > b.URI:
			return 1
		}
		return 0
	}
	return bytes.Compare(a.Charge, b.Charge)
}

// EncoderArbre sérialise un arbre dans l'ordre de la bibliothèque de
// référence : attestations triées, puis opérations triées par étiquette et
// argument ; chaque branche sauf la dernière précédée de ff.
func EncoderArbre(arbre []*Branche) ([]byte, error) {
	var attestations, operations []*Branche
	for _, b := range arbre {
		if b.Attestation != nil {
			attestations = append(attestations, b)
		} else {
			operations = append(operations, b)
		}
	}
	sort.SliceStable(attestations, func(i, j int) bool {
		return ComparerAttestations(attestations[i].Attestation, attestations[j].Attestation) < 0
	})
	sort.SliceStable(operations, func(i, j int) bool {
		if operations[i].Op != operations[j].Op {
			return operations[i].Op < operations[j].Op
		}
		return bytes.Compare(operations[i].Argument, operations[j].Argument) < 0
	})
	branches := append(attestations, operations...)
	if len(branches) == 0 {
		return nil, &ErreurOts{"arbre vide"}
	}
	var out []byte
	for i, b := range branches {
		if i < len(branches)-1 {
			out = append(out, 0xff)
		}
		if b.Attestation != nil {
			out = append(out, 0x00)
			out = append(out, EncoderAttestation(b.Attestation)...)
			continue
		}
		out = append(out, b.Op)
		if b.Argument != nil {
			out = append(out, varbytes(b.Argument)...)
		}
		sous, err := EncoderArbre(b.Arbre)
		if err != nil {
			return nil, err
		}
		out = append(out, sous...)
	}
	return out, nil
}

// EncoderOts écrit un fichier .ots complet.
func EncoderOts(empreinte []byte, arbre []*Branche) ([]byte, error) {
	corps, err := EncoderArbre(arbre)
	if err != nil {
		return nil, err
	}
	out := append([]byte{}, EnTeteMagique...)
	out = append(out, VersionOts, OpSHA256)
	out = append(out, empreinte...)
	return append(out, corps...), nil
}

// Operation est une opération d'un chemin linéaire.
type Operation struct {
	Op       byte
	Argument []byte
}

// Chemin construit un arbre linéaire depuis une suite d'opérations
// terminée par des branches finales.
func Chemin(operations []Operation, finales []*Branche) []*Branche {
	arbre := finales
	for i := len(operations) - 1; i >= 0; i-- {
		arbre = []*Branche{{Op: operations[i].Op, Argument: operations[i].Argument, Arbre: arbre}}
	}
	return arbre
}

// --- exécution (O-3) ------------------------------------------------------------

// AttestationExecutee est une attestation atteinte avec le message calculé
// (nil sous une opération hors profil ou après un défaut).
type AttestationExecutee struct {
	*Attestation
	Resultat   []byte
	HorsProfil bool
}

func appliquer(op byte, argument, message []byte) []byte {
	switch op {
	case OpAppend:
		return append(append([]byte{}, message...), argument...)
	case OpPrepend:
		return append(append([]byte{}, argument...), message...)
	}
	s := sha256.Sum256(message)
	return s[:]
}

// Executer rejoue les opérations depuis l'empreinte (CT-6 EX-10.7). Rend le
// premier défaut (texte vide si aucun), les attestations atteintes et
// l'ensemble des étiquettes d'opération rencontrées.
func Executer(p *Preuve) (defaut string, attestations []AttestationExecutee, operations map[byte]bool) {
	operations = map[byte]bool{}
	var parcourir func(arbre []*Branche, message []byte, horsProfil bool)
	parcourir = func(arbre []*Branche, message []byte, horsProfil bool) {
		for _, b := range arbre {
			if b.Attestation != nil {
				var res []byte
				if !horsProfil && message != nil {
					res = message
				}
				attestations = append(attestations, AttestationExecutee{Attestation: b.Attestation, Resultat: res, HorsProfil: horsProfil})
				continue
			}
			operations[b.Op] = true
			if horsProfil || !duProfil(b.Op) || message == nil {
				parcourir(b.Arbre, nil, horsProfil || !duProfil(b.Op))
				continue
			}
			var resultat []byte
			if len(message) < 1 || len(message) > borneMessage {
				if defaut == "" {
					defaut = fmt.Sprintf("message de %d octets en entrée de l'opération 0x%x", len(message), b.Op)
				}
			} else {
				resultat = appliquer(b.Op, b.Argument, message)
				if len(resultat) < 1 || len(resultat) > borneMessage {
					if defaut == "" {
						defaut = fmt.Sprintf("résultat de %d octets de l'opération 0x%x, au plus %d", len(resultat), b.Op, borneMessage)
					}
					resultat = nil
				}
			}
			parcourir(b.Arbre, resultat, false)
		}
	}
	parcourir(p.Arbre, p.Empreinte, false)
	return defaut, attestations, operations
}

// EtatPreuve rend « complete » si la preuve porte une attestation Bitcoin,
// « en_attente » sinon (EX-6.7).
func EtatPreuve(octets []byte) (string, error) {
	p, err := LireOts(octets)
	if err != nil {
		return "", err
	}
	_, attestations, _ := Executer(p)
	for _, a := range attestations {
		if a.Genre == "bitcoin" {
			return "complete", nil
		}
	}
	return "en_attente", nil
}

// --- CT-5 : engagement, fichier en attente, fusion ---------------------------------

// EngagementOts calcule e = SHA-256(empreinte ‖ nonce de 16 octets) (EX-6.2).
func EngagementOts(empreinte, nonce []byte) ([]byte, error) {
	if len(nonce) != 16 {
		return nil, refus("AN-17", "nonce OpenTimestamps : 16 octets attendus")
	}
	if len(empreinte) != 32 {
		return nil, refus("AN-5", "empreinte : 32 octets attendus (SHA-256)")
	}
	s := sha256.Sum256(append(append([]byte{}, empreinte...), nonce...))
	return s[:], nil
}

// ConstruireOts écrit le fichier .ots d'EX-6.4 : en-tête, empreinte, f0
// nonce, 08, puis la fusion des réponses des calendriers (listes de branches
// sous l'engagement) dans l'ordre de la bibliothèque de référence.
func ConstruireOts(empreinte, nonce []byte, reponses [][]*Branche) ([]byte, error) {
	if len(nonce) != 16 {
		return nil, refus("AN-18", "nonce OpenTimestamps : 16 octets attendus")
	}
	if len(empreinte) != 32 {
		return nil, refus("AN-5", "empreinte : 32 octets attendus (SHA-256)")
	}
	var branches []*Branche
	for _, r := range reponses {
		branches = append(branches, r...)
	}
	if len(branches) == 0 {
		return nil, refus("AN-18", "aucune réponse de calendrier à écrire")
	}
	return EncoderOts(empreinte, Chemin([]Operation{{Op: OpAppend, Argument: nonce}, {Op: OpSHA256}}, branches))
}

// LireReponseCalendrier relit un Timestamp sérialisé par un calendrier (sans
// en-tête de fichier : l'arbre seul) et rend ses branches ; refuse une
// opération hors du profil ou un arbre sans attestation (AN-17).
func LireReponseCalendrier(octets []byte) ([]*Branche, error) {
	faux := append([]byte{}, EnTeteMagique...)
	faux = append(faux, VersionOts, OpSHA256)
	faux = append(faux, make([]byte, 32)...)
	p, err := LireOts(append(faux, octets...))
	if err != nil {
		return nil, err
	}
	attestations := 0
	var parcourir func([]*Branche) error
	parcourir = func(branches []*Branche) error {
		for _, b := range branches {
			if b.Attestation != nil {
				attestations++
				continue
			}
			if !duProfil(b.Op) {
				return refus("AN-17", "réponse de calendrier : opération 0x%x hors du profil {f0, f1, 08}", b.Op)
			}
			if err := parcourir(b.Arbre); err != nil {
				return err
			}
		}
		return nil
	}
	if err := parcourir(p.Arbre); err != nil {
		return nil, err
	}
	if attestations == 0 {
		return nil, refus("AN-17", "réponse de calendrier sans attestation")
	}
	return p.Arbre, nil
}

// FusionnerOts remplace, dans la preuve, l'attestation en attente de l'URI
// donnée par les branches reçues du calendrier, puis resérialise (EX-6.6).
func FusionnerOts(octets []byte, uri string, reponse []*Branche) ([]byte, error) {
	p, err := LireOts(octets)
	if err != nil {
		return nil, err
	}
	faite := false
	var parcourir func(branches []*Branche) []*Branche
	parcourir = func(branches []*Branche) []*Branche {
		for i, b := range branches {
			if !faite && b.Attestation != nil && b.Attestation.Genre == "en_attente" && b.Attestation.URI == uri {
				faite = true
				out := append([]*Branche{}, branches[:i]...)
				out = append(out, reponse...)
				return append(out, branches[i+1:]...)
			}
		}
		for _, b := range branches {
			if b.Attestation == nil {
				b.Arbre = parcourir(b.Arbre)
			}
		}
		return branches
	}
	p.Arbre = parcourir(p.Arbre)
	if !faite {
		return nil, refus("AN-19", "aucune attestation en attente de %s dans la preuve", uri)
	}
	return EncoderOts(p.Empreinte, p.Arbre)
}
