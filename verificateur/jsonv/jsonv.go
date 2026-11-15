// Paquet jsonv : lecteur JSON strict et borné, qui conserve ce que la forme
// canonique JCS v0 de CT-1 §4 doit pouvoir refuser (clé en double, substitut
// isolé, nombre non entier) au lieu de le corriger comme le fait
// encoding/json.
//
// Règles de lecture (CT-6 EX-4.16, révision 0.4 ; CT-1 §3 et §4, révision
// 0.5) :
//   - le texte est de l'UTF-8 bien formé, sans marque d'ordre d'octets
//     (CT-1 §3) ; sinon ce n'est pas du JSON. Seule exception : une suite
//     de trois octets ED A0 80 à ED BF BF (substitut UTF-16 écrit en octets,
//     à la manière de CESU-8), seule ou suivie d'une autre, est lue comme un
//     substitut isolé : défaut de forme canonique (E-2), et non texte qui
//     n'est pas du JSON ;
//   - grammaire de la RFC 8259, espaces « » « \t » « \n » « \r » seulement ;
//   - profondeur bornée à 128 (CT-6 EX-4.13, EX-4.16 point 3 ; CT-1 §4,
//     règle 7) : un scalaire est de profondeur 0, un objet ou un tableau de
//     1 + la plus grande profondeur de ses valeurs ; on compte les objets et
//     les tableaux imbriqués, la racine comprise (`[[1]]` vaut 2) ;
//   - un nom en double dans un objet est conservé et signalé ; la lecture
//     d'un membre rend la dernière occurrence, comme JSON.parse ;
//   - un échappement `\uXXXX` de substitut non apparié est conservé (codé
//     en WTF-8) et signalé ;
//   - un nombre garde son texte (pour la forme canonique) et sa valeur en
//     float64 (pour le schéma, comme ECMAScript) ;
//   - le nombre de valeurs (scalaires, objets et tableaux, racine comprise)
//     est borné pendant l'analyse, avant toute matérialisation : au plus une
//     valeur par OctetsParValeur octets de la limite de taille de l'entrée
//     (CT-6 EX-15.1, révision demandée par la revue de sécurité de l'étape 8). Au-delà, la
//     lecture s'arrête et le document est traité comme un document qui n'est
//     pas du JSON, comme pour la profondeur. Sans cette borne, un document de
//     petites valeurs (« [0,0,0,…] ») dans sa limite de taille coûte environ
//     cent fois sa taille en mémoire et arrête l'exécutif sans rapport.
package jsonv

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Genre d'une valeur JSON.
type Genre uint8

const (
	Nul Genre = iota
	Booleen
	Nombre
	Chaine
	Tableau
	Objet
)

// Valeur : nœud d'un document JSON. Les champs sont rangés pour tenir dans
// le moins de mémoire possible (une valeur par octet lu dans le pire cas) ;
// les chaînes et les textes de nombres sont des vues du texte source, sans
// copie, quand elles ne portent pas d'échappement.
type Valeur struct {
	Genre Genre
	// Bool : valeur d'un booléen.
	Bool bool
	// SubstitutIsole : la chaîne contient un substitut UTF-16 non apparié.
	SubstitutIsole bool
	// Doublon : l'objet porte au moins un nom en double.
	Doublon bool
	// Texte : texte source d'un nombre.
	Texte string
	// Num : valeur d'un nombre en double précision (sémantique ECMAScript).
	Num float64
	// Chaine : valeur d'une chaîne (WTF-8 si SubstitutIsole).
	Chaine string
	// Elements : éléments d'un tableau.
	Elements []*Valeur
	// Membres : membres d'un objet, dans l'ordre du texte, doublons compris.
	Membres []Membre
	// index : table des noms, construite seulement pour les objets de plus
	// de membresLineaires membres (les petits objets se parcourent).
	index map[string]int
}

// membresLineaires : au-dessous de ce nombre de membres, un objet n'a pas
// de table d'index : la recherche parcourt les membres.
const membresLineaires = 8

// Bornes du nombre de valeurs d'un document.
const (
	// OctetsParValeur : un document lu sous une limite de taille L admet au
	// plus L / OctetsParValeur valeurs (ValeursMax).
	OctetsParValeur = 16
	// ValeursPlancher : nombre de valeurs toujours admis, quelle que soit la
	// limite de taille (petites entrées).
	ValeursPlancher = 4096
	// LimiteDefaut : limite de taille retenue par Analyser quand l'appelant
	// n'en donne pas : la plus grande des limites d'EX-4.13 (64 Mio), soit
	// 4 194 304 valeurs.
	LimiteDefaut = 64 << 20
)

// ValeursMax rend le nombre de valeurs admis pour une entrée lue sous la
// limite de taille donnée, en octets.
func ValeursMax(limite int64) int {
	n := limite / OctetsParValeur
	if n < ValeursPlancher {
		n = ValeursPlancher
	}
	return int(n)
}

// ErrValeurs : nombre de valeurs supérieur à la borne.
var ErrValeurs = errors.New("nombre de valeurs JSON supérieur à la borne (une valeur par 16 octets de la limite de taille)")

// Membre d'un objet.
type Membre struct {
	Nom          string
	NomSubstitut bool
	Valeur       *Valeur
}

// ProfondeurMax : profondeur admise (CT-6 EX-4.13), comptée en conteneurs
// imbriqués, la racine comprise.
const ProfondeurMax = 128

// ErrProfondeur : imbrication trop profonde.
var ErrProfondeur = errors.New("profondeur d'imbrication JSON supérieure à 128")

// Analyser lit un document JSON complet, sous la borne de valeurs de
// LimiteDefaut. Les entrées lues sous une limite de taille connue passent
// par AnalyserLimite.
func Analyser(b []byte) (*Valeur, error) {
	return AnalyserLimite(b, LimiteDefaut)
}

// AnalyserLimite lit un document JSON complet lu sous la limite de taille
// donnée (EX-4.13) : la profondeur est bornée à ProfondeurMax et le nombre
// de valeurs à ValeursMax(limite).
func AnalyserLimite(b []byte, limite int64) (*Valeur, error) {
	return analyser(b, ProfondeurMax, ValeursMax(limite))
}

// AnalyserProfondeur lit un document JSON avec une profondeur maximale donnée
// (nombre de conteneurs imbriqués admis, la racine comprise) et la borne de
// valeurs de LimiteDefaut.
func AnalyserProfondeur(b []byte, profondeur int) (*Valeur, error) {
	return analyser(b, profondeur, ValeursMax(LimiteDefaut))
}

func analyser(b []byte, profondeur, valeurs int) (*Valeur, error) {
	if !utf8Substituts(b) {
		return nil, errors.New("texte qui n'est pas de l'UTF-8 bien formé")
	}
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return nil, errors.New("marque d'ordre d'octets en tête du texte")
	}
	l := &lecteur{b: b, src: string(b), max: profondeur, reste: valeurs}
	l.espaces()
	v, err := l.valeur(0)
	if err != nil {
		return nil, err
	}
	l.espaces()
	if l.i != len(l.b) {
		return nil, fmt.Errorf("octets après la fin du document JSON (position %d)", l.i)
	}
	return v, nil
}

type lecteur struct {
	b []byte
	// src : le texte source, dont les chaînes sans échappement et les textes
	// de nombres sont des vues (aucune copie par valeur).
	src string
	i   int
	max int
	// reste : nombre de valeurs encore admises (ErrValeurs à zéro).
	reste int
	// bloc : valeurs allouées d'avance (alloc).
	bloc []Valeur
}

// compter décompte une valeur lue ; ErrValeurs quand la borne est atteinte.
func (l *lecteur) compter() error {
	if l.reste <= 0 {
		return ErrValeurs
	}
	l.reste--
	return nil
}

// tailleBloc : nombre de valeurs allouées d'un bloc (une allocation par
// bloc, non par valeur).
const tailleBloc = 128

// alloc rend une valeur vierge prise dans le bloc courant.
func (l *lecteur) alloc() *Valeur {
	if len(l.bloc) == 0 {
		l.bloc = make([]Valeur, tailleBloc)
	}
	v := &l.bloc[0]
	l.bloc = l.bloc[1:]
	return v
}

func (l *lecteur) erreur(msg string) error {
	return fmt.Errorf("JSON non valide à la position %d : %s", l.i, msg)
}

func (l *lecteur) espaces() {
	for l.i < len(l.b) {
		switch l.b[l.i] {
		case ' ', '\t', '\n', '\r':
			l.i++
		default:
			return
		}
	}
}

// valeur lit une valeur dont le conteneur parent est à la profondeur prof
// (0 pour la racine du document) : un objet ou un tableau lu ici est de
// rang prof + 1 et n'est admis que si ce rang ne dépasse pas la borne ; un
// scalaire n'ajoute aucun niveau. La récursion est donc bornée par la borne.
func (l *lecteur) valeur(prof int) (*Valeur, error) {
	if l.i >= len(l.b) {
		return nil, l.erreur("fin de texte inattendue")
	}
	if err := l.compter(); err != nil {
		return nil, err
	}
	switch c := l.b[l.i]; {
	case c == '{' || c == '[':
		if prof >= l.max {
			return nil, ErrProfondeur
		}
		if c == '{' {
			return l.objet(prof)
		}
		return l.tableau(prof)
	case c == '"':
		s, iso, err := l.chaine()
		if err != nil {
			return nil, err
		}
		v := l.alloc()
		v.Genre, v.Chaine, v.SubstitutIsole = Chaine, s, iso
		return v, nil
	case c == 't':
		return l.litteral("true", Booleen, true)
	case c == 'f':
		return l.litteral("false", Booleen, false)
	case c == 'n':
		return l.litteral("null", Nul, false)
	case c == '-' || (c >= '0' && c <= '9'):
		return l.nombre()
	}
	return nil, l.erreur("caractère inattendu")
}

func (l *lecteur) litteral(mot string, g Genre, b bool) (*Valeur, error) {
	if len(l.b)-l.i < len(mot) || l.src[l.i:l.i+len(mot)] != mot {
		return nil, l.erreur("littéral inconnu")
	}
	l.i += len(mot)
	v := l.alloc()
	v.Genre, v.Bool = g, b
	return v, nil
}

// ajouterMembre ajoute un membre à un objet en construction, note un nom en
// double et tient l'index au-delà de membresLineaires membres.
func (v *Valeur) ajouterMembre(m Membre) {
	if v.index == nil {
		for _, x := range v.Membres {
			if x.Nom == m.Nom {
				v.Doublon = true
				break
			}
		}
		if len(v.Membres) < membresLineaires {
			v.Membres = append(v.Membres, m)
			return
		}
		v.index = make(map[string]int, 2*membresLineaires)
		for k, x := range v.Membres {
			v.index[x.Nom] = k
		}
	}
	if _, deja := v.index[m.Nom]; deja {
		v.Doublon = true
	}
	v.index[m.Nom] = len(v.Membres)
	v.Membres = append(v.Membres, m)
}

// rang rend le rang de la dernière occurrence du membre nommé, ou -1.
func (v *Valeur) rang(nom string) int {
	if v.index != nil {
		if k, ok := v.index[nom]; ok {
			return k
		}
		return -1
	}
	for k := len(v.Membres) - 1; k >= 0; k-- {
		if v.Membres[k].Nom == nom {
			return k
		}
	}
	return -1
}

func (l *lecteur) objet(prof int) (*Valeur, error) {
	l.i++
	v := l.alloc()
	v.Genre = Objet
	l.espaces()
	if l.i < len(l.b) && l.b[l.i] == '}' {
		l.i++
		return v, nil
	}
	for {
		l.espaces()
		if l.i >= len(l.b) || l.b[l.i] != '"' {
			return nil, l.erreur("nom de membre attendu")
		}
		nom, iso, err := l.chaine()
		if err != nil {
			return nil, err
		}
		l.espaces()
		if l.i >= len(l.b) || l.b[l.i] != ':' {
			return nil, l.erreur("« : » attendu")
		}
		l.i++
		l.espaces()
		val, err := l.valeur(prof + 1)
		if err != nil {
			return nil, err
		}
		v.ajouterMembre(Membre{Nom: nom, NomSubstitut: iso, Valeur: val})
		l.espaces()
		if l.i >= len(l.b) {
			return nil, l.erreur("fin de texte dans un objet")
		}
		if l.b[l.i] == ',' {
			l.i++
			continue
		}
		if l.b[l.i] == '}' {
			l.i++
			return v, nil
		}
		return nil, l.erreur("« , » ou « } » attendu")
	}
}

func (l *lecteur) tableau(prof int) (*Valeur, error) {
	l.i++
	v := l.alloc()
	v.Genre, v.Elements = Tableau, []*Valeur{}
	l.espaces()
	if l.i < len(l.b) && l.b[l.i] == ']' {
		l.i++
		return v, nil
	}
	for {
		l.espaces()
		e, err := l.valeur(prof + 1)
		if err != nil {
			return nil, err
		}
		v.Elements = append(v.Elements, e)
		l.espaces()
		if l.i >= len(l.b) {
			return nil, l.erreur("fin de texte dans un tableau")
		}
		if l.b[l.i] == ',' {
			l.i++
			continue
		}
		if l.b[l.i] == ']' {
			l.i++
			return v, nil
		}
		return nil, l.erreur("« , » ou « ] » attendu")
	}
}

func hexa(c byte) (int, bool) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), true
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10, true
	}
	return 0, false
}

func (l *lecteur) u4() (int, error) {
	if len(l.b)-l.i < 4 {
		return 0, l.erreur("échappement \\u incomplet")
	}
	v := 0
	for k := 0; k < 4; k++ {
		h, ok := hexa(l.b[l.i+k])
		if !ok {
			return 0, l.erreur("échappement \\u non hexadécimal")
		}
		v = v*16 + h
	}
	l.i += 4
	return v, nil
}

// wtf8 code un substitut isolé sur trois octets (forme WTF-8).
func wtf8(u int) []byte {
	return []byte{byte(0xE0 | (u >> 12)), byte(0x80 | ((u >> 6) & 0x3F)), byte(0x80 | (u & 0x3F))}
}

func (l *lecteur) chaine() (string, bool, error) {
	l.i++
	// Première passe sans copie : une chaîne sans échappement ni substitut
	// écrit en octets est une vue du texte source.
	debut := l.i
	for l.i < len(l.b) {
		c := l.b[l.i]
		if c == '"' {
			s := l.src[debut:l.i]
			l.i++
			return s, false, nil
		}
		if c < 0x20 || c == '\\' || c == 0xED {
			break
		}
		l.i++
	}
	out := make([]byte, 0, l.i-debut+16)
	out = append(out, l.b[debut:l.i]...)
	iso := false
	for {
		if l.i >= len(l.b) {
			return "", false, l.erreur("chaîne non terminée")
		}
		c := l.b[l.i]
		switch {
		case c == '"':
			l.i++
			return string(out), iso, nil
		case c < 0x20:
			return "", false, l.erreur("caractère de contrôle non échappé dans une chaîne")
		case c == '\\':
			l.i++
			if l.i >= len(l.b) {
				return "", false, l.erreur("échappement incomplet")
			}
			e := l.b[l.i]
			l.i++
			switch e {
			case '"', '\\', '/':
				out = append(out, e)
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'u':
				u, err := l.u4()
				if err != nil {
					return "", false, err
				}
				switch {
				case u >= 0xD800 && u <= 0xDBFF:
					// Substitut haut : apparié seulement s'il est suivi de
					// \u d'un substitut bas.
					if len(l.b)-l.i >= 6 && l.b[l.i] == '\\' && l.b[l.i+1] == 'u' {
						sauve := l.i
						l.i += 2
						u2, err := l.u4()
						if err == nil && u2 >= 0xDC00 && u2 <= 0xDFFF {
							r := 0x10000 + ((u - 0xD800) << 10) + (u2 - 0xDC00)
							out = utf8.AppendRune(out, rune(r))
							continue
						}
						l.i = sauve
					}
					out = append(out, wtf8(u)...)
					iso = true
				case u >= 0xDC00 && u <= 0xDFFF:
					out = append(out, wtf8(u)...)
					iso = true
				default:
					out = utf8.AppendRune(out, rune(u))
				}
			default:
				return "", false, l.erreur("échappement inconnu")
			}
		case c == 0xED && l.i+2 < len(l.b) && l.b[l.i+1] >= 0xA0 && l.b[l.i+1] <= 0xBF:
			// Substitut UTF-16 écrit en octets (CESU-8) : substitut isolé
			// de CT-1 §4, règle 3 (EX-4.16, point 1), conservé en WTF-8.
			out = append(out, l.b[l.i:l.i+3]...)
			l.i += 3
			iso = true
		default:
			out = append(out, c)
			l.i++
		}
	}
}

// utf8Substituts dit si b est de l'UTF-8 bien formé (RFC 3629), à cette
// exception près qu'une suite ED A0 80 à ED BF BF (point de code de U+D800
// à U+DFFF écrit en octets) est admise ici : elle est lue comme un substitut
// isolé, défaut de forme canonique (CT-1 §3, révision 0.5 ; CT-6 EX-4.16,
// point 1). Toute autre suite mal formée (octet de continuation isolé,
// forme trop longue, au-delà de U+10FFFF, suite tronquée) rend faux.
func utf8Substituts(b []byte) bool {
	for i := 0; i < len(b); {
		c := b[i]
		if c < 0x80 {
			i++
			continue
		}
		if c == 0xED && i+2 < len(b) && b[i+1] >= 0xA0 && b[i+1] <= 0xBF && b[i+2] >= 0x80 && b[i+2] <= 0xBF {
			i += 3
			continue
		}
		r, n := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && n <= 1 {
			return false
		}
		i += n
	}
	return true
}

func (l *lecteur) nombre() (*Valeur, error) {
	debut := l.i
	if l.b[l.i] == '-' {
		l.i++
	}
	if l.i >= len(l.b) {
		return nil, l.erreur("nombre incomplet")
	}
	if l.b[l.i] == '0' {
		l.i++
	} else if l.b[l.i] >= '1' && l.b[l.i] <= '9' {
		for l.i < len(l.b) && l.b[l.i] >= '0' && l.b[l.i] <= '9' {
			l.i++
		}
	} else {
		return nil, l.erreur("chiffre attendu")
	}
	if l.i < len(l.b) && l.b[l.i] == '.' {
		l.i++
		n := 0
		for l.i < len(l.b) && l.b[l.i] >= '0' && l.b[l.i] <= '9' {
			l.i++
			n++
		}
		if n == 0 {
			return nil, l.erreur("chiffre attendu après « . »")
		}
	}
	if l.i < len(l.b) && (l.b[l.i] == 'e' || l.b[l.i] == 'E') {
		l.i++
		if l.i < len(l.b) && (l.b[l.i] == '+' || l.b[l.i] == '-') {
			l.i++
		}
		n := 0
		for l.i < len(l.b) && l.b[l.i] >= '0' && l.b[l.i] <= '9' {
			l.i++
			n++
		}
		if n == 0 {
			return nil, l.erreur("chiffre attendu dans l'exposant")
		}
	}
	texte := l.src[debut:l.i]
	f, err := strconv.ParseFloat(texte, 64)
	if err != nil {
		var ne *strconv.NumError
		if !errors.As(err, &ne) || ne.Err != strconv.ErrRange {
			return nil, l.erreur("nombre illisible")
		}
		// Dépassement : ±Inf ou 0, comme ECMAScript.
	}
	v := l.alloc()
	v.Genre, v.Texte, v.Num = Nombre, texte, f
	return v, nil
}

// Membre rend la valeur du membre `nom` (dernière occurrence), ou nil.
func (v *Valeur) Membre(nom string) *Valeur {
	if v == nil || v.Genre != Objet {
		return nil
	}
	if k := v.rang(nom); k >= 0 {
		return v.Membres[k].Valeur
	}
	return nil
}

// A dit si le membre `nom` existe.
func (v *Valeur) A(nom string) bool {
	if v == nil || v.Genre != Objet {
		return false
	}
	return v.rang(nom) >= 0
}

// Chemin descend dans des membres successifs ; nil si l'un manque.
func (v *Valeur) Chemin(noms ...string) *Valeur {
	c := v
	for _, n := range noms {
		c = c.Membre(n)
		if c == nil {
			return nil
		}
	}
	return c
}

// Noms rend les noms distincts des membres, dans l'ordre de leur dernière
// occurrence retenue (ordre du texte, doublons ôtés en gardant le premier
// rang).
func (v *Valeur) Noms() []string {
	if v == nil || v.Genre != Objet {
		return nil
	}
	vus := map[string]bool{}
	var noms []string
	for _, m := range v.Membres {
		if !vus[m.Nom] {
			vus[m.Nom] = true
			noms = append(noms, m.Nom)
		}
	}
	return noms
}

// EstObjet, EstTableau, EstChaine, EstNul : prédicats de genre (nil compris).
func (v *Valeur) EstObjet() bool   { return v != nil && v.Genre == Objet }
func (v *Valeur) EstTableau() bool { return v != nil && v.Genre == Tableau }
func (v *Valeur) EstChaine() bool  { return v != nil && v.Genre == Chaine }
func (v *Valeur) EstNul() bool     { return v != nil && v.Genre == Nul }
func (v *Valeur) EstBooleen() bool { return v != nil && v.Genre == Booleen }

// Str rend la chaîne et vrai si la valeur est une chaîne.
func (v *Valeur) Str() (string, bool) {
	if v == nil || v.Genre != Chaine {
		return "", false
	}
	return v.Chaine, true
}

// S rend la chaîne, ou "" si la valeur n'en est pas une.
func (v *Valeur) S() string {
	s, _ := v.Str()
	return s
}

// Entier rend la valeur d'un nombre entier (au sens mathématique) qui tient
// dans l'intervalle sûr [-(2^53-1), 2^53-1].
func (v *Valeur) Entier() (int64, bool) {
	if v == nil || v.Genre != Nombre {
		return 0, false
	}
	f := v.Num
	if math.IsInf(f, 0) || math.IsNaN(f) || math.Trunc(f) != f || math.Abs(f) > 9007199254740991 {
		return 0, false
	}
	return int64(f), true
}

// Egales compare deux valeurs JSON selon leur sens (ordre des membres
// indifférent, nombres par leur valeur, dernière occurrence des doublons),
// comme le font `const`, `enum` et `uniqueItems` d'un validateur de schéma.
func Egales(a, b *Valeur) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Genre != b.Genre {
		return false
	}
	switch a.Genre {
	case Nul:
		return true
	case Booleen:
		return a.Bool == b.Bool
	case Nombre:
		return a.Num == b.Num
	case Chaine:
		return a.Chaine == b.Chaine
	case Tableau:
		if len(a.Elements) != len(b.Elements) {
			return false
		}
		for i := range a.Elements {
			if !Egales(a.Elements[i], b.Elements[i]) {
				return false
			}
		}
		return true
	case Objet:
		na, nb := a.Noms(), b.Noms()
		if len(na) != len(nb) {
			return false
		}
		for _, n := range na {
			if !b.A(n) || !Egales(a.Membre(n), b.Membre(n)) {
				return false
			}
		}
		return true
	}
	return false
}

// NouvelObjet construit un objet à partir de membres (sans doublon) : sert à
// fabriquer des valeurs à comparer (objet A de CT-1 §6.3).
func NouvelObjet(membres ...Membre) *Valeur {
	v := &Valeur{Genre: Objet}
	for _, m := range membres {
		v.ajouterMembre(m)
	}
	return v
}

// CleEgalite rend une clé de texte telle que deux valeurs ont la même clé si
// et seulement si Egales les tient pour égales : les membres d'un objet y
// sont triés par nom, en dernière occurrence, et un nombre y est écrit par
// sa valeur. Elle sert à `uniqueItems`, en temps linéaire, à la place d'une
// comparaison de chaque couple d'éléments (revue de sécurité de l'étape 8).
func CleEgalite(v *Valeur) string {
	var sb strings.Builder
	ecrireCle(&sb, v)
	return sb.String()
}

func ecrireCle(sb *strings.Builder, v *Valeur) {
	if v == nil {
		sb.WriteString("?")
		return
	}
	switch v.Genre {
	case Nul:
		sb.WriteString("n")
	case Booleen:
		if v.Bool {
			sb.WriteString("t")
		} else {
			sb.WriteString("f")
		}
	case Nombre:
		sb.WriteString("#")
		sb.WriteString(strconv.FormatFloat(v.Num, 'g', -1, 64))
	case Chaine:
		sb.WriteString(strconv.Quote(v.Chaine))
	case Tableau:
		sb.WriteString("[")
		for i, e := range v.Elements {
			if i > 0 {
				sb.WriteString(",")
			}
			ecrireCle(sb, e)
		}
		sb.WriteString("]")
	case Objet:
		noms := v.Noms()
		tries := make([]string, len(noms))
		copy(tries, noms)
		// Tri par insertion : les objets comparés ici ont peu de membres.
		for i := 1; i < len(tries); i++ {
			for k := i; k > 0 && tries[k] < tries[k-1]; k-- {
				tries[k], tries[k-1] = tries[k-1], tries[k]
			}
		}
		sb.WriteString("{")
		for i, n := range tries {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString(strconv.Quote(n))
			sb.WriteString(":")
			ecrireCle(sb, v.Membre(n))
		}
		sb.WriteString("}")
	}
}

// NouvelleChaine construit une valeur chaîne.
func NouvelleChaine(s string) *Valeur { return &Valeur{Genre: Chaine, Chaine: s} }

// SansMembres rend une copie superficielle de l'objet privé des membres
// nommés (toutes occurrences) : sert à former E' (objet sans hash ni sig) et
// R (annonce de rotation sans counter_sig).
func (v *Valeur) SansMembres(noms ...string) *Valeur {
	exclus := map[string]bool{}
	for _, n := range noms {
		exclus[n] = true
	}
	c := &Valeur{Genre: Objet}
	for _, m := range v.Membres {
		if exclus[m.Nom] {
			continue
		}
		c.ajouterMembre(m)
	}
	return c
}
