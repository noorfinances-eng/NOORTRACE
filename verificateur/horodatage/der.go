package horodatage

// Lecteur DER borné du profil de CT-6 §9.3 (EX-9.4, EX-9.6, EX-9.21) :
// étiquettes et longueurs selon cryptobyte (numéros d'étiquette inférieurs
// à 31, longueurs définies de forme minimale), BOOLEAN codé 00 ou ff,
// profondeur d'imbrication au plus 32 (EX-15.1), aucun octet après une
// structure qui n'en admet pas. Les INTEGER ne sont pas contrôlés quant à
// leur forme minimale (EX-9.6) : leur valeur est lue telle quelle.

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/crypto/cryptobyte"
	casn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// profondeurDER : profondeur d'imbrication DER maximale (EX-9.4, EX-15.1).
const profondeurDER = 32

// Étiquettes utilisées hors des constantes de cryptobyte.
const (
	tagBMPString     = casn1.Tag(30)
	tagNumericString = casn1.Tag(18)
)

// ctx rend l'étiquette « [n] » de classe contextuelle, construite ou non.
func ctx(n uint8, construit bool) casn1.Tag {
	t := casn1.Tag(n).ContextSpecific()
	if construit {
		t = t.Constructed()
	}
	return t
}

// defaut : défaut de lecture, nommé dans les deux langues.
type defaut struct {
	fr, en string
}

func (d *defaut) Error() string { return d.fr }

func def(fr, en string) *defaut { return &defaut{fr: fr, en: en} }

func defF(fr, en string, args ...any) *defaut {
	return &defaut{fr: fmt.Sprintf(fr, args...), en: fmt.Sprintf(en, args...)}
}

// prefixer place un contexte devant le défaut (« certificat 1 du jeton : … »).
func prefixer(d *defaut, fr, en string) *defaut {
	return &defaut{fr: fr + d.fr, en: en + d.en}
}

var (
	errEncodage = def("encodage DER contraire au profil de §9.3 (étiquette, longueur ou structure)", "DER encoding contrary to the §9.3 profile (tag, length or structure)")
)

// verifierProfil parcourt une structure DER complète : chaque élément se lit
// selon cryptobyte, chaque BOOLEAN vaut 00 ou ff, la profondeur ne dépasse
// pas 32 à partir de base (0 pour une structure de premier niveau), et
// aucun octet ne suit la structure.
func verifierProfil(der []byte, base int) *defaut {
	s := cryptobyte.String(der)
	if d := parcourir(&s, base+1); d != nil {
		return d
	}
	if !s.Empty() {
		return def("octets après la fin de la structure DER", "bytes after the end of the DER structure")
	}
	return nil
}

// parcourir lit un élément et, s'il est construit, ses éléments ; la
// profondeur est bornée, donc la récursion aussi (EX-15.2).
func parcourir(s *cryptobyte.String, prof int) *defaut {
	if prof > profondeurDER {
		return def("profondeur d'imbrication DER supérieure à 32", "DER nesting depth greater than 32")
	}
	var contenu cryptobyte.String
	var tag casn1.Tag
	if !s.ReadAnyASN1(&contenu, &tag) {
		return errEncodage
	}
	if tag&0x20 != 0 {
		for !contenu.Empty() {
			if d := parcourir(&contenu, prof+1); d != nil {
				return d
			}
		}
		return nil
	}
	if tag == casn1.BOOLEAN && (len(contenu) != 1 || (contenu[0] != 0 && contenu[0] != 0xff)) {
		return def("BOOLEAN codé autrement que 00 ou ff", "BOOLEAN encoded otherwise than 00 or ff")
	}
	return nil
}

// lireEntier lit un INTEGER et rend ses octets de valeur, non vides, tels
// qu'encodés (EX-9.6 : la forme minimale n'est pas contrôlée).
func lireEntier(s *cryptobyte.String, tag casn1.Tag) ([]byte, bool) {
	var c cryptobyte.String
	if !s.ReadASN1(&c, tag) || len(c) == 0 {
		return nil, false
	}
	return []byte(c), true
}

// valeurEntier interprète des octets d'INTEGER en complément à deux.
func valeurEntier(b []byte) *big.Int {
	v := new(big.Int).SetBytes(b)
	if len(b) > 0 && b[0]&0x80 != 0 {
		v.Sub(v, new(big.Int).Lsh(big.NewInt(1), uint(len(b))*8))
	}
	return v
}

// petitEntier rend la valeur d'un INTEGER qui tient dans un int64.
func petitEntier(b []byte) (int64, bool) {
	v := valeurEntier(b)
	if !v.IsInt64() {
		return 0, false
	}
	return v.Int64(), true
}

// memeEntier compare deux INTEGER par leur valeur.
func memeEntier(a, b []byte) bool {
	return valeurEntier(a).Cmp(valeurEntier(b)) == 0
}

// lireOID lit un OBJECT IDENTIFIER.
func lireOID(s *cryptobyte.String) (asn1.ObjectIdentifier, bool) {
	var o asn1.ObjectIdentifier
	if !s.ReadASN1ObjectIdentifier(&o) {
		return nil, false
	}
	return o, true
}

// algo : AlgorithmIdentifier (RFC 5280 §4.1.1.2).
type algo struct {
	oid asn1.ObjectIdentifier
	// params : élément DER complet des paramètres, ou nil s'ils sont absents.
	params []byte
}

// paramsNulOuAbsents : paramètres absents ou NULL (05 00).
func (a algo) paramsNulOuAbsents() bool {
	return a.params == nil || bytes.Equal(a.params, []byte{0x05, 0x00})
}

func lireAlgo(s *cryptobyte.String) (algo, bool) {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, casn1.SEQUENCE) {
		return algo{}, false
	}
	o, ok := lireOID(&seq)
	if !ok {
		return algo{}, false
	}
	a := algo{oid: o}
	if !seq.Empty() {
		var p cryptobyte.String
		var t casn1.Tag
		if !seq.ReadAnyASN1Element(&p, &t) || !seq.Empty() {
			return algo{}, false
		}
		a.params = []byte(p)
	}
	return a, true
}

// lireNom lit un Name (élément complet) et contrôle ses chaînes (EX-9.4) :
// une UTF8String doit être de l'UTF-8 valide, une BMPString de longueur
// paire. Il rend aussi la valeur du premier commonName, ou nil (EX-9.19).
func lireNom(s *cryptobyte.String) ([]byte, *string, *defaut) {
	var brut cryptobyte.String
	if !s.ReadASN1Element(&brut, casn1.SEQUENCE) {
		return nil, nil, def("Name illisible", "unreadable Name")
	}
	cn, d := analyserNom(brut)
	return []byte(brut), cn, d
}

// analyserNom contrôle un Name déjà délimité (élément complet).
func analyserNom(brut []byte) (*string, *defaut) {
	s := cryptobyte.String(brut)
	var rdns cryptobyte.String
	if !s.ReadASN1(&rdns, casn1.SEQUENCE) || !s.Empty() {
		return nil, def("Name illisible", "unreadable Name")
	}
	var cn *string
	cnVu := false
	for !rdns.Empty() {
		var rdn cryptobyte.String
		if !rdns.ReadASN1(&rdn, casn1.SET) {
			return nil, def("RelativeDistinguishedName illisible", "unreadable RelativeDistinguishedName")
		}
		for !rdn.Empty() {
			var atv cryptobyte.String
			if !rdn.ReadASN1(&atv, casn1.SEQUENCE) {
				return nil, def("AttributeTypeAndValue illisible", "unreadable AttributeTypeAndValue")
			}
			o, ok := lireOID(&atv)
			var val cryptobyte.String
			var tag casn1.Tag
			if !ok || !atv.ReadAnyASN1(&val, &tag) || !atv.Empty() {
				return nil, def("AttributeTypeAndValue illisible", "unreadable AttributeTypeAndValue")
			}
			switch tag {
			case casn1.UTF8String:
				if !utf8.Valid(val) {
					return nil, def("UTF8String d'un nom qui n'est pas de l'UTF-8 valide (EX-9.4)", "UTF8String in a name that is not valid UTF-8 (EX-9.4)")
				}
			case tagBMPString:
				if len(val)%2 != 0 {
					return nil, def("BMPString d'un nom de longueur impaire (EX-9.4)", "BMPString in a name of odd length (EX-9.4)")
				}
			}
			if !cnVu && o.Equal(oidCommonName) {
				cnVu = true
				cn = decoderChaine(tag, val)
			}
		}
	}
	return cn, nil
}

// decoderChaine décode la valeur d'un attribut de nom pour tsu_subject_cn
// (EX-9.19) ; un autre type de chaîne, ou une valeur vide, donne nil.
func decoderChaine(tag casn1.Tag, val []byte) *string {
	var s string
	switch tag {
	case casn1.UTF8String:
		s = string(val)
	case casn1.PrintableString, casn1.IA5String, casn1.T61String, tagNumericString:
		// Octets lus comme ISO 8859-1 : identique à l'ASCII pour les
		// caractères admis par ces types, et toujours de l'UTF-8 valide.
		var b strings.Builder
		for _, c := range val {
			b.WriteRune(rune(c))
		}
		s = b.String()
	case tagBMPString:
		u := make([]uint16, len(val)/2)
		for i := range u {
			u[i] = uint16(val[2*i])<<8 | uint16(val[2*i+1])
		}
		s = string(utf16.Decode(u))
	default:
		return nil
	}
	if s == "" {
		return nil
	}
	return &s
}

// lireTemps lit un Time de certificat ou de CRL (RFC 5280 §4.1.2.5) :
// UTCTime « AAMMJJhhmmssZ » (20AA pour AA < 50, 19AA sinon) ou
// GeneralizedTime « AAAAMMJJhhmmssZ », date existante.
func lireTemps(s *cryptobyte.String) (time.Time, bool) {
	var c cryptobyte.String
	switch {
	case s.PeekASN1Tag(casn1.UTCTime):
		if !s.ReadASN1(&c, casn1.UTCTime) || len(c) != 13 || c[12] != 'Z' {
			return time.Time{}, false
		}
		aa, ok := chiffres(c[0:2])
		if !ok {
			return time.Time{}, false
		}
		an := 2000 + aa
		if aa >= 50 {
			an = 1900 + aa
		}
		return dateHeure(an, c[2:12])
	case s.PeekASN1Tag(casn1.GeneralizedTime):
		if !s.ReadASN1(&c, casn1.GeneralizedTime) || len(c) != 15 || c[14] != 'Z' {
			return time.Time{}, false
		}
		an, ok := chiffres(c[0:4])
		if !ok {
			return time.Time{}, false
		}
		return dateHeure(an, c[4:14])
	}
	return time.Time{}, false
}

// chiffres lit un entier décimal non signé de chiffres ASCII.
func chiffres(b []byte) (int, bool) {
	if len(b) == 0 {
		return 0, false
	}
	v := 0
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, false
		}
		v = v*10 + int(c-'0')
	}
	return v, true
}

// dateHeure lit « MMJJhhmmss » et refuse une date qui n'existe pas.
func dateHeure(an int, b []byte) (time.Time, bool) {
	mo, ok1 := chiffres(b[0:2])
	jo, ok2 := chiffres(b[2:4])
	he, ok3 := chiffres(b[4:6])
	mi, ok4 := chiffres(b[6:8])
	se, ok5 := chiffres(b[8:10])
	if !(ok1 && ok2 && ok3 && ok4 && ok5) || mo < 1 || mo > 12 || jo < 1 || he > 23 || mi > 59 || se > 59 {
		return time.Time{}, false
	}
	t := time.Date(an, time.Month(mo), jo, he, mi, se, 0, time.UTC)
	if t.Year() != an || int(t.Month()) != mo || t.Day() != jo {
		return time.Time{}, false
	}
	return t, true
}

// extension : Extension (RFC 5280 §4.1).
type extension struct {
	oid      asn1.ObjectIdentifier
	critique bool
	// critiqueFauxEncode : le champ critical est encodé à FALSE (01 01 00).
	critiqueFauxEncode bool
	valeur             []byte
}

// lireExtensions lit une SEQUENCE OF Extension.
func lireExtensions(s *cryptobyte.String) ([]extension, bool) {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, casn1.SEQUENCE) {
		return nil, false
	}
	return lireListeExtensions(seq)
}

// lireListeExtensions lit les Extension successives d'un contenu déjà
// délimité (Extensions [1] IMPLICIT de TSTInfo).
func lireListeExtensions(seq cryptobyte.String) ([]extension, bool) {
	var out []extension
	for !seq.Empty() {
		var e cryptobyte.String
		if !seq.ReadASN1(&e, casn1.SEQUENCE) {
			return nil, false
		}
		o, ok := lireOID(&e)
		if !ok {
			return nil, false
		}
		x := extension{oid: o}
		if e.PeekASN1Tag(casn1.BOOLEAN) {
			if !e.ReadASN1Boolean(&x.critique) {
				return nil, false
			}
			x.critiqueFauxEncode = !x.critique
		}
		var v cryptobyte.String
		if !e.ReadASN1(&v, casn1.OCTET_STRING) || !e.Empty() {
			return nil, false
		}
		x.valeur = []byte(v)
		out = append(out, x)
	}
	return out, true
}
