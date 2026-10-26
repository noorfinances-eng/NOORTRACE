// DER (ITU-T X.690) : lecteur borné, TimeStampReq de CT-5 EX-5.1 construite
// octet pour octet et relue (AN-5, AN-6), TimeStampResp (RFC 3161 §2.4.2 :
// PKIStatusInfo, PKIFailureInfo, TimeStampToken) et TSTInfo (politique,
// messageImprint, numéro de série, genTime, accuracy, nonce). Les
// vérifications T-1 à T-9 de CT-6 ne sont pas refaites ici (CT-5 EX-A.4) :
// la lecture du TSTInfo suffit au classement d'EX-5.10.

package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ErreurAncrage signale un refus (construction ou lecture hors de CT-5),
// avec la vérification AN- en cause quand elle est nommée.
type ErreurAncrage struct {
	Regle string
	Msg   string
}

func (e *ErreurAncrage) Error() string { return e.Msg }

func refus(regle, format string, args ...any) *ErreurAncrage {
	return &ErreurAncrage{Regle: regle, Msg: fmt.Sprintf(format, args...)}
}

// AlgorithmeSHA256DER est l'AlgorithmIdentifier sha256 à paramètres NULL
// explicites (EX-5.1, EX-5.2).
var AlgorithmeSHA256DER = []byte{0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00}

// OIDSHA256 est l'OID de SHA-256 (2.16.840.1.101.3.4.2.1).
const OIDSHA256 = "2.16.840.1.101.3.4.2.1"

// TailleMaxReponse est la taille maximale du corps d'une réponse (EX-5.5).
const TailleMaxReponse = 128 * 1024

var nonceMax = new(big.Int).SetUint64(math.MaxUint64)
var reOID = regexp.MustCompile(`^[0-2](\.(0|[1-9][0-9]*))+$`)
var reHex32 = regexp.MustCompile(`^0x[0-9a-f]{64}$`)

// --- écriture ----------------------------------------------------------------

func longueurDER(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	case n < 0x10000:
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
	return []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}
}

func tlv(etiquette byte, corps []byte) []byte {
	out := []byte{etiquette}
	out = append(out, longueurDER(len(corps))...)
	return append(out, corps...)
}

// EncoderEntierDER rend l'INTEGER DER minimal d'un entier non négatif (octet
// 00 de tête seulement si le bit haut vaut 1).
func EncoderEntierDER(v *big.Int) ([]byte, error) {
	if v.Sign() < 0 {
		return nil, refus("", "INTEGER DER : entier non négatif attendu")
	}
	octets := v.Bytes()
	if len(octets) == 0 {
		octets = []byte{0}
	}
	if octets[0]&0x80 != 0 {
		octets = append([]byte{0}, octets...)
	}
	return tlv(0x02, octets), nil
}

func base128(n int64) []byte {
	b := []byte{byte(n & 0x7f)}
	n /= 128
	for n > 0 {
		b = append([]byte{byte(n&0x7f) | 0x80}, b...)
		n /= 128
	}
	return b
}

// EncoderOIDDER rend l'OBJECT IDENTIFIER DER d'un OID en notation pointée.
func EncoderOIDDER(texte string) ([]byte, error) {
	if !reOID.MatchString(texte) {
		return nil, refus("", "OID invalide : %q", texte)
	}
	parties := strings.Split(texte, ".")
	arcs := make([]int64, len(parties))
	for i, p := range parties {
		arcs[i], _ = strconv.ParseInt(p, 10, 64)
	}
	if arcs[0] < 2 && arcs[1] > 39 {
		return nil, refus("", "OID invalide : %s", texte)
	}
	octets := base128(arcs[0]*40 + arcs[1])
	for _, a := range arcs[2:] {
		octets = append(octets, base128(a)...)
	}
	return tlv(0x06, octets), nil
}

// OctetsEmpreinte lit une empreinte 0x de 32 octets (AN-5).
func OctetsEmpreinte(digest string) ([]byte, error) {
	if !reHex32.MatchString(digest) {
		return nil, refus("AN-5", "empreinte : 32 octets attendus (SHA-256)")
	}
	b, _ := hex.DecodeString(digest[2:])
	return b, nil
}

// ConstruireRequete construit la TimeStampReq d'EX-5.1, octet pour octet :
// version 1, messageImprint SHA-256 (paramètres NULL), reqPolicy si
// policyOID est non nul, nonce de 64 bits (INTEGER minimal), certReq TRUE.
// Refuse tout ce qui n'est pas une requête de CT-5 (AN-5, AN-6).
func ConstruireRequete(digest string, nonce *big.Int, policyOID *string, certReq bool) ([]byte, error) {
	empreinte, err := OctetsEmpreinte(digest)
	if err != nil {
		return nil, err
	}
	if nonce == nil {
		return nil, refus("AN-6", "nonce : entier attendu")
	}
	if nonce.Sign() < 1 || nonce.Cmp(nonceMax) > 0 {
		return nil, refus("AN-6", "nonce %s hors de [1, 2^64 - 1]", nonce.String())
	}
	if !certReq {
		return nil, refus("AN-5", "certReq vaut toujours TRUE (EX-5.4)")
	}
	version, _ := EncoderEntierDER(big.NewInt(1))
	mi := tlv(0x30, append(append([]byte{}, AlgorithmeSHA256DER...), tlv(0x04, empreinte)...))
	corps := append(version, mi...)
	if policyOID != nil {
		oid, err := EncoderOIDDER(*policyOID)
		if err != nil {
			return nil, err
		}
		corps = append(corps, oid...)
	}
	n, _ := EncoderEntierDER(nonce)
	corps = append(corps, n...)
	corps = append(corps, tlv(0x01, []byte{0xff})...)
	return tlv(0x30, corps), nil
}

// --- lecture ------------------------------------------------------------------

// Noeud est un élément DER : étiquette, contenu (Val), enfants pour une
// forme construite, et les octets complets de l'élément.
type Noeud struct {
	Etiquette byte
	Val       []byte
	Enfants   []*Noeud
	Octets    []byte
}

type erreurDER struct{ msg string }

func (e *erreurDER) Error() string { return e.msg }

func lireEnTete(buf []byte, pos int) (etiquette byte, debut, fin int, err error) {
	if pos+2 > len(buf) {
		return 0, 0, 0, &erreurDER{"DER tronqué"}
	}
	etiquette = buf[pos]
	if etiquette&0x1f == 0x1f {
		return 0, 0, 0, &erreurDER{"étiquette DER multi-octets non admise"}
	}
	longueur := int(buf[pos+1])
	p := pos + 2
	if longueur&0x80 != 0 {
		n := longueur & 0x7f
		if n == 0 || n > 4 || p+n > len(buf) {
			return 0, 0, 0, &erreurDER{"longueur DER mal formée"}
		}
		longueur = 0
		for i := 0; i < n; i++ {
			longueur = longueur*256 + int(buf[p])
			p++
		}
		if longueur < 0x80 || (n >= 2 && longueur < 1<<(8*(n-1))) {
			return 0, 0, 0, &erreurDER{"longueur DER non minimale"}
		}
	}
	if p+longueur > len(buf) {
		return 0, 0, 0, &erreurDER{"DER tronqué"}
	}
	return etiquette, p, p + longueur, nil
}

func lireNoeud(buf []byte, pos int, prof int) (*Noeud, int, error) {
	if prof > 32 {
		return nil, 0, &erreurDER{"imbrication DER trop profonde"}
	}
	etiquette, debut, fin, err := lireEnTete(buf, pos)
	if err != nil {
		return nil, 0, err
	}
	n := &Noeud{Etiquette: etiquette, Val: buf[debut:fin], Octets: buf[pos:fin]}
	if etiquette&0x20 != 0 {
		p := debut
		for p < fin {
			e, suivant, err := lireNoeud(buf, p, prof+1)
			if err != nil {
				return nil, 0, err
			}
			if suivant > fin {
				return nil, 0, &erreurDER{"élément DER débordant de son conteneur"}
			}
			n.Enfants = append(n.Enfants, e)
			p = suivant
		}
	}
	return n, fin, nil
}

// ParseDER lit un élément DER qui occupe tout le tampon.
func ParseDER(buf []byte) (*Noeud, error) {
	n, fin, err := lireNoeud(buf, 0, 0)
	if err != nil {
		return nil, err
	}
	if fin != len(buf) {
		return nil, &erreurDER{fmt.Sprintf("%d octet(s) après l'élément DER", len(buf)-fin)}
	}
	return n, nil
}

func decoderOIDOctets(b []byte) (string, error) {
	if len(b) == 0 || b[len(b)-1]&0x80 != 0 {
		return "", &erreurDER{"OID mal formé"}
	}
	var arcs []int64
	var v int64
	for i := 0; i < len(b); i++ {
		if v == 0 && b[i] == 0x80 {
			return "", &erreurDER{"OID : sous-identifiant non minimal"}
		}
		v = v*128 + int64(b[i]&0x7f)
		if b[i]&0x80 == 0 {
			arcs = append(arcs, v)
			v = 0
		}
	}
	premier := int64(2)
	if arcs[0] < 40 {
		premier = 0
	} else if arcs[0] < 80 {
		premier = 1
	}
	parties := []string{strconv.FormatInt(premier, 10), strconv.FormatInt(arcs[0]-premier*40, 10)}
	for _, a := range arcs[1:] {
		parties = append(parties, strconv.FormatInt(a, 10))
	}
	return strings.Join(parties, "."), nil
}

// entierDER lit un INTEGER DER (complément à deux) en big.Int.
func entierDER(b []byte) *big.Int {
	if len(b) == 0 {
		return new(big.Int)
	}
	v := new(big.Int).SetBytes(b)
	if b[0]&0x80 != 0 {
		v.Sub(v, new(big.Int).Lsh(big.NewInt(1), uint(8*len(b))))
	}
	return v
}

// Requete est une TimeStampReq relue.
type Requete struct {
	Digest    string
	PolicyOID *string
	Nonce     *big.Int
}

// LireRequete relit une TimeStampReq de CT-5 ; refuse toute forme hors
// d'EX-5.1 (AN-5).
func LireRequete(octets []byte) (*Requete, error) {
	racine, err := ParseDER(octets)
	if err != nil {
		return nil, refus("AN-5", "TimeStampReq : %s", err.Error())
	}
	if racine.Etiquette != 0x30 {
		return nil, refus("AN-5", "TimeStampReq : SEQUENCE attendue sur tout le fichier")
	}
	e := racine.Enfants
	i := 0
	suivant := func(etiquette byte, quoi string) ([]byte, error) {
		if i >= len(e) {
			return nil, refus("AN-5", "%s : DER tronqué", quoi)
		}
		if e[i].Etiquette != etiquette {
			return nil, refus("AN-5", "%s : étiquette 0x%x, attendue 0x%x", quoi, e[i].Etiquette, etiquette)
		}
		v := e[i].Val
		i++
		return v, nil
	}
	version, err := suivant(0x02, "version")
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(version, []byte{1}) {
		return nil, refus("AN-5", "version : 1 attendue")
	}
	if i >= len(e) || e[i].Etiquette != 0x30 {
		return nil, refus("AN-5", "messageImprint : SEQUENCE attendue")
	}
	mi := e[i]
	i++
	if len(mi.Enfants) != 2 || !bytes.Equal(mi.Enfants[0].Octets, AlgorithmeSHA256DER) {
		return nil, refus("AN-5", "hashAlgorithm : sha256 avec paramètres NULL attendu (EX-5.2)")
	}
	hm := mi.Enfants[1]
	if hm.Etiquette != 0x04 || len(hm.Val) != 32 {
		return nil, refus("AN-5", "hashedMessage : OCTET STRING de 32 octets attendu")
	}
	r := &Requete{Digest: "0x" + hex.EncodeToString(hm.Val)}
	if i < len(e) && e[i].Etiquette == 0x06 {
		oid, err := decoderOIDOctets(e[i].Val)
		if err != nil {
			return nil, refus("AN-5", "reqPolicy : %s", err.Error())
		}
		r.PolicyOID = &oid
		i++
	}
	nonceOctets, err := suivant(0x02, "nonce")
	if err != nil {
		return nil, err
	}
	if len(nonceOctets) == 0 || len(nonceOctets) > 9 {
		return nil, refus("AN-5", "nonce : 1 à 9 octets attendus")
	}
	if nonceOctets[0]&0x80 != 0 {
		return nil, refus("AN-5", "nonce : entier négatif")
	}
	if len(nonceOctets) > 1 && nonceOctets[0] == 0 && nonceOctets[1]&0x80 == 0 {
		return nil, refus("AN-5", "nonce : zéro de tête superflu (encodage non minimal)")
	}
	r.Nonce = new(big.Int).SetBytes(nonceOctets)
	if r.Nonce.Sign() < 1 || r.Nonce.Cmp(nonceMax) > 0 {
		return nil, refus("AN-5", "nonce %s hors de [1, 2^64 - 1]", r.Nonce.String())
	}
	certReq, err := suivant(0x01, "certReq")
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(certReq, []byte{0xff}) {
		return nil, refus("AN-5", "certReq : TRUE (ff) attendu")
	}
	if i != len(e) {
		return nil, refus("AN-5", "champ supplémentaire après certReq")
	}
	return r, nil
}

// HexNonce écrit un nonce de 64 bits en hexadécimal 0x sur 16 chiffres.
func HexNonce(n *big.Int) string {
	s := n.Text(16)
	for len(s) < 16 {
		s = "0" + s
	}
	return "0x" + s
}

// --- TimeStampResp -----------------------------------------------------------------

// NomsFailureInfo nomme les bits de PKIFailureInfo (RFC 3161 §2.4.2).
var NomsFailureInfo = map[int]string{0: "badAlg", 2: "badRequest", 5: "badDataFormat", 14: "timeNotAvailable", 15: "unacceptedPolicy", 16: "unacceptedExtension", 17: "addInfoNotAvailable", 25: "systemFailure"}

// NomsPKI nomme les PKIStatus 0 à 5.
var NomsPKI = []string{"granted", "grantedWithMods", "rejection", "waiting", "revocationWarning", "revocationNotification"}

// ReponseTsa est une TimeStampResp relue.
type ReponseTsa struct {
	Status       int64
	StatusString *string
	FailInfo     *string
	FailInfoBits []int
	Token        []byte
}

// LireReponseTsa relit une TimeStampResp (RFC 3161 §2.4.2).
func LireReponseTsa(octets []byte) (*ReponseTsa, error) {
	if len(octets) > TailleMaxReponse {
		return nil, refus("", "réponse de %d octets, au plus %d", len(octets), TailleMaxReponse)
	}
	racine, err := ParseDER(octets)
	if err != nil {
		return nil, refus("", "TimeStampResp illisible : %s", err.Error())
	}
	if racine.Etiquette != 0x30 || len(racine.Enfants) < 1 || len(racine.Enfants) > 2 {
		return nil, refus("", "TimeStampResp : SEQUENCE { status, timeStampToken OPTIONAL } attendue")
	}
	psi := racine.Enfants[0]
	if psi.Etiquette != 0x30 || len(psi.Enfants) < 1 || len(psi.Enfants) > 3 {
		return nil, refus("", "PKIStatusInfo mal formé")
	}
	st := psi.Enfants[0]
	if st.Etiquette != 0x02 || len(st.Val) != 1 {
		return nil, refus("", "PKIStatusInfo.status : INTEGER d'un octet attendu")
	}
	r := &ReponseTsa{Status: int64(st.Val[0])}
	for _, n := range psi.Enfants[1:] {
		switch {
		case n.Etiquette == 0x30 && r.StatusString == nil && r.FailInfo == nil && r.FailInfoBits == nil:
			var parties []string
			for _, u := range n.Enfants {
				parties = append(parties, string(u.Val))
			}
			s := strings.Join(parties, " ")
			r.StatusString = &s
		case n.Etiquette == 0x03 && r.FailInfo == nil && r.FailInfoBits == nil:
			v := n.Val
			r.FailInfoBits = []int{}
			for i := 1; i < len(v); i++ {
				for b := 0; b < 8; b++ {
					if v[i]&(0x80>>b) != 0 {
						r.FailInfoBits = append(r.FailInfoBits, (i-1)*8+b)
					}
				}
			}
			if len(r.FailInfoBits) > 0 {
				nom, ok := NomsFailureInfo[r.FailInfoBits[0]]
				if !ok {
					nom = fmt.Sprintf("bit_%d", r.FailInfoBits[0])
				}
				r.FailInfo = &nom
			}
		default:
			return nil, refus("", "PKIStatusInfo : élément inattendu")
		}
	}
	if len(racine.Enfants) == 2 {
		if racine.Enfants[1].Etiquette != 0x30 {
			return nil, refus("", "timeStampToken : ContentInfo attendu")
		}
		r.Token = racine.Enfants[1].Octets
	}
	return r, nil
}

// --- TimeStampToken et TSTInfo ----------------------------------------------------------

const (
	oidSignedData = "1.2.840.113549.1.7.2"
	oidTSTInfo    = "1.2.840.113549.1.9.16.1.4"
)

// Precision est le champ accuracy de TSTInfo (sous-champs absents : nil).
type Precision struct{ Seconds, Millis, Micros *big.Int }

// Secondes rend la précision en secondes (sous-champs absents : zéro).
func (p *Precision) Secondes() float64 {
	f := func(v *big.Int) float64 {
		if v == nil {
			return 0
		}
		x, _ := new(big.Float).SetInt(v).Float64()
		return x
	}
	return f(p.Seconds) + f(p.Millis)/1000 + f(p.Micros)/1e6
}

// TSTInfo est le contenu horodaté d'un jeton (RFC 3161 §2.4.2).
type TSTInfo struct {
	Politique     string
	EmpreinteAlgo string
	Empreinte     []byte
	Numero        *big.Int
	GenTimeTexte  string
	Precision     *Precision
	Nonce         *big.Int
}

func oidDe(n *Noeud, quoi string) (string, error) {
	if n == nil || n.Etiquette != 0x06 {
		return "", &erreurDER{quoi + " : OBJECT IDENTIFIER attendu"}
	}
	return decoderOIDOctets(n.Val)
}

// LireJetonTST lit le TSTInfo d'un TimeStampToken (ContentInfo → SignedData
// → encapContentInfo → eContent), sans vérifier la signature (T-6) ni le
// chemin (T-7) : ces vérifications sont des entrées déclarées (EX-A.4).
func LireJetonTST(token []byte) (*TSTInfo, error) {
	ci, err := ParseDER(token)
	if err != nil {
		return nil, err
	}
	if ci.Etiquette != 0x30 || len(ci.Enfants) != 2 {
		return nil, &erreurDER{"ContentInfo mal formé"}
	}
	if oid, err := oidDe(ci.Enfants[0], "contentType"); err != nil || oid != oidSignedData {
		return nil, &erreurDER{"contentType différent de id-signedData"}
	}
	contenu := ci.Enfants[1]
	if contenu.Etiquette != 0xa0 || len(contenu.Enfants) != 1 || contenu.Enfants[0].Etiquette != 0x30 {
		return nil, &erreurDER{"content [0] mal formé"}
	}
	sd := contenu.Enfants[0].Enfants
	if len(sd) < 4 {
		return nil, &erreurDER{"SignedData mal formé"}
	}
	if sd[0].Etiquette != 0x02 || !bytes.Equal(sd[0].Val, []byte{3}) {
		return nil, &erreurDER{"SignedData.version 3 attendue"}
	}
	if sd[1].Etiquette != 0x31 {
		return nil, &erreurDER{"digestAlgorithms : SET attendu"}
	}
	eci := sd[2]
	if eci.Etiquette != 0x30 || len(eci.Enfants) != 2 {
		return nil, &erreurDER{"encapContentInfo sans eContent"}
	}
	if oid, err := oidDe(eci.Enfants[0], "eContentType"); err != nil || oid != oidTSTInfo {
		return nil, &erreurDER{"eContentType différent de id-ct-TSTInfo"}
	}
	ec := eci.Enfants[1]
	if ec.Etiquette != 0xa0 || len(ec.Enfants) != 1 || ec.Enfants[0].Etiquette != 0x04 {
		return nil, &erreurDER{"eContent [0] mal formé"}
	}
	if sd[len(sd)-1].Etiquette != 0x31 {
		return nil, &erreurDER{"signerInfos : SET attendu"}
	}
	return LireTSTInfo(ec.Enfants[0].Val)
}

// LireTSTInfo lit les octets de eContent (forme de T-1).
func LireTSTInfo(octets []byte) (*TSTInfo, error) {
	racine, err := ParseDER(octets)
	if err != nil {
		return nil, err
	}
	if racine.Etiquette != 0x30 {
		return nil, &erreurDER{"TSTInfo : SEQUENCE attendue"}
	}
	e := racine.Enfants
	if len(e) < 5 {
		return nil, &erreurDER{"TSTInfo tronqué"}
	}
	i := 0
	if e[i].Etiquette != 0x02 || !bytes.Equal(e[i].Val, []byte{1}) {
		return nil, &erreurDER{"TSTInfo.version 1 attendue"}
	}
	i++
	t := &TSTInfo{}
	if t.Politique, err = oidDe(e[i], "TSTInfo.policy"); err != nil {
		return nil, err
	}
	i++
	mi := e[i]
	if mi.Etiquette != 0x30 || len(mi.Enfants) != 2 {
		return nil, &erreurDER{"messageImprint mal formé"}
	}
	alg := mi.Enfants[0]
	if alg.Etiquette != 0x30 || len(alg.Enfants) < 1 || len(alg.Enfants) > 2 {
		return nil, &erreurDER{"messageImprint.hashAlgorithm mal formé"}
	}
	if t.EmpreinteAlgo, err = oidDe(alg.Enfants[0], "messageImprint.hashAlgorithm"); err != nil {
		return nil, err
	}
	if mi.Enfants[1].Etiquette != 0x04 {
		return nil, &erreurDER{"messageImprint.hashedMessage : OCTET STRING attendu"}
	}
	t.Empreinte = mi.Enfants[1].Val
	i++
	if e[i].Etiquette != 0x02 {
		return nil, &erreurDER{"TSTInfo.serialNumber : INTEGER attendu"}
	}
	t.Numero = entierDER(e[i].Val)
	i++
	if e[i].Etiquette != 0x18 {
		return nil, &erreurDER{"TSTInfo.genTime : GeneralizedTime attendu"}
	}
	t.GenTimeTexte = string(e[i].Val)
	i++
	if i < len(e) && e[i].Etiquette == 0x30 {
		p := &Precision{}
		for _, c := range e[i].Enfants {
			switch {
			case c.Etiquette == 0x02 && p.Seconds == nil && p.Millis == nil && p.Micros == nil:
				p.Seconds = entierDER(c.Val)
			case c.Etiquette == 0x80 && p.Millis == nil && p.Micros == nil:
				p.Millis = entierDER(c.Val)
			case c.Etiquette == 0x81 && p.Micros == nil:
				p.Micros = entierDER(c.Val)
			default:
				return nil, &erreurDER{"accuracy mal formé"}
			}
		}
		t.Precision = p
		i++
	}
	if i < len(e) && e[i].Etiquette == 0x01 {
		if !bytes.Equal(e[i].Val, []byte{0xff}) {
			return nil, &erreurDER{"ordering codé explicitement à FALSE"}
		}
		i++
	}
	if i < len(e) && e[i].Etiquette == 0x02 {
		t.Nonce = entierDER(e[i].Val)
		i++
	}
	if i < len(e) && e[i].Etiquette == 0xa0 {
		i++
	}
	if i < len(e) && e[i].Etiquette == 0xa1 {
		i++
	}
	if i != len(e) {
		return nil, &erreurDER{"élément inattendu dans TSTInfo"}
	}
	return t, nil
}

// --- GeneralizedTime ---------------------------------------------------------------------

// Instant est une seconde UNIX et une fraction décimale (texte, sans zéro final).
type Instant struct {
	S    int64
	Frac string
}

var reGenTime = regexp.MustCompile(`^([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})(?:\.([0-9]*[1-9]))?Z$`)

// LireGenTime lit un genTime AAAAMMJJhhmmss[.f]Z (fraction sans zéro final,
// date existante) ; nil sinon (CT-6 EX-9.15, règle 1).
func LireGenTime(texte string) *Instant {
	m := reGenTime.FindStringSubmatch(texte)
	if m == nil {
		return nil
	}
	n := func(s string) int { v, _ := strconv.Atoi(s); return v }
	a, mo, j, h, mi, s := n(m[1]), n(m[2]), n(m[3]), n(m[4]), n(m[5]), n(m[6])
	t := time.Date(a, time.Month(mo), j, h, mi, s, 0, time.UTC)
	if t.Year() != a || int(t.Month()) != mo || t.Day() != j || t.Hour() != h || t.Minute() != mi || t.Second() != s {
		return nil
	}
	return &Instant{S: t.Unix(), Frac: m[7]}
}

// RFC3339 écrit l'instant en RFC 3339 UTC, fraction seulement si non nulle.
func (i *Instant) RFC3339() string {
	base := time.Unix(i.S, 0).UTC().Format("2006-01-02T15:04:05")
	if i.Frac != "" {
		return base + "." + i.Frac + "Z"
	}
	return base + "Z"
}

// Ms rend l'instant en millisecondes UNIX (fraction arrondie à la milliseconde).
func (i *Instant) Ms() int64 {
	frac := i.Frac
	if frac == "" {
		frac = "0"
	}
	texte := "0." + frac
	if len(texte) > 12 {
		texte = texte[:12]
	}
	f, _ := strconv.ParseFloat(texte, 64)
	return i.S*1000 + int64(math.Round(f*1000))
}
