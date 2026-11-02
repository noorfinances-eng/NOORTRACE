package registre

// Certificat de commit (11.3.3) : lecture des lignes (EX-11.6), condensé
// signé (EX-11.7), signature secp256k1 R ‖ S ‖ V (EX-14.2), hachage d'un jeu
// de validateurs et quorum (EX-11.8), vérification d'un certificat (R-5,
// EX-11.14).
//
// Lecture des lignes. CT-6 EX-11.6 renvoie au décodeur du nœud, et CT-4 §9.2
// en donne la règle : noms comparés sans la casse, dernière occurrence
// retenue, membres inconnus ignorés, octets binaires en base64 standard. Le
// nœud est écrit en Go et décode ses enveloppes avec encoding/json ; ce
// paquet emploie le même décodeur, dans les mêmes types, pour accepter ni
// plus ni moins que lui. Une ligne acceptée est canonique si elle est égale,
// octet pour octet, à la sérialisation de l'enveloppe décodée par
// encoding/json (ordre et casse des membres du nœud) ; sinon AV-R-2.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/noorfinances-eng/noortrace/verificateur/ancres"
	"github.com/noorfinances-eng/noortrace/verificateur/commun"
)

// Constantes du condensé signé (EX-11.7) et du hachage d'un jeu (EX-11.8).
const (
	domaineBFT           = "noor/v1/bft"
	prefixeSignature     = "noor/v1/bft-sign|"
	prefixeValset        = "noor/v1/valsethash|"
	typeProposition      = "CONS_PROPOSAL"
	typePrecommit        = "CONS_PRECOMMIT"
	typeVotePrecommit    = 2
	longueurSignature    = 65
	longueurHachageLigne = 32
)

// enveloppe : une ligne de certificat, dans la forme du nœud.
type enveloppe struct {
	Domain      string          `json:"domain"`
	ChainID     string          `json:"chainId"`
	Type        string          `json:"type"`
	ValidatorID string          `json:"validatorId"`
	ValsetHash  []byte          `json:"valsetHash"`
	Height      uint64          `json:"height"`
	Round       uint64          `json:"round"`
	BlockHash   []byte          `json:"blockHash"`
	BodyHash    []byte          `json:"bodyHash"`
	Body        json.RawMessage `json:"body"`
	Sig         []byte          `json:"sig"`
}

// corpsProposition : les membres du corps d'une proposition que R-5 compare
// (objet Proposal du nœud, CT-4 §9.2).
type corpsProposition struct {
	Height    uint64 `json:"height"`
	Round     uint64 `json:"round"`
	Proposer  string `json:"proposer"`
	BlockHash string `json:"blockHash"`
}

// corpsVote : les membres du corps d'un precommit (objet Vote du nœud).
type corpsVote struct {
	Height    uint64 `json:"Height"`
	Round     uint64 `json:"Round"`
	Voter     string `json:"Voter"`
	Type      int64  `json:"Type"`
	BlockHash string `json:"BlockHash"`
}

// lireLigne décode une ligne comme le nœud ; canonique dit si la ligne est
// la sérialisation de l'enveloppe décodée.
func lireLigne(ligne string) (env enveloppe, canonique bool, err error) {
	if err = json.Unmarshal([]byte(ligne), &env); err != nil {
		return env, false, err
	}
	b, e := json.Marshal(&env)
	return env, e == nil && bytes.Equal(b, []byte(ligne)), nil
}

func lp(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

// condenseSigne rend le condensé de EX-11.7 d'une enveloppe dont les
// hachages ont 32 octets.
func condenseSigne(e *enveloppe) [32]byte {
	var b []byte
	b = append(b, prefixeSignature...)
	b = lp(b, domaineBFT)
	b = lp(b, e.ChainID)
	b = lp(b, e.Type)
	b = lp(b, e.ValidatorID)
	b = append(b, e.ValsetHash...)
	b = binary.BigEndian.AppendUint64(b, e.Height)
	b = binary.BigEndian.AppendUint64(b, e.Round)
	b = append(b, e.BlockHash...)
	b = append(b, e.BodyHash...)
	return sha256.Sum256(b)
}

var demiOrdre = func() *big.Int {
	n := new(big.Int).Set(secp256k1.S256().N)
	return n.Rsh(n, 1)
}()

// recouvrer rend la clé publique non compressée qui a produit une
// signature R ‖ S ‖ V (V dans {0, 1}, S bas, EX-11.7, EX-14.2) sur un
// condensé de 32 octets.
func recouvrer(condense [32]byte, sig []byte) ([]byte, error) {
	if len(sig) != longueurSignature {
		return nil, fmt.Errorf("signature de %d octets au lieu de 65", len(sig))
	}
	v := sig[64]
	if v > 1 {
		return nil, fmt.Errorf("V vaut %d, hors de {0, 1}", v)
	}
	if new(big.Int).SetBytes(sig[32:64]).Cmp(demiOrdre) > 0 {
		return nil, fmt.Errorf("S haut")
	}
	compacte := make([]byte, 65)
	compacte[0] = 27 + v
	copy(compacte[1:], sig[:64])
	cle, _, err := ecdsa.RecoverCompact(compacte, condense[:])
	if err != nil {
		return nil, err
	}
	return cle.SerializeUncompressed(), nil
}

// cleNonCompressee ramène la clé déclarée d'un validateur (33, 64 ou 65
// octets) à sa forme non compressée (EX-11.7).
func cleNonCompressee(b []byte) ([]byte, bool) {
	if len(b) == 64 {
		b = append([]byte{0x04}, b...)
	}
	if len(b) != 33 && len(b) != 65 {
		return nil, false
	}
	c, err := secp256k1.ParsePubKey(b)
	if err != nil {
		return nil, false
	}
	return c.SerializeUncompressed(), true
}

// hachageJeu rend le hachage d'un jeu de validateurs (EX-11.8) : clés telles
// que déclarées, identifiants dans l'ordre croissant de leurs octets.
func hachageJeu(jeu *ancres.JeuValidateurs) [32]byte {
	vs := append([]ancres.Validateur{}, jeu.Validateurs...)
	sort.SliceStable(vs, func(i, j int) bool { return vs[i].ID < vs[j].ID })
	b := []byte(prefixeValset)
	for _, v := range vs {
		b = append(b, v.ID...)
		b = append(b, 0)
		b = append(b, v.Cle...)
		b = append(b, 0)
	}
	return sha256.Sum256(b)
}

// quorum de N validateurs (EX-11.8) : ⌊(N + f) / 2⌋ + 1, f = ⌊(N − 1) / 3⌋.
func quorum(n int) int {
	if n <= 0 {
		return 1
	}
	f := (n - 1) / 3
	return (n+f)/2 + 1
}

// hachageCorps lit le blockHash d'un corps (« 0x » et 64 hexadécimaux).
func hachageCorps(s string) ([]byte, bool) {
	if len(s) != 66 || s[0] != '0' || (s[1] != 'x' && s[1] != 'X') {
		return nil, false
	}
	b, err := hex.DecodeString(s[2:])
	return b, err == nil
}

// ligneCertificat : le résultat de la lecture d'une ligne d'un certificat.
type ligneCertificat struct {
	indice     int // 0 : proposition ; k ≥ 1 : precommit k − 1
	validateur string
	canonique  bool
	defaut     string // vide si la ligne est valide
	defautEn   string
}

// verifierLigne applique EX-11.14 à une ligne d'un certificat, contre le jeu
// de l'ancre retenu par R-2.
func verifierLigne(ligne string, attendu string, c *certificat, cles map[string][]byte) ligneCertificat {
	var r ligneCertificat
	env, canon, err := lireLigne(ligne)
	if err != nil {
		r.defaut, r.defautEn = "ligne illisible par le décodeur du nœud ("+err.Error()+")", "line unreadable by the node decoder ("+err.Error()+")"
		return r
	}
	r.canonique, r.validateur = canon, env.ValidatorID
	ko := func(fr, en string) ligneCertificat {
		r.defaut, r.defautEn = fr, en
		return r
	}
	switch {
	case env.Domain != domaineBFT:
		return ko("domaine « "+env.Domain+" » différent de noor/v1/bft", "domain “"+env.Domain+"” differs from noor/v1/bft")
	case env.Type != attendu:
		return ko("type « "+env.Type+" » au lieu de "+attendu, "type “"+env.Type+"” instead of "+attendu)
	case env.ChainID != c.chainID:
		return ko("chainId différent de celui du certificat", "chainId differs from the certificate's")
	case len(env.ValsetHash) != longueurHachageLigne || !bytes.Equal(env.ValsetHash, c.valset[:]):
		return ko("valsetHash différent de celui du certificat", "valsetHash differs from the certificate's")
	case env.Height != c.hauteur || env.Round != c.tour:
		return ko(fmt.Sprintf("hauteur %d ou tour %d différents du certificat", env.Height, env.Round), fmt.Sprintf("height %d or round %d differ from the certificate", env.Height, env.Round))
	case len(env.BlockHash) != longueurHachageLigne || !bytes.Equal(env.BlockHash, c.bloc[:]):
		return ko("blockHash différent de celui du certificat", "blockHash differs from the certificate's")
	case len(env.BodyHash) != longueurHachageLigne:
		return ko("bodyHash de longueur différente de 32 octets", "bodyHash not 32 bytes long")
	}
	corps := sha256.Sum256(env.Body)
	if !bytes.Equal(env.BodyHash, corps[:]) {
		return ko("bodyHash différent du SHA-256 des octets du corps", "bodyHash differs from the SHA-256 of the body bytes")
	}
	// Cohérence du corps.
	var h, t uint64
	var bloc, signataire string
	if attendu == typeProposition {
		var p corpsProposition
		if err := json.Unmarshal(env.Body, &p); err != nil {
			return ko("corps de proposition illisible ("+err.Error()+")", "unreadable proposal body ("+err.Error()+")")
		}
		h, t, bloc, signataire = p.Height, p.Round, p.BlockHash, p.Proposer
	} else {
		var v corpsVote
		if err := json.Unmarshal(env.Body, &v); err != nil {
			return ko("corps de precommit illisible ("+err.Error()+")", "unreadable precommit body ("+err.Error()+")")
		}
		if v.Type != typeVotePrecommit {
			return ko(fmt.Sprintf("vote de type %d au lieu de 2", v.Type), fmt.Sprintf("vote of type %d instead of 2", v.Type))
		}
		h, t, bloc, signataire = v.Height, v.Round, v.BlockHash, v.Voter
	}
	if h != c.hauteur || t != c.tour {
		return ko("hauteur ou tour du corps différents du certificat", "body height or round differ from the certificate")
	}
	if b, ok := hachageCorps(bloc); !ok || !bytes.Equal(b, c.bloc[:]) {
		return ko("bloc du corps différent du blockHash du certificat", "body block differs from the certificate blockHash")
	}
	if signataire != "" && signataire != env.ValidatorID {
		return ko("signataire du corps « "+signataire+" » différent de validatorId", "body signer “"+signataire+"” differs from validatorId")
	}
	cle, ok := cles[env.ValidatorID]
	if !ok {
		return ko("validateur « "+env.ValidatorID+" » absent du jeu de l'ancre", "validator “"+env.ValidatorID+"” not in the anchor set")
	}
	rec, err := recouvrer(condenseSigne(&env), env.Sig)
	if err != nil {
		return ko("signature refusée ("+err.Error()+")", "signature refused ("+err.Error()+")")
	}
	if !bytes.Equal(rec, cle) {
		return ko("signature d'une autre clé que celle de "+env.ValidatorID, "signature by another key than that of "+env.ValidatorID)
	}
	return r
}

// resultatR5 : R-5 pour un certificat.
type resultatR5 struct {
	valide       bool
	detail       commun.Texte
	signataires  []string // identifiants distincts des precommits valides, croissants
	nonCanonique []ligneCertificat
}

// verifierCertificat applique EX-11.14 à un certificat, contre le jeu de
// l'ancre retenu par R-2.
func verifierCertificat(c *certificat, jeu *ancres.JeuValidateurs) resultatR5 {
	var r resultatR5
	cles := map[string][]byte{}
	for _, v := range jeu.Validateurs {
		if u, ok := cleNonCompressee(v.Cle); ok {
			cles[v.ID] = u
		}
	}
	var defauts, defautsEn []string
	vus := map[string]bool{}
	lignes := append([]string{c.proposition}, c.precommits...)
	for i, l := range lignes {
		attendu := typePrecommit
		nom, nomEn := fmt.Sprintf("precommit %d", i-1), fmt.Sprintf("precommit %d", i-1)
		if i == 0 {
			attendu, nom, nomEn = typeProposition, "proposition", "proposal"
		}
		lc := verifierLigne(l, attendu, c, cles)
		lc.indice = i
		if lc.defaut == "" && !lc.canonique {
			r.nonCanonique = append(r.nonCanonique, lc)
		}
		if lc.defaut != "" {
			defauts = append(defauts, nom+" : "+lc.defaut)
			defautsEn = append(defautsEn, nomEn+": "+lc.defautEn)
			continue
		}
		if i == 0 {
			continue
		}
		if vus[lc.validateur] {
			defauts = append(defauts, nom+" : signataire "+lc.validateur+" déjà compté")
			defautsEn = append(defautsEn, nomEn+": signer "+lc.validateur+" already counted")
			continue
		}
		vus[lc.validateur] = true
		r.signataires = append(r.signataires, lc.validateur)
	}
	sort.Strings(r.signataires)
	q := quorum(len(jeu.Validateurs))
	if len(defauts) == 0 && len(r.signataires) < q {
		defauts = append(defauts, fmt.Sprintf("%d signataires distincts, sous le quorum de %d", len(r.signataires), q))
		defautsEn = append(defautsEn, fmt.Sprintf("%d distinct signers, below the quorum of %d", len(r.signataires), q))
	}
	if len(defauts) > 0 {
		r.detail = texte(fmt.Sprintf("bloc %d : %s", c.hauteur, strings.Join(defauts, " ; ")), fmt.Sprintf("block %d: %s", c.hauteur, strings.Join(defautsEn, "; ")))
		return r
	}
	r.valide = true
	r.detail = texte(fmt.Sprintf("bloc %d : %d sur %d (%s), quorum %d", c.hauteur, len(r.signataires), len(jeu.Validateurs), strings.Join(r.signataires, ", "), q),
		fmt.Sprintf("block %d: %d of %d (%s), quorum %d", c.hauteur, len(r.signataires), len(jeu.Validateurs), strings.Join(r.signataires, ", "), q))
	return r
}
