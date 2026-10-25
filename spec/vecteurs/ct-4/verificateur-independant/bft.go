// Bloc BFT, jeu de validateurs et certificat de commit, recalculés hors
// ligne comme le contrôle 8 de CT-6, que CT-4 CP-2 et CP-4 (9.4) et RG-19
// (6.8) reprennent :
//
//   - BFTBlockHash : keccak256 de la préimage de 212 octets de CT-6 EX-11.4
//     (étiquette « noor/v1/bftblockhash », parentHash, number, timestamp,
//     stateRoot, transactionsRoot, receiptsRoot, gasUsed, gasLimit,
//     baseFeePerGas) ;
//   - hachage d'un jeu : sha256("noor/v1/valsethash|" ‖ pour chaque
//     identifiant pris dans l'ordre croissant de ses octets : identifiant ‖
//     00 ‖ clé telle que déclarée ‖ 00) (CT-6 EX-11.8) ; quorum
//     ⌊(N + f)/2⌋ + 1, f = ⌊(N − 1)/3⌋ ;
//   - enveloppe signée : condensé sha256("noor/v1/bft-sign|" ‖ LP(domaine) ‖
//     LP(chainId) ‖ LP(type) ‖ LP(validatorId) ‖ valsetHash ‖ u64(height) ‖
//     u64(round) ‖ blockHash ‖ bodyHash), signature R ‖ S ‖ V de 65 octets,
//     S bas, V dans {0, 1} (CT-6 EX-11.7) ; vérification de la proposition et
//     des precommits selon CT-6 EX-11.14.
//
// La lecture d'une ligne suit CT-6 EX-11.6, qui renvoie à la table « Ce que
// le vérificateur accepte » de scripts/verify/README.md : noms de membres
// comparés sans la casse (repliement simple d'Unicode, comme
// strings.EqualFold), dernière occurrence gagnante, base64 standard avec
// tolérance des sauts de ligne et des bits de bourrage non nuls, hachage de
// bloc du corps en 0x ou 0X et en chiffres de toute casse, Voter et proposer
// vides ou nuls admis. Les noms des membres de l'enveloppe et des corps
// (domain, chainId, type, validatorId, valsetHash, height, round, blockHash,
// bodyHash, body, sig ; Height, Round, Voter, Type, BlockHash pour un vote ;
// height, round, proposer, blockHash, txsRaw pour une proposition) sont ceux
// que CT-6 EX-11.14 et ce tableau nomment et que portent les lignes
// capturées.

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
)

// EnTete porte les dix champs engagés d'un en-tête (CT-6 §11.2.1), plus la
// liste des transactions servie.
type EnTete struct {
	Number, Timestamp, GasUsed, GasLimit, BaseFee *big.Int
	Hash, ParentHash, StateRoot, TxRoot, RcptRoot []byte
	Transactions                                  []string
	Brut                                          *Value
}

// LireEnTete lit le résultat d'eth_getBlockByNumber(h, false).
func LireEnTete(v *Value) (EnTete, error) {
	var e EnTete
	if v == nil || v.Kind != KindObject {
		return e, errors.New("en-tête : objet attendu")
	}
	e.Brut = v
	q := func(cle string) (*big.Int, error) {
		s, err := Champ(v, cle)
		if err != nil {
			return nil, err
		}
		return Quantite(s)
	}
	h := func(cle string) ([]byte, error) {
		s, err := Champ(v, cle)
		if err != nil {
			return nil, err
		}
		b, err := DecoderHexLibre(s)
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("%s : 32 octets attendus", cle)
		}
		return b, nil
	}
	var err error
	if e.Number, err = q("number"); err != nil {
		return e, err
	}
	if e.Timestamp, err = q("timestamp"); err != nil {
		return e, err
	}
	if e.GasUsed, err = q("gasUsed"); err != nil {
		return e, err
	}
	if e.GasLimit, err = q("gasLimit"); err != nil {
		return e, err
	}
	if e.BaseFee, err = q("baseFeePerGas"); err != nil {
		return e, err
	}
	for _, p := range []struct {
		cle string
		dst *[]byte
	}{{"hash", &e.Hash}, {"parentHash", &e.ParentHash}, {"stateRoot", &e.StateRoot}, {"transactionsRoot", &e.TxRoot}, {"receiptsRoot", &e.RcptRoot}} {
		if *p.dst, err = h(p.cle); err != nil {
			return e, err
		}
	}
	if txs := v.Get("transactions"); txs != nil && txs.Kind == KindArray {
		for _, t := range txs.Arr {
			e.Transactions = append(e.Transactions, strings.ToLower(t.S()))
		}
	}
	return e, nil
}

// EtiquetteBloc est « noor/v1/bftblockhash » (20 octets, CT-6 EX-11.4).
var EtiquetteBloc = []byte("noor/v1/bftblockhash")

// BFTBlockHash recalcule le hachage du bloc (CT-6 EX-11.4).
func BFTBlockHash(e EnTete) ([]byte, error) {
	for _, n := range []*big.Int{e.Number, e.Timestamp, e.GasUsed, e.GasLimit} {
		if n.BitLen() > 64 {
			return nil, errors.New("entier de l'en-tête au-delà de 64 bits")
		}
	}
	if e.BaseFee.BitLen() > 256 {
		return nil, errors.New("baseFeePerGas au-delà de 256 bits")
	}
	pre := concat(EtiquetteBloc, e.ParentHash, u64be(e.Number.Uint64()), u64be(e.Timestamp.Uint64()),
		e.StateRoot, e.TxRoot, e.RcptRoot, u64be(e.GasUsed.Uint64()), u64be(e.GasLimit.Uint64()), u256(e.BaseFee))
	if len(pre) != 212 {
		return nil, fmt.Errorf("préimage de %d octets au lieu de 212", len(pre))
	}
	return Keccak256(pre), nil
}

// Validateur est une entrée d'un jeu (validators.json).
type Validateur struct {
	ID     string
	Cle    []byte // octets tels que déclarés
	CleXY  []byte // X ‖ Y
	CleHex string
}

// JeuValidateurs est un jeu chargé comme le nœud le charge.
type JeuValidateurs struct {
	Valideurs []Validateur // triés par identifiant
}

// ChargerJeu charge une liste { id, pubKeyHex } : identifiants non vides et
// distincts, clés non vides, exploitables (points de secp256k1) et
// distinctes (CT-6 EX-12.2, scripts/verify/README.md point 2 ; CT-4
// EX-6.21), puis tri par identifiant.
func ChargerJeu(liste *Value) (JeuValidateurs, error) {
	var j JeuValidateurs
	if liste == nil || liste.Kind != KindArray {
		return j, errors.New("jeu : tableau attendu")
	}
	ids := map[string]bool{}
	cles := map[string]bool{}
	for _, v := range liste.Arr {
		id, err := Champ(v, "id")
		if err != nil {
			return j, err
		}
		if id == "" {
			return j, errors.New("jeu : identifiant vide")
		}
		if ids[id] {
			return j, fmt.Errorf("jeu : identifiant %q en double", id)
		}
		ids[id] = true
		ph, err := Champ(v, "pubKeyHex")
		if err != nil {
			return j, err
		}
		b, err := DecoderHexLibre(ph)
		if err != nil || len(b) == 0 {
			return j, fmt.Errorf("jeu : clé de %q illisible", id)
		}
		xy, err := ClePubliqueXY(b)
		if err != nil {
			return j, fmt.Errorf("jeu : clé de %q : %v", id, err)
		}
		if cles[string(xy)] {
			return j, fmt.Errorf("jeu : clé de %q en double", id)
		}
		cles[string(xy)] = true
		j.Valideurs = append(j.Valideurs, Validateur{ID: id, Cle: b, CleXY: xy, CleHex: ph})
	}
	sort.Slice(j.Valideurs, func(a, b int) bool { return j.Valideurs[a].ID < j.Valideurs[b].ID })
	return j, nil
}

// Hachage rend le hachage du jeu (CT-6 EX-11.8).
func (j JeuValidateurs) Hachage() []byte {
	var buf bytes.Buffer
	buf.WriteString("noor/v1/valsethash|")
	for _, v := range j.Valideurs {
		buf.WriteString(v.ID)
		buf.WriteByte(0)
		buf.Write(v.Cle)
		buf.WriteByte(0)
	}
	return Sha256(buf.Bytes())
}

// Quorum rend ⌊(N + f)/2⌋ + 1 avec f = ⌊(N − 1)/3⌋ (CT-4 4.4, CT-6
// EX-11.8).
func Quorum(n int) int {
	f := (n - 1) / 3
	return (n+f)/2 + 1
}

// Fautes rend f = ⌊(N − 1)/3⌋.
func Fautes(n int) int { return (n - 1) / 3 }

func (j JeuValidateurs) cle(id string) []byte {
	for _, v := range j.Valideurs {
		if v.ID == id {
			return v.CleXY
		}
	}
	return nil
}

// ------------------------------------------------------------ lignes

type membreBrut struct {
	cle  string
	brut []byte
}

// scanValeur rend la position après la valeur JSON qui commence en p.
func scanValeur(b []byte, p int) (int, error) {
	if p >= len(b) {
		return 0, errors.New("valeur attendue")
	}
	switch c := b[p]; {
	case c == '"':
		p++
		for p < len(b) {
			switch b[p] {
			case '\\':
				p += 2
			case '"':
				return p + 1, nil
			default:
				p++
			}
		}
		return 0, errors.New("chaîne non terminée")
	case c == '{' || c == '[':
		ferm := byte('}')
		if c == '[' {
			ferm = ']'
		}
		p++
		for {
			p = sauterBlancs(b, p)
			if p < len(b) && b[p] == ferm {
				return p + 1, nil
			}
			if c == '{' {
				q, err := scanValeur(b, p)
				if err != nil {
					return 0, err
				}
				p = sauterBlancs(b, q)
				if p >= len(b) || b[p] != ':' {
					return 0, errors.New("':' attendu")
				}
				p = sauterBlancs(b, p+1)
			}
			q, err := scanValeur(b, p)
			if err != nil {
				return 0, err
			}
			p = sauterBlancs(b, q)
			if p < len(b) && b[p] == ',' {
				p++
				continue
			}
			if p < len(b) && b[p] == ferm {
				return p + 1, nil
			}
			return 0, errors.New("',' ou fermeture attendue")
		}
	default:
		q := p
		for q < len(b) && !strings.ContainsRune(" \t\r\n,]}", rune(b[q])) {
			q++
		}
		if q == p {
			return 0, errors.New("valeur attendue")
		}
		return q, nil
	}
}

func sauterBlancs(b []byte, p int) int {
	for p < len(b) && (b[p] == ' ' || b[p] == '\t' || b[p] == '\n' || b[p] == '\r') {
		p++
	}
	return p
}

// membresBruts découpe un objet JSON en membres, chaque valeur gardée sous
// ses octets d'origine, puis la valide par l'analyseur strict.
func membresBruts(b []byte) ([]membreBrut, error) {
	if _, err := ParseJSON(b); err != nil {
		// L'analyseur strict refuse les noms en double ; le décodeur du
		// nœud les admet (dernière occurrence gagnante) : on ne garde de
		// cette analyse que la validité lexicale de chaque valeur.
		if !strings.Contains(err.Error(), "clé en double") {
			return nil, err
		}
	}
	p := sauterBlancs(b, 0)
	if p >= len(b) || b[p] != '{' {
		return nil, errors.New("objet attendu")
	}
	p++
	var ms []membreBrut
	for {
		p = sauterBlancs(b, p)
		if p < len(b) && b[p] == '}' {
			return ms, nil
		}
		q, err := scanValeur(b, p)
		if err != nil {
			return nil, err
		}
		nom, err := ParseJSON(b[p:q])
		if err != nil || nom.Kind != KindString {
			return nil, errors.New("nom de membre illisible")
		}
		p = sauterBlancs(b, q)
		if p >= len(b) || b[p] != ':' {
			return nil, errors.New("':' attendu")
		}
		p = sauterBlancs(b, p+1)
		q, err = scanValeur(b, p)
		if err != nil {
			return nil, err
		}
		ms = append(ms, membreBrut{cle: nom.Str, brut: b[p:q]})
		p = sauterBlancs(b, q)
		if p < len(b) && b[p] == ',' {
			p++
			continue
		}
		if p < len(b) && b[p] == '}' {
			return ms, nil
		}
		return nil, errors.New("',' ou '}' attendu")
	}
}

// membre rend la dernière occurrence d'un nom comparé sans la casse.
func membre(ms []membreBrut, nom string) ([]byte, bool) {
	var r []byte
	ok := false
	for _, m := range ms {
		if strings.EqualFold(m.cle, nom) {
			r, ok = m.brut, true
		}
	}
	return r, ok
}

func chaineBrute(b []byte) (string, error) {
	v, err := ParseJSON(b)
	if err != nil {
		return "", err
	}
	if v.Kind != KindString {
		return "", errors.New("chaîne attendue")
	}
	return v.Str, nil
}

func entierBrut(b []byte) (uint64, error) {
	v, err := ParseJSON(b)
	if err != nil {
		return 0, err
	}
	if v.Kind != KindNumber {
		return 0, errors.New("entier attendu")
	}
	n, ok := EntierLitteral(v.Num)
	if !ok || n.Sign() < 0 || n.BitLen() > 64 {
		return 0, fmt.Errorf("entier non littéral ou hors de uint64 : %s", v.Num)
	}
	return n.Uint64(), nil
}

func base64Brut(b []byte, n int) ([]byte, error) {
	s, err := chaineBrute(b)
	if err != nil {
		return nil, err
	}
	d, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64 : %v", err)
	}
	if n >= 0 && len(d) != n {
		return nil, fmt.Errorf("base64 : %d octets au lieu de %d", len(d), n)
	}
	return d, nil
}

// Enveloppe est une ligne lue.
type Enveloppe struct {
	Domaine, ChainID, Type, ValidatorID string
	ValsetHash, BlockHash, BodyHash     []byte
	Height, Round                       uint64
	Corps                               []byte // octets d'origine
	Sig                                 []byte // 65 octets
}

// LireEnveloppe lit une ligne de certificat.
func LireEnveloppe(ligne string) (Enveloppe, error) {
	var e Enveloppe
	ms, err := membresBruts([]byte(ligne))
	if err != nil {
		return e, err
	}
	get := func(nom string) ([]byte, error) {
		b, ok := membre(ms, nom)
		if !ok {
			return nil, fmt.Errorf("membre %s absent", nom)
		}
		return b, nil
	}
	for _, p := range []struct {
		nom string
		dst *string
	}{{"domain", &e.Domaine}, {"chainId", &e.ChainID}, {"type", &e.Type}, {"validatorId", &e.ValidatorID}} {
		b, err := get(p.nom)
		if err != nil {
			return e, err
		}
		if *p.dst, err = chaineBrute(b); err != nil {
			return e, fmt.Errorf("%s : %v", p.nom, err)
		}
	}
	for _, p := range []struct {
		nom string
		dst *[]byte
	}{{"valsetHash", &e.ValsetHash}, {"blockHash", &e.BlockHash}, {"bodyHash", &e.BodyHash}} {
		b, err := get(p.nom)
		if err != nil {
			return e, err
		}
		if *p.dst, err = base64Brut(b, 32); err != nil {
			return e, fmt.Errorf("%s : %v", p.nom, err)
		}
	}
	for _, p := range []struct {
		nom string
		dst *uint64
	}{{"height", &e.Height}, {"round", &e.Round}} {
		b, err := get(p.nom)
		if err != nil {
			return e, err
		}
		if *p.dst, err = entierBrut(b); err != nil {
			return e, fmt.Errorf("%s : %v", p.nom, err)
		}
	}
	if e.Corps, err = get("body"); err != nil {
		return e, err
	}
	b, err := get("sig")
	if err != nil {
		return e, err
	}
	if e.Sig, err = base64Brut(b, 65); err != nil {
		return e, fmt.Errorf("sig : %v", err)
	}
	return e, nil
}

// lp écrit la longueur sur 4 octets grand-boutistes puis x (CT-6 EX-11.7).
func lp(x string) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(x)))
	return append(l[:], x...)
}

// CondenseEnveloppe rend le condensé signé d'une enveloppe (CT-6 EX-11.7).
func CondenseEnveloppe(e Enveloppe) []byte {
	pre := concat([]byte("noor/v1/bft-sign|"), lp(e.Domaine), lp(e.ChainID), lp(e.Type), lp(e.ValidatorID),
		e.ValsetHash, u64be(e.Height), u64be(e.Round), e.BlockHash, e.BodyHash)
	return Sha256(pre)
}

// Certificat est le champ result de noor_getCommitCertificate, réduit aux
// champs que CT-6 EX-11.3 lit.
type Certificat struct {
	Height, Round uint64
	ChainID       string
	ValsetHash    []byte
	BlockHash     []byte
	Proposition   string
	Precommits    []string
	Brut          *Value
}

// LireCertificat lit un certificat (champ result).
func LireCertificat(v *Value) (Certificat, error) {
	var c Certificat
	if v == nil || v.Kind != KindObject {
		return c, errors.New("certificat : objet attendu")
	}
	c.Brut = v
	for _, p := range []struct {
		cle string
		dst *uint64
	}{{"height", &c.Height}, {"round", &c.Round}} {
		s, err := Champ(v, p.cle)
		if err != nil {
			return c, err
		}
		n, err := Quantite(s)
		if err != nil || n.BitLen() > 64 {
			return c, fmt.Errorf("certificat : %s %q", p.cle, s)
		}
		*p.dst = n.Uint64()
	}
	var err error
	if c.ChainID, err = Champ(v, "chainId"); err != nil {
		return c, err
	}
	vh, err := Champ(v, "valsetHash")
	if err != nil {
		return c, err
	}
	if c.ValsetHash, err = DecoderHexN(vh, 32); err != nil {
		return c, err
	}
	bh, err := Champ(v, "blockHash")
	if err != nil {
		return c, err
	}
	if c.BlockHash, err = DecoderHexN(bh, 32); err != nil {
		return c, err
	}
	prop := v.Get("proposal")
	if prop == nil || prop.Kind != KindObject {
		return c, errors.New("certificat : proposal absente (EX-11.3 : exigée en version 0)")
	}
	if c.Proposition, err = Champ(prop, "line"); err != nil {
		return c, err
	}
	pcs := v.Get("precommits")
	if pcs == nil || pcs.Kind != KindArray || len(pcs.Arr) == 0 {
		return c, errors.New("certificat : precommits absents")
	}
	for _, p := range pcs.Arr {
		l, err := Champ(p, "line")
		if err != nil {
			return c, err
		}
		c.Precommits = append(c.Precommits, l)
	}
	return c, nil
}

// hachageCorps lit un hachage de bloc d'un corps : 0x ou 0X, chiffres de
// toute casse (tolérance du décodeur, scripts/verify/README.md).
func hachageCorps(b []byte) ([]byte, error) {
	s, err := chaineBrute(b)
	if err != nil {
		return nil, err
	}
	h, err := DecoderHexLibre(s)
	if err != nil || len(h) != 32 {
		return nil, fmt.Errorf("hachage de bloc du corps %q", s)
	}
	return h, nil
}

// verifierEnveloppe applique CT-6 EX-11.14 à une ligne et rend son
// signataire et, pour une proposition, son corps.
func verifierEnveloppe(ligne, typ string, c Certificat, jeu JeuValidateurs) (string, []membreBrut, error) {
	e, err := LireEnveloppe(ligne)
	if err != nil {
		return "", nil, err
	}
	if e.Domaine != "noor/v1/bft" {
		return "", nil, fmt.Errorf("domaine %q", e.Domaine)
	}
	if e.Type != typ {
		return "", nil, fmt.Errorf("type %q au lieu de %s", e.Type, typ)
	}
	if e.ChainID != c.ChainID {
		return "", nil, fmt.Errorf("chainId %q au lieu de %q", e.ChainID, c.ChainID)
	}
	if !bytes.Equal(e.ValsetHash, c.ValsetHash) {
		return "", nil, errors.New("valsetHash de l'enveloppe différent du certificat")
	}
	if e.Height != c.Height || e.Round != c.Round {
		return "", nil, errors.New("hauteur ou tour de l'enveloppe différents du certificat")
	}
	if !bytes.Equal(e.BlockHash, c.BlockHash) {
		return "", nil, errors.New("blockHash de l'enveloppe différent du certificat")
	}
	if !bytes.Equal(e.BodyHash, Sha256(e.Corps)) {
		return "", nil, errors.New("bodyHash différent du sha256 des octets du corps")
	}
	corps, err := membresBruts(e.Corps)
	if err != nil {
		return "", nil, fmt.Errorf("corps : %v", err)
	}
	b, ok := membre(corps, "height")
	if !ok {
		return "", nil, errors.New("corps : hauteur absente")
	}
	if h, err := entierBrut(b); err != nil || h != c.Height {
		return "", nil, errors.New("corps : hauteur différente")
	}
	b, ok = membre(corps, "round")
	if !ok {
		return "", nil, errors.New("corps : tour absent")
	}
	if r, err := entierBrut(b); err != nil || r != c.Round {
		return "", nil, errors.New("corps : tour différent")
	}
	b, ok = membre(corps, "blockHash")
	if !ok {
		return "", nil, errors.New("corps : blockHash absent")
	}
	if h, err := hachageCorps(b); err != nil || !bytes.Equal(h, c.BlockHash) {
		return "", nil, errors.New("corps : blockHash différent")
	}
	signataireCorps := "voter"
	if typ == "CONS_PROPOSAL" {
		signataireCorps = "proposer"
	} else if b, ok := membre(corps, "type"); ok {
		v, err := ParseJSON(b)
		if err != nil || v.Kind != KindNumber {
			return "", nil, errors.New("corps : Type non entier")
		}
		n, ok := EntierLitteral(v.Num)
		if !ok || n.Sign() < 0 || n.Cmp(big.NewInt(255)) > 0 {
			return "", nil, errors.New("corps : Type hors de uint8")
		}
	}
	if b, ok := membre(corps, signataireCorps); ok {
		v, err := ParseJSON(b)
		if err != nil {
			return "", nil, err
		}
		switch v.Kind {
		case KindNull:
		case KindString:
			if v.Str != "" && v.Str != e.ValidatorID {
				return "", nil, fmt.Errorf("corps : %s %q différent du signataire %q", signataireCorps, v.Str, e.ValidatorID)
			}
		default:
			return "", nil, fmt.Errorf("corps : %s mal typé", signataireCorps)
		}
	}
	cle := jeu.cle(e.ValidatorID)
	if cle == nil {
		return "", nil, fmt.Errorf("validateur %q hors du jeu", e.ValidatorID)
	}
	if e.Sig[64] > 1 {
		return "", nil, errors.New("V hors de {0, 1}")
	}
	r := new(big.Int).SetBytes(e.Sig[:32])
	s := new(big.Int).SetBytes(e.Sig[32:64])
	if s.Cmp(secpDemiN) > 0 {
		return "", nil, errors.New("S haut")
	}
	pub, err := Recouvrer(CondenseEnveloppe(e), r, s, int(e.Sig[64]))
	if err != nil {
		return "", nil, err
	}
	if !bytes.Equal(pub, cle) {
		return "", nil, fmt.Errorf("signature : clé recouvrée autre que celle de %q", e.ValidatorID)
	}
	return e.ValidatorID, corps, nil
}

// VerifierCertificat vérifie un certificat contre un jeu (CT-6 EX-11.6 à
// EX-11.8, EX-11.14) et rend les transactions brutes du corps de la
// proposition (txsRaw) et le nombre de signataires distincts.
func VerifierCertificat(c Certificat, jeu JeuValidateurs) ([][]byte, int, error) {
	if !bytes.Equal(c.ValsetHash, jeu.Hachage()) {
		return nil, 0, errors.New("valsetHash du certificat différent du hachage du jeu")
	}
	_, corps, err := verifierEnveloppe(c.Proposition, "CONS_PROPOSAL", c, jeu)
	if err != nil {
		return nil, 0, fmt.Errorf("proposition : %v", err)
	}
	vus := map[string]bool{}
	for i, l := range c.Precommits {
		id, _, err := verifierEnveloppe(l, "CONS_PRECOMMIT", c, jeu)
		if err != nil {
			return nil, 0, fmt.Errorf("precommit %d : %v", i, err)
		}
		if vus[id] {
			return nil, 0, fmt.Errorf("precommit %d : signataire %q en double", i, id)
		}
		vus[id] = true
	}
	if q := Quorum(len(jeu.Valideurs)); len(vus) < q {
		return nil, 0, fmt.Errorf("%d signataires distincts pour un quorum de %d", len(vus), q)
	}
	var txs [][]byte
	if b, ok := membre(corps, "txsRaw"); ok {
		v, err := ParseJSON(b)
		if err != nil {
			return nil, 0, err
		}
		switch v.Kind {
		case KindNull:
		case KindArray:
			for _, t := range v.Arr {
				if t.Kind != KindString {
					return nil, 0, errors.New("txsRaw : chaîne base64 attendue")
				}
				d, err := base64.StdEncoding.DecodeString(t.Str)
				if err != nil {
					return nil, 0, fmt.Errorf("txsRaw : %v", err)
				}
				txs = append(txs, d)
			}
		default:
			return nil, 0, errors.New("txsRaw mal typé")
		}
	}
	return txs, len(vus), nil
}
