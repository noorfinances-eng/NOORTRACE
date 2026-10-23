// Confrontation des vecteurs CT-6 de la famille registre
// (spec/vecteurs/ct-6/registre, spec/CT-6-verificateur.md annexe A.8) par
// des implémentations tierces, sans le code JavaScript du dépôt :
//
//   - go-ethereum v1.17.0 (version que noorchain-core épingle) :
//     types.DeriveSha et trie.StackTrie pour la racine des reçus,
//     types.CreateBloom pour le bloom, accounts/abi pour le décodage des
//     journaux PeriodSubmitted, Anchored et RecorderRegistered, crypto.Keccak256 ;
//   - noorcore (module noorchain-evm-l1, employé en lecture seule) :
//     node.BFTBlockHash pour le hachage du bloc, consensus.DecodeSignedEnvelope,
//     consensus.VerifyEnvelope, consensus.ValidatorSetHash et
//     consensus.Quorum2f1 pour les certificats de commit.
//
// Le programme lit :
//
//  1. la capture brute (capture/ : réponses JSON-RPC du nœud) et compare ses
//     recalculs aux valeurs de attendu.json (hachage BFT, préimage, racine et
//     encodages des reçus, événements décodés, signataires) ;
//
//  2. trie.json : racines des listes de reçus synthétiques (DeriveSha) et des
//     couples génériques (StackTrie) ;
//
//  3. chaque jeu de parties (periode-1, periode-2, variantes/) avec les
//     ancres de test (et leurs modifications) : il refait, à sa façon, les
//     vérifications R-1 à R-10 et N-4 et compare leur statut à celui que
//     attendu.json consigne.
//
//     go run . <spec/vecteurs/ct-6/registre> <spec/vecteurs/ct-1>
//
// Code de retour : 0 si tout concorde, 1 sinon, 2 si une entrée est illisible.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"

	"noorchain-evm-l1/core/consensus"
	"noorchain-evm-l1/core/node"
)

// ABI des trois événements, recopiée des déclarations de contracts/*.sol.
const abiEvenements = `[
 {"type":"event","name":"PeriodSubmitted","anonymous":false,"inputs":[
  {"name":"id","type":"uint256","indexed":true},
  {"name":"periodHash","type":"bytes32","indexed":true},
  {"name":"orgId","type":"bytes32","indexed":false},
  {"name":"journalId","type":"bytes32","indexed":false},
  {"name":"root","type":"bytes32","indexed":false},
  {"name":"periodStart","type":"uint64","indexed":false},
  {"name":"periodEnd","type":"uint64","indexed":false},
  {"name":"firstSeq","type":"uint64","indexed":false},
  {"name":"lastSeq","type":"uint64","indexed":false},
  {"name":"version","type":"uint32","indexed":false},
  {"name":"publisher","type":"address","indexed":true},
  {"name":"uri","type":"string","indexed":false},
  {"name":"publishedAt","type":"uint64","indexed":false}]},
 {"type":"event","name":"Anchored","anonymous":false,"inputs":[
  {"name":"fingerprint","type":"bytes32","indexed":true},
  {"name":"issuer","type":"address","indexed":true},
  {"name":"docType","type":"bytes32","indexed":false}]},
 {"type":"event","name":"RecorderRegistered","anonymous":false,"inputs":[
  {"name":"orgId","type":"bytes32","indexed":true},
  {"name":"chainKey","type":"address","indexed":true},
  {"name":"journalId","type":"bytes32","indexed":true},
  {"name":"ed25519PubKey","type":"bytes32","indexed":false},
  {"name":"publisher","type":"address","indexed":false}]}
]`

var evenementDuRole = map[string]string{"cloture": "PeriodSubmitted", "ancre": "Anchored", "inscription": "RecorderRegistered"}
var contratDuRole = map[string]string{"cloture": "period_registry", "ancre": "attestation_registry", "inscription": "recorder_registry"}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type journalJSON struct {
	Address string   `json:"address"`
	Topics  []string `json:"topics"`
	Data    string   `json:"data"`
}

type recuJSON struct {
	Type              string        `json:"type"`
	Status            string        `json:"status"`
	CumulativeGasUsed string        `json:"cumulativeGasUsed"`
	Logs              []journalJSON `json:"logs"`
	TransactionHash   string        `json:"transactionHash"`
}

type enteteJSON struct {
	Number           string   `json:"number"`
	Hash             string   `json:"hash"`
	ParentHash       string   `json:"parentHash"`
	Timestamp        string   `json:"timestamp"`
	StateRoot        string   `json:"stateRoot"`
	TransactionsRoot string   `json:"transactionsRoot"`
	ReceiptsRoot     string   `json:"receiptsRoot"`
	GasUsed          string   `json:"gasUsed"`
	GasLimit         string   `json:"gasLimit"`
	BaseFeePerGas    string   `json:"baseFeePerGas"`
	Transactions     []string `json:"transactions"`
}

type ligneJSON struct {
	Line string `json:"line"`
}

type certificatJSON struct {
	Height     string      `json:"height"`
	Round      string      `json:"round"`
	ChainID    string      `json:"chainId"`
	ValsetHash string      `json:"valsetHash"`
	BlockHash  string      `json:"blockHash"`
	Proposal   ligneJSON   `json:"proposal"`
	Precommits []ligneJSON `json:"precommits"`
}

type validateurJSON struct {
	ID        string `json:"id"`
	PubKeyHex string `json:"pubKeyHex"`
}

type jeuJSON struct {
	FromHeight uint64           `json:"from_height"`
	ToHeight   *uint64          `json:"to_height"`
	Validators []validateurJSON `json:"validators"`
	Source     string           `json:"source"`
}

type entreeJSON struct {
	Role             string     `json:"role"`
	Block            enteteJSON `json:"block"`
	Receipts         []recuJSON `json:"receipts"`
	TransactionIndex int        `json:"transaction_index"`
	LogIndex         int        `json:"log_index"`
}

type partiesJSON struct {
	Registre struct {
		Entries []entreeJSON `json:"entries"`
	}
	Certificats struct {
		Certificates []certificatJSON `json:"certificates"`
	}
	Validateurs *struct {
		Sets []jeuJSON `json:"sets"`
	}
}

type ancresJSON struct {
	Registry *struct {
		ChainID       string            `json:"chain_id"`
		Contracts     map[string]string `json:"contracts"`
		ValidatorSets []jeuJSON         `json:"validator_sets"`
	} `json:"registry"`
	Recorders []struct {
		OrgID     string  `json:"org_id"`
		JournalID string  `json:"journal_id"`
		KeyID     string  `json:"key_id"`
		PublicKey string  `json:"public_key"`
		ChainKey  *string `json:"chain_key"`
	} `json:"recorders"`
}

type modification struct {
	Pointer string `json:"pointer"`
	Value   any    `json:"value"`
}

type jeuAttendu struct {
	Nom                 string            `json:"nom"`
	Parties             string            `json:"parties"`
	ValidateursPresent  bool              `json:"validateurs_present"`
	Manifeste           string            `json:"manifeste"`
	Ancres              *string           `json:"ancres"`
	ModificationsAncres []modification    `json:"modifications_ancres"`
	Statuses            map[string]string `json:"statuses"`
}

type attenduJSON struct {
	Capture struct {
		ValsetHash string `json:"valset_hash"`
	} `json:"capture"`
	Blocs []struct {
		Height           uint64         `json:"height"`
		Role             string         `json:"role"`
		TransactionHash  string         `json:"transaction_hash"`
		BftPreimage      string         `json:"bft_preimage"`
		BftBlockHash     string         `json:"bft_block_hash"`
		ReceiptsRoot     string         `json:"receipts_root"`
		ReceiptEncodings []string       `json:"receipt_encodings"`
		Event            map[string]any `json:"event"`
		Certificate      struct {
			Proposer         string   `json:"proposer"`
			PrecommitSigners []string `json:"precommit_signers"`
		} `json:"certificate"`
	} `json:"blocs"`
	Ancres        json.RawMessage `json:"ancres"`
	JeuxDeParties []jeuAttendu    `json:"jeux_de_parties"`
	Variantes     []jeuAttendu    `json:"variantes"`
}

// ---------------------------------------------------------------------------
// Outils
// ---------------------------------------------------------------------------

var ecarts, concordances int

func lire(chemin string, v any) {
	b, err := os.ReadFile(chemin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "entrée illisible :", err)
		os.Exit(2)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(v); err != nil {
		fmt.Fprintln(os.Stderr, "JSON illisible :", chemin, err)
		os.Exit(2)
	}
}

func lireRPC(chemin string, v any) {
	var enveloppe struct {
		Result json.RawMessage `json:"result"`
	}
	lire(chemin, &enveloppe)
	if err := json.Unmarshal(enveloppe.Result, v); err != nil {
		fmt.Fprintln(os.Stderr, "résultat illisible :", chemin, err)
		os.Exit(2)
	}
}

func constat(ok bool, format string, a ...any) {
	etat := "concordant"
	if !ok {
		etat = "ÉCART"
		ecarts++
	} else {
		concordances++
	}
	fmt.Printf("  [%s] %s\n", etat, fmt.Sprintf(format, a...))
}

func u64(s string) uint64 { return hexutil.MustDecodeUint64(s) }

func recuGeth(r recuJSON) *types.Receipt {
	rc := &types.Receipt{Type: uint8(u64(r.Type)), Status: u64(r.Status), CumulativeGasUsed: u64(r.CumulativeGasUsed)}
	for _, j := range r.Logs {
		l := &types.Log{Address: common.HexToAddress(j.Address), Data: hexutil.MustDecode(j.Data)}
		for _, t := range j.Topics {
			l.Topics = append(l.Topics, common.HexToHash(t))
		}
		rc.Logs = append(rc.Logs, l)
	}
	rc.Bloom = types.CreateBloom(rc)
	return rc
}

func racineRecus(recus []recuJSON) (common.Hash, types.Receipts) {
	liste := types.Receipts{}
	for _, r := range recus {
		liste = append(liste, recuGeth(r))
	}
	return types.DeriveSha(liste, trie.NewStackTrie(nil)), liste
}

func hachageBFT(b enteteJSON) common.Hash {
	return node.BFTBlockHash(common.HexToHash(b.ParentHash), u64(b.Number), u64(b.Timestamp), common.HexToHash(b.StateRoot), common.HexToHash(b.TransactionsRoot), common.HexToHash(b.ReceiptsRoot), u64(b.GasUsed), u64(b.GasLimit), hexutil.MustDecodeBig(b.BaseFeePerGas))
}

// jeuNoorcore construit un ValidatorSet comme LoadValidatorSetFile le charge.
func jeuNoorcore(vs []validateurJSON) (consensus.ValidatorSet, error) {
	jeu := consensus.ValidatorSet{}
	for i, v := range vs {
		pk, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(v.PubKeyHex), "0x"))
		if err != nil {
			return jeu, fmt.Errorf("validateur %d : %v", i, err)
		}
		jeu.Validators = append(jeu.Validators, consensus.Validator{ID: strings.TrimSpace(v.ID), PubKey: pk})
	}
	if err := jeu.ValidateForProduction(); err != nil {
		return jeu, err
	}
	jeu.SortByID()
	return jeu, nil
}

func hachageJeu(vs []validateurJSON) common.Hash {
	jeu, err := jeuNoorcore(vs)
	if err != nil {
		return common.Hash{}
	}
	h := consensus.ValidatorSetHash(jeu)
	return common.BytesToHash(h[:])
}

// verifierLignes : chaque ligne est une enveloppe valide (VerifyEnvelope) de
// ce certificat ; rend les signataires distincts des precommits et le proposant.
func verifierLignes(c certificatJSON, jeu consensus.ValidatorSet) (proposant string, signataires []string, ordre []string, err error) {
	vh := consensus.ValidatorSetHash(jeu)
	params := consensus.VerifyParams{ChainID: c.ChainID, ValsetHash: vh, Vs: jeu}
	h, r, bh := u64(c.Height), u64(c.Round), common.HexToHash(c.BlockHash)
	verifier := func(ligne string, type_ string) (string, error) {
		e, err := consensus.DecodeSignedEnvelope([]byte(ligne))
		if err != nil {
			return "", err
		}
		if _, err := consensus.VerifyEnvelope(e, params); err != nil {
			return e.ValidatorID, err
		}
		if e.Type != type_ || e.Height != h || e.Round != r || common.BytesToHash(e.BlockHash) != bh {
			return e.ValidatorID, fmt.Errorf("enveloppe %s %s d'un autre bloc, hauteur ou tour", e.Type, e.ValidatorID)
		}
		return e.ValidatorID, nil
	}
	proposant, err = verifier(c.Proposal.Line, consensus.WireProposal)
	if err != nil {
		return
	}
	vus := map[string]bool{}
	for _, p := range c.Precommits {
		var id string
		id, err = verifier(p.Line, consensus.WirePrecommit)
		if err != nil {
			return
		}
		ordre = append(ordre, id)
		if vus[id] {
			err = fmt.Errorf("signataire %s en double", id)
			return
		}
		vus[id] = true
		signataires = append(signataires, id)
	}
	if len(signataires) < consensus.Quorum2f1(jeu.Size()) {
		err = fmt.Errorf("%d signataires pour un quorum de %d", len(signataires), consensus.Quorum2f1(jeu.Size()))
	}
	return
}

// decoder décode un journal par l'ABI ; rend les valeurs en chaînes canoniques.
func decoder(evts abi.ABI, role string, j journalJSON) (map[string]string, error) {
	ev := evts.Events[evenementDuRole[role]]
	if len(j.Topics) == 0 || common.HexToHash(j.Topics[0]) != ev.ID {
		return nil, fmt.Errorf("topics[0] n'est pas celui de %s", ev.Sig)
	}
	var indexes abi.Arguments
	for _, a := range ev.Inputs {
		if a.Indexed {
			indexes = append(indexes, a)
		}
	}
	if len(j.Topics)-1 != len(indexes) {
		return nil, fmt.Errorf("%d sujets indexés au lieu de %d", len(j.Topics)-1, len(indexes))
	}
	tps := []common.Hash{}
	for _, t := range j.Topics[1:] {
		tps = append(tps, common.HexToHash(t))
	}
	champs := map[string]any{}
	if err := abi.ParseTopicsIntoMap(champs, indexes, tps); err != nil {
		return nil, err
	}
	donnees := hexutil.MustDecode(j.Data)
	if err := ev.Inputs.NonIndexed().UnpackIntoMap(champs, donnees); err != nil {
		return nil, err
	}
	// Forme stricte : le réencodage des valeurs non indexées redonne exactement data.
	var valeurs []any
	for _, a := range ev.Inputs.NonIndexed() {
		valeurs = append(valeurs, champs[a.Name])
	}
	reencode, err := ev.Inputs.NonIndexed().Pack(valeurs...)
	if err != nil || !bytes.Equal(reencode, donnees) {
		return nil, fmt.Errorf("data non canonique")
	}
	out := map[string]string{"name": ev.Name}
	for _, a := range ev.Inputs {
		switch v := champs[a.Name].(type) {
		case [32]byte:
			out[a.Name] = "0x" + hex.EncodeToString(v[:])
		case common.Address:
			out[a.Name] = strings.ToLower(v.Hex())
		case *big.Int:
			out[a.Name] = v.String()
		case uint64:
			out[a.Name] = strconv.FormatUint(v, 10)
		case uint32:
			out[a.Name] = strconv.FormatUint(uint64(v), 10)
		case string:
			out[a.Name] = v
		default:
			out[a.Name] = fmt.Sprint(v)
		}
	}
	// Un sujet d'adresse aux octets de tête non nuls est décodé sans erreur par l'ABI : le refuser ici.
	for i, a := range indexes {
		if a.Type.T == abi.AddressTy && !bytes.Equal(tps[i][:12], make([]byte, 12)) {
			return nil, fmt.Errorf("sujet %s : octets de tête non nuls", a.Name)
		}
	}
	return out, nil
}

func chaine(v any) string {
	switch x := v.(type) {
	case json.Number:
		return x.String()
	case string:
		return x
	default:
		return fmt.Sprint(x)
	}
}

// appliquer : pointeurs JSON (RFC 6901) sur un document générique.
func appliquer(doc any, mods []modification) any {
	for _, m := range mods {
		segs := strings.Split(m.Pointer, "/")[1:]
		cible := doc
		for _, s := range segs[:len(segs)-1] {
			switch c := cible.(type) {
			case map[string]any:
				cible = c[s]
			case []any:
				i, _ := strconv.Atoi(s)
				cible = c[i]
			}
		}
		dernier := segs[len(segs)-1]
		switch c := cible.(type) {
		case map[string]any:
			c[dernier] = m.Value
		case []any:
			i, _ := strconv.Atoi(dernier)
			c[i] = m.Value
		}
	}
	return doc
}

// ---------------------------------------------------------------------------
// Vérifications R- refaites en Go
// ---------------------------------------------------------------------------

type manifeste struct {
	OrgID         string `json:"org_id"`
	JournalID     string `json:"journal_id"`
	Root          string `json:"root"`
	PeriodStart   uint64 `json:"period_start"`
	PeriodEnd     uint64 `json:"period_end"`
	FirstSeq      uint64 `json:"first_seq"`
	LastSeq       uint64 `json:"last_seq"`
	Version       uint64 `json:"version"`
	RecorderKeyID string `json:"recorder_key_id"`
}

type contexte struct {
	evts       abi.ABI
	manifeste  manifeste
	periodHash common.Hash
	cles       map[string]string // public_key -> key_id
}

func agreger(items []string) string {
	nonExecute := false
	for _, s := range items {
		if s == "echoue" {
			return "echoue"
		}
		if s == "non_execute" {
			nonExecute = true
		}
	}
	if nonExecute {
		return "non_execute"
	}
	return "reussi"
}

func controle8(ctx contexte, p partiesJSON, a ancresJSON) map[string]string {
	st := map[string]string{}
	entrees := p.Registre.Entries
	certs := p.Certificats.Certificates
	// N-4 figure si l'ancre donne une chain_key pour la clé du manifeste.
	var cleChaine *string
	for _, r := range a.Recorders {
		if r.OrgID == ctx.manifeste.OrgID && r.JournalID == ctx.manifeste.JournalID && r.KeyID == ctx.manifeste.RecorderKeyID && r.ChainKey != nil {
			cleChaine = r.ChainKey
		}
	}
	// R-1 : rôles et appariement (la conformité au schéma est l'affaire de l'implémentation de référence).
	roles := map[string]int{}
	for _, e := range entrees {
		roles[e.Role]++
	}
	parH := map[uint64]certificatJSON{}
	r1 := roles["cloture"] == 1 && roles["ancre"] == 1 && roles["inscription"] <= 8 && len(entrees) >= 2
	for _, c := range certs {
		if _, deja := parH[u64(c.Height)]; deja {
			r1 = false
		}
		parH[u64(c.Height)] = c
	}
	servis := map[uint64]bool{}
	for _, e := range entrees {
		h := u64(e.Block.Number)
		if _, ok := parH[h]; !ok {
			r1 = false
		}
		servis[h] = true
		if e.TransactionIndex >= len(e.Receipts) || e.LogIndex >= len(e.Receipts[e.TransactionIndex].Logs) {
			r1 = false
		}
	}
	for h := range parH {
		if !servis[h] {
			r1 = false
		}
	}
	if !r1 {
		st["R-1"] = "echoue"
		for _, id := range []string{"R-2", "R-3", "R-4", "R-5", "R-6", "R-7", "R-8", "R-9", "R-10"} {
			st[id] = "non_execute"
		}
		if cleChaine != nil {
			st["N-4"] = "non_execute"
		}
		return st
	}
	st["R-1"] = "reussi"
	reg := a.Registry
	// R-2, R-4, R-5, R-3 par certificat.
	var r2, r3, r4, r5 []string
	r5ParHauteur := map[uint64]string{}
	for _, c := range certs {
		h := u64(c.Height)
		nr5 := len(r5)
		var jeu *jeuJSON
		if reg != nil {
			for i := range reg.ValidatorSets {
				s := reg.ValidatorSets[i]
				if h >= s.FromHeight && (s.ToHeight == nil || h <= *s.ToHeight) {
					jeu = &reg.ValidatorSets[i]
					break
				}
			}
		}
		switch {
		case jeu == nil:
			r2 = append(r2, "non_execute")
			r5 = append(r5, "non_execute")
		case hachageJeu(jeu.Validators) != common.HexToHash(c.ValsetHash):
			r2 = append(r2, "echoue")
			r5 = append(r5, "non_execute")
		default:
			r2 = append(r2, "reussi")
			ens, _ := jeuNoorcore(jeu.Validators)
			if _, _, _, err := verifierLignes(c, ens); err != nil {
				r5 = append(r5, "echoue")
			} else {
				r5 = append(r5, "reussi")
			}
		}
		r5ParHauteur[h] = r5[nr5]
		if reg == nil {
			r4 = append(r4, "non_execute")
		} else if c.ChainID != reg.ChainID {
			r4 = append(r4, "echoue")
		} else {
			r4 = append(r4, "reussi")
		}
		if p.Validateurs != nil {
			ok := false
			for _, s := range p.Validateurs.Sets {
				if h >= s.FromHeight && (s.ToHeight == nil || h <= *s.ToHeight) && hachageJeu(s.Validators) == common.HexToHash(c.ValsetHash) {
					ok = true
				}
			}
			if ok {
				r3 = append(r3, "reussi")
			} else {
				r3 = append(r3, "echoue")
			}
		}
	}
	st["R-2"], st["R-4"], st["R-5"] = agreger(r2), agreger(r4), agreger(r5)
	if p.Validateurs == nil {
		st["R-3"] = "non_execute"
	} else {
		st["R-3"] = agreger(r3)
	}
	// R-6, R-7 par entrée ; R-8, R-9, R-10 sur les entrées liées.
	var r6, r7, r8, r9, r10 []string
	lie := make([]bool, len(entrees))
	for i, e := range entrees {
		c := parH[u64(e.Block.Number)]
		bh := hachageBFT(e.Block)
		ok6 := bh == common.HexToHash(c.BlockHash) && bh == common.HexToHash(e.Block.Hash)
		racine, _ := racineRecus(e.Receipts)
		ok7 := racine == common.HexToHash(e.Block.ReceiptsRoot)
		r6 = append(r6, map[bool]string{true: "reussi", false: "echoue"}[ok6])
		r7 = append(r7, map[bool]string{true: "reussi", false: "echoue"}[ok7])
		lie[i] = ok6 && ok7
	}
	st["R-6"], st["R-7"] = agreger(r6), agreger(r7)
	issuer := ""
	issuerLu := false
	for i, e := range entrees {
		if e.Role == "ancre" && lie[i] {
			if v, err := decoder(ctx.evts, "ancre", e.Receipts[e.TransactionIndex].Logs[e.LogIndex]); err == nil {
				issuer, issuerLu = v["issuer"], true
			}
		}
	}
	ancreLiee := false
	for i, e := range entrees {
		if e.Role == "ancre" {
			ancreLiee = lie[i]
		}
	}
	empreinte := crypto.Keccak256Hash(common.HexToHash(ctx.manifeste.OrgID).Bytes(), common.HexToHash(ctx.manifeste.JournalID).Bytes(), ctx.periodHash.Bytes())
	docType := crypto.Keccak256Hash([]byte("noortrace/periode/v0"))
	nbInscriptions := 0
	var clesChaineManifeste []string
	for i, e := range entrees {
		j := e.Receipts[e.TransactionIndex].Logs[e.LogIndex]
		if !lie[i] {
			r8 = append(r8, "non_execute")
			if e.Role == "inscription" {
				r10 = append(r10, "non_execute")
				nbInscriptions++
			} else {
				r9 = append(r9, "non_execute")
			}
			continue
		}
		if reg == nil {
			r8 = append(r8, "non_execute")
		} else if strings.ToLower(j.Address) != reg.Contracts[contratDuRole[e.Role]] {
			r8 = append(r8, "echoue")
		} else {
			r8 = append(r8, "reussi")
		}
		v, err := decoder(ctx.evts, e.Role, j)
		switch e.Role {
		case "cloture":
			ok := err == nil &&
				v["periodHash"] == strings.ToLower(ctx.periodHash.Hex()) &&
				v["orgId"] == ctx.manifeste.OrgID && v["journalId"] == ctx.manifeste.JournalID && v["root"] == ctx.manifeste.Root &&
				v["periodStart"] == strconv.FormatUint(ctx.manifeste.PeriodStart, 10) && v["periodEnd"] == strconv.FormatUint(ctx.manifeste.PeriodEnd, 10) &&
				v["firstSeq"] == strconv.FormatUint(ctx.manifeste.FirstSeq, 10) && v["lastSeq"] == strconv.FormatUint(ctx.manifeste.LastSeq, 10) &&
				v["version"] == strconv.FormatUint(ctx.manifeste.Version, 10) && v["publishedAt"] == strconv.FormatUint(u64(e.Block.Timestamp), 10)
			r9 = append(r9, map[bool]string{true: "reussi", false: "echoue"}[ok])
		case "ancre":
			ok := err == nil && v["fingerprint"] == strings.ToLower(empreinte.Hex()) && v["docType"] == strings.ToLower(docType.Hex())
			r9 = append(r9, map[bool]string{true: "reussi", false: "echoue"}[ok])
		case "inscription":
			nbInscriptions++
			ok := err == nil && v["orgId"] == ctx.manifeste.OrgID && v["journalId"] == ctx.manifeste.JournalID
			if ok {
				cle, connue := ctx.cles[v["ed25519PubKey"]]
				ok = connue
				if connue && cle == ctx.manifeste.RecorderKeyID {
					clesChaineManifeste = append(clesChaineManifeste, v["chainKey"])
				}
			}
			r10 = append(r10, map[bool]string{true: "reussi", false: "echoue"}[ok])
		}
	}
	st["R-8"], st["R-9"] = agreger(r8), agreger(r9)
	// EX-11.19 : parmi les inscriptions de la clé du manifeste, au moins une sous l'émetteur de
	// l'ancre ; les autres (réinscription sous une autre clé de chaîne) ne font pas échouer R-10.
	if ancreLiee && len(clesChaineManifeste) > 0 && agreger(r10) == "reussi" {
		sousEmetteur := false
		for _, k := range clesChaineManifeste {
			sousEmetteur = sousEmetteur || (issuerLu && k == issuer)
		}
		if !sousEmetteur {
			r10 = append(r10, "echoue")
		}
	}
	if nbInscriptions == 0 {
		st["R-10"] = "non_execute"
	} else {
		st["R-10"] = agreger(r10)
	}
	// EX-12.5 : N-4 exige l'entrée ancre liée (R-6, R-7) et R-5 réussie pour le certificat de son
	// bloc : sans quorum vérifié, l'émetteur lu n'est pas authentifié.
	if cleChaine != nil {
		hAncre := uint64(0)
		for _, e := range entrees {
			if e.Role == "ancre" {
				hAncre = u64(e.Block.Number)
			}
		}
		switch {
		case !ancreLiee:
			st["N-4"] = "non_execute"
		case r5ParHauteur[hAncre] != "reussi":
			st["N-4"] = "non_execute"
		case issuerLu && issuer == *cleChaine:
			st["N-4"] = "reussi"
		default:
			st["N-4"] = "echoue"
		}
	}
	return st
}

// ---------------------------------------------------------------------------
// Programme
// ---------------------------------------------------------------------------

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage : registre <spec/vecteurs/ct-6/registre> <spec/vecteurs/ct-1>")
		os.Exit(2)
	}
	rep, ct1 := os.Args[1], os.Args[2]
	evts, err := abi.JSON(strings.NewReader(abiEvenements))
	if err != nil {
		panic(err)
	}
	var att attenduJSON
	lire(filepath.Join(rep, "attendu.json"), &att)

	fmt.Println("== 0. Constantes ==")
	constat(evts.Events["PeriodSubmitted"].ID.Hex() == "0x6d6cb8da98056d2abd84165b9f6d64d8097b1e28deaf23013228f6bdd5370fba", "topics[0] de PeriodSubmitted (abi) = %s", evts.Events["PeriodSubmitted"].ID.Hex())
	constat(evts.Events["Anchored"].ID.Hex() == "0x4450fd19f5dafd45e52f91aa82897967b7469e348fd7d5083f4e0515df90706e", "topics[0] de Anchored (abi) = %s", evts.Events["Anchored"].ID.Hex())
	constat(evts.Events["RecorderRegistered"].ID.Hex() == "0xe29e846d78f0b22a87c669add67dec8daa3b0935e6f4c96d7f627a60e7ae44ec", "topics[0] de RecorderRegistered (abi) = %s", evts.Events["RecorderRegistered"].ID.Hex())

	// 1. Capture brute.
	fmt.Println("== 1. Capture brute (capture/) contre attendu.json ==")
	capDir := filepath.Join(rep, "capture")
	jeuCapture, err := consensus.LoadValidatorSetFile(filepath.Join(capDir, "validators.json"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	vh := consensus.ValidatorSetHash(jeuCapture)
	constat("0x"+hex.EncodeToString(vh[:]) == att.Capture.ValsetHash, "ValidatorSetHash(validators.json) = 0x%x", vh)
	for _, b := range att.Blocs {
		fmt.Printf("bloc %d (%s, %s)\n", b.Height, b.Role, b.TransactionHash)
		var bloc enteteJSON
		lireRPC(filepath.Join(capDir, fmt.Sprintf("bloc-%d.json", b.Height)), &bloc)
		bh := hachageBFT(bloc)
		pre := hexutil.MustDecode(b.BftPreimage)
		constat(bh == common.HexToHash(bloc.Hash) && bh == common.HexToHash(b.BftBlockHash), "node.BFTBlockHash = %s = hash servi = attendu", bh.Hex())
		constat(len(pre) == 212 && crypto.Keccak256Hash(pre) == bh, "keccak256(préimage attendue de %d octets) = BFTBlockHash", len(pre))
		var recus []recuJSON
		for _, t := range bloc.Transactions {
			var r recuJSON
			lireRPC(filepath.Join(capDir, "recu-"+t+".json"), &r)
			recus = append(recus, r)
		}
		racine, liste := racineRecus(recus)
		constat(racine == common.HexToHash(bloc.ReceiptsRoot) && racine == common.HexToHash(b.ReceiptsRoot), "DeriveSha(%d reçu(s)) = %s = receiptsRoot servi = attendu", len(recus), racine.Hex())
		for i := range liste {
			var buf bytes.Buffer
			liste.EncodeIndex(i, &buf)
			constat(i < len(b.ReceiptEncodings) && "0x"+hex.EncodeToString(buf.Bytes()) == b.ReceiptEncodings[i], "encodage de consensus du reçu %d (EncodeIndex) = attendu", i)
		}
		var cible journalJSON
		for _, r := range recus {
			if strings.EqualFold(r.TransactionHash, b.TransactionHash) {
				cible = r.Logs[0]
			}
		}
		v, err := decoder(evts, b.Role, cible)
		ok := err == nil && len(v) == len(b.Event)
		for k, x := range b.Event {
			if v[k] != chaine(x) {
				ok = false
			}
		}
		constat(ok, "%s décodé par l'ABI = événement attendu (%d champs)", evenementDuRole[b.Role], len(b.Event))
		var c certificatJSON
		lireRPC(filepath.Join(capDir, fmt.Sprintf("certificat-%d.json", b.Height)), &c)
		prop, sig, ordre, err := verifierLignes(c, jeuCapture)
		constat(err == nil && common.HexToHash(c.BlockHash) == bh && common.HexToHash(c.ValsetHash) == common.BytesToHash(vh[:]), "certificat : proposition et %d precommits valides (VerifyEnvelope), quorum %d sur %d, blockHash = BFTBlockHash (err=%v)", len(sig), consensus.Quorum2f1(jeuCapture.Size()), jeuCapture.Size(), err)
		constat(prop == b.Certificate.Proposer && strings.Join(ordre, ",") == strings.Join(b.Certificate.PrecommitSigners, ","), "proposant %s, signataires %s = attendu", prop, strings.Join(ordre, ","))
	}

	// 2. Trie synthétique.
	fmt.Println("== 2. trie.json ==")
	var tr struct {
		Recus []struct {
			N        int        `json:"n"`
			Receipts []recuJSON `json:"receipts"`
			Root     string     `json:"root"`
		} `json:"recus"`
		Generique []struct {
			N     int `json:"n"`
			Pairs []struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			} `json:"pairs"`
			Root string `json:"root"`
		} `json:"generique"`
		Vide string `json:"vide"`
	}
	lire(filepath.Join(rep, "trie.json"), &tr)
	for _, x := range tr.Recus {
		racine, _ := racineRecus(x.Receipts)
		constat(racine == common.HexToHash(x.Root), "DeriveSha de %d reçus synthétiques = %s", x.N, racine.Hex())
	}
	for _, g := range tr.Generique {
		paires := g.Pairs
		sort.Slice(paires, func(i, j int) bool {
			return bytes.Compare(hexutil.MustDecode(paires[i].Key), hexutil.MustDecode(paires[j].Key)) < 0
		})
		st := trie.NewStackTrie(nil)
		for _, p := range paires {
			_ = st.Update(hexutil.MustDecode(p.Key), hexutil.MustDecode(p.Value))
		}
		constat(st.Hash() == common.HexToHash(g.Root), "StackTrie de %d couples génériques = %s", g.N, st.Hash().Hex())
	}
	constat(types.EmptyReceiptsHash == common.HexToHash(tr.Vide), "racine vide = types.EmptyReceiptsHash %s", types.EmptyReceiptsHash.Hex())
	k0, _ := rlp.EncodeToBytes(uint(0))
	constat(bytes.Equal(k0, []byte{0x80}), "clé RLP(0) = 0x80")

	// 3. Jeux de parties et variantes : vérifications R- refaites.
	fmt.Println("== 3. Jeux de parties et variantes : R-1 à R-10 et N-4 refaites en Go ==")
	var ancresBase any
	d := json.NewDecoder(bytes.NewReader(att.Ancres))
	d.UseNumber()
	_ = d.Decode(&ancresBase)
	var mattendu struct {
		Periodes []struct {
			Fichier    string `json:"fichier"`
			Canonical  string `json:"canonical"`
			PeriodHash string `json:"period_hash"`
		} `json:"periodes"`
	}
	lire(filepath.Join(ct1, "manifestes", "attendu.json"), &mattendu)
	var clesDoc struct {
		Keys []struct {
			KeyID     string `json:"key_id"`
			PublicKey string `json:"public_key"`
		} `json:"keys"`
	}
	lire(filepath.Join(ct1, "dossiers", "valide-seq-7", "cles.json"), &clesDoc)
	cles := map[string]string{}
	for _, k := range clesDoc.Keys {
		cles[k.PublicKey] = k.KeyID
	}
	jeux := append(append([]jeuAttendu{}, att.JeuxDeParties...), att.Variantes...)
	for _, j := range jeux {
		fichierManifeste := filepath.Base(j.Manifeste)
		var m manifeste
		lire(filepath.Join(ct1, "manifestes", fichierManifeste), &m)
		var ph common.Hash
		for _, p := range mattendu.Periodes {
			if p.Fichier == fichierManifeste {
				ph = sha256.Sum256(append([]byte("noortrace/manifeste/v0\n"), []byte(p.Canonical)...))
				if "0x"+hex.EncodeToString(ph[:]) != p.PeriodHash {
					constat(false, "periodHash de %s", fichierManifeste)
				}
			}
		}
		var p partiesJSON
		pdir := filepath.Join(rep, filepath.FromSlash(j.Parties))
		lire(filepath.Join(pdir, "registre.json"), &p.Registre)
		lire(filepath.Join(pdir, "certificat-commit.json"), &p.Certificats)
		if j.ValidateursPresent {
			p.Validateurs = &struct {
				Sets []jeuJSON `json:"sets"`
			}{}
			lire(filepath.Join(pdir, "validateurs.json"), p.Validateurs)
		}
		var a ancresJSON
		if j.Ancres != nil {
			brut, _ := json.Marshal(appliquer(copieProfonde(ancresBase), j.ModificationsAncres))
			_ = json.Unmarshal(brut, &a)
		}
		st := controle8(contexte{evts: evts, manifeste: m, periodHash: ph, cles: cles}, p, a)
		fmt.Printf("%s\n", j.Nom)
		ids := []string{"R-1", "R-2", "R-3", "R-4", "R-5", "R-6", "R-7", "R-8", "R-9", "R-10", "N-4"}
		for _, id := range ids {
			attendu, figure := j.Statuses[id]
			obtenu, calcule := st[id]
			if !figure && !calcule {
				continue
			}
			attenduCourt := strings.SplitN(attendu, ":", 2)[0]
			constat(figure && calcule && attenduCourt == obtenu, "%-4s go = %-11s attendu = %s", id, obtenu, attendu)
		}
	}

	fmt.Printf("\nconcordances : %d, écarts : %d\n", concordances, ecarts)
	if ecarts > 0 {
		os.Exit(1)
	}
}

func copieProfonde(v any) any {
	b, _ := json.Marshal(v)
	var out any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	_ = d.Decode(&out)
	return out
}
