// Capture d'une transaction du registre (CT-4 9.4) : CP-2 à CP-6 recalculées
// hors ligne sur l'index et les réponses brutes, et export des parties du
// dossier (9.6).
//
// Lectures retenues là où le texte laisse un choix :
//   - CP-2 « hash de l'en-tête égale blockHash du reçu » : le reçu est celui
//     de la transaction capturée (receipts[transaction_index]) ; l'index en
//     reporte block_hash et block_number, qui doivent aussi égaler l'en-tête ;
//   - CP-3 « un reçu par hachage de transactions, dans cet ordre » : le reçu
//     de rang i a pour transactionHash le hachage de rang i de l'en-tête (la
//     correspondance se lit dans le reçu, le nom du fichier relevant de
//     CP-6) ;
//   - CP-4 : l'index désigne par validator_set_hash le jeu contre lequel le
//     certificat est vérifié ; ce hachage doit être celui du jeu employé ;
//   - CP-5 : rôles à événement et événement attendu selon OP-11 (7.3) ;
//     deploiement et approvisionnement n'ont pas de journal (log_index nul).

package main

import (
	"bytes"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Événements attendus par rôle (OP-11, 5.7).
var evenementsRole = map[string][]string{
	"inscription":        {"RecorderRegistered(bytes32,address,bytes32,bytes32,address)"},
	"ancre":              {"Anchored(bytes32,address,bytes32)"},
	"cloture":            {"PeriodSubmitted(uint256,bytes32,bytes32,bytes32,bytes32,uint64,uint64,uint64,uint64,uint32,address,string,uint64)"},
	"revocation":         {"RecorderRevoked(bytes32,address,address)"},
	"assignation":        {"CuratorSetAssigned(bytes32,address,address)"},
	"reassignation":      {"CuratorSetAssigned(bytes32,address,address)"},
	"administration_jeu": {"AdminOpRelayed(bytes32,address,uint256)"},
	"jeu_approbateurs":   {"AdminAccepted(address,address)", "CuratorAdded(address)", "ThresholdUpdated(uint256)"},
}

// ResultatCapture porte les verdicts CP-2 à CP-6 d'un index et ce qui a été
// lu.
type ResultatCapture struct {
	Verdicts map[string]*Echec // nil : réussi
	Index    *Value
	EnTete   EnTete
	BlocBrut *Value
	Recus    []Recu
	RecusBr  []*Value
	Cert     Certificat
	CertBrut *Value
	Txs      [][]byte
	lu       bool
}

func cpEchec(cp, code, format string, a ...any) *Echec {
	return echecCode(cp, code, true, format, a...)
}

var reRecu = regexp.MustCompile(`^recu-0x[0-9a-f]{64}\.json$`)

// VerifierCapture recalcule CP-2 à CP-6 sur l'index nomIndex du répertoire
// rep, le certificat étant vérifié contre jeu sous l'identifiant BFT bft.
func (c *Ctx) VerifierCapture(rep, nomIndex string, jeu *JeuValidateurs, bft string) ResultatCapture {
	res := ResultatCapture{Verdicts: map[string]*Echec{}}
	for _, cp := range []string{"CP-2", "CP-3", "CP-4", "CP-5", "CP-6"} {
		res.Verdicts[cp] = nil
	}
	tous := func(e *Echec) {
		for cp := range res.Verdicts {
			res.Verdicts[cp] = &Echec{Check: cp, Code: e.Code, Fixe: e.Fixe, Raison: e.Raison}
		}
	}
	idx, _, err := LireJSON(filepath.Join(rep, nomIndex))
	if err != nil {
		tous(cpEchec("CP-6", "capture_incomplete", "index illisible : %v", err))
		return res
	}
	res.Index = idx
	// CP-6 : schéma de l'index, noms, SHA-256, réponses brutes complètes.
	var cp6 []string
	if errs := c.Schemas.Valider("operations-registre-v0.schema.json", idx); len(errs) > 0 {
		cp6 = append(cp6, "index non conforme à son schéma : "+strings.Join(errs, " ; "))
	}
	h, _ := EntierLitteral(idx.Get("block_number").Num)
	ti64, _ := EntierLitteral(idx.Get("transaction_index").Num)
	if h == nil || ti64 == nil {
		tous(cpEchec("CP-6", "capture_incomplete", "index : block_number ou transaction_index illisible"))
		return res
	}
	ti := int(ti64.Int64())
	role := idx.Get("role").S()
	if want := fmt.Sprintf("capture-%s-%d-%s.json", h, ti, role); nomIndex != want {
		cp6 = append(cp6, fmt.Sprintf("index nommé %s au lieu de %s", nomIndex, want))
	}
	fichiers := idx.Get("files")
	lire := func(o *Value, nomAttendu string) (*Value, error) {
		nom := o.Get("name").S()
		if nomAttendu != "" && nom != nomAttendu {
			cp6 = append(cp6, fmt.Sprintf("fichier %s au lieu de %s", nom, nomAttendu))
		}
		if strings.ContainsAny(nom, "/\\") {
			cp6 = append(cp6, "fichier "+nom+" hors du répertoire des captures")
		}
		b, err := os.ReadFile(filepath.Join(rep, nom))
		if err != nil {
			cp6 = append(cp6, "fichier "+nom+" absent")
			return nil, err
		}
		if Hex0x(Sha256(b)) != o.Get("sha256").S() {
			cp6 = append(cp6, "SHA-256 de "+nom+" différent de celui de l'index")
		}
		v, err := ParseJSON(b)
		if err != nil {
			cp6 = append(cp6, nom+" : "+err.Error())
			return nil, err
		}
		r, err := resultatRPC(v)
		if err != nil || v.Get("id") == nil {
			cp6 = append(cp6, nom+" : réponse JSON-RPC complète attendue")
			if err == nil {
				err = fmt.Errorf("id absent")
			}
			return nil, err
		}
		return r, nil
	}
	blocR, errBloc := lire(fichiers.Get("block"), fmt.Sprintf("bloc-%s.json", h))
	var et EnTete
	if errBloc == nil {
		et, errBloc = LireEnTete(blocR)
	}
	res.EnTete, res.BlocBrut = et, blocR
	var recus []Recu
	var errRecus error
	for i, o := range fichiers.Get("receipts").Arr {
		nomAtt := ""
		if errBloc == nil && i < len(et.Transactions) {
			nomAtt = "recu-" + et.Transactions[i] + ".json"
		} else if !reRecu.MatchString(o.Get("name").S()) {
			cp6 = append(cp6, "reçu "+o.Get("name").S()+" hors de la forme recu-<hachage>.json")
		}
		r, err := lire(o, nomAtt)
		if err != nil {
			errRecus = err
			continue
		}
		rc, err := LireRecu(r)
		if err != nil {
			errRecus = err
			continue
		}
		recus = append(recus, rc)
		res.RecusBr = append(res.RecusBr, r)
	}
	res.Recus = recus
	certR, errCert := lire(fichiers.Get("certificate"), fmt.Sprintf("certificat-%s.json", h))
	res.CertBrut = certR
	if len(cp6) > 0 {
		res.Verdicts["CP-6"] = cpEchec("CP-6", "capture_incomplete", "%s", strings.Join(cp6, " ; "))
	}

	// CP-2 : en-tête.
	if errBloc != nil {
		res.Verdicts["CP-2"] = cpEchec("CP-2", "capture_incomplete", "en-tête illisible : %v", errBloc)
	} else {
		bh, err := BFTBlockHash(et)
		switch {
		case err != nil:
			res.Verdicts["CP-2"] = cpEchec("CP-2", "capture_incomplete", "%v", err)
		case !bytes.Equal(bh, et.Hash):
			res.Verdicts["CP-2"] = cpEchec("CP-2", "capture_incomplete", "BFTBlockHash %s différent de hash %s", Hex0x(bh), Hex0x(et.Hash))
		case et.Number.Cmp(h) != 0:
			res.Verdicts["CP-2"] = cpEchec("CP-2", "capture_incomplete", "en-tête de hauteur %s au lieu de %s", et.Number, h)
		case idx.Get("block_hash").S() != Hex0x(et.Hash):
			res.Verdicts["CP-2"] = cpEchec("CP-2", "capture_incomplete", "block_hash de l'index %s différent de hash de l'en-tête", idx.Get("block_hash").S())
		case errRecus == nil && ti < len(recus) && recus[ti].BlockHash != Hex0x(et.Hash):
			res.Verdicts["CP-2"] = cpEchec("CP-2", "capture_incomplete", "blockHash du reçu %s différent de hash de l'en-tête", recus[ti].BlockHash)
		}
	}

	// CP-3 : reçus.
	switch {
	case errBloc != nil || errRecus != nil:
		res.Verdicts["CP-3"] = cpEchec("CP-3", "capture_incomplete", "en-tête ou reçus illisibles")
	case len(recus) != len(et.Transactions):
		res.Verdicts["CP-3"] = cpEchec("CP-3", "capture_incomplete", "%d reçus pour %d transactions", len(recus), len(et.Transactions))
	default:
		for i, r := range recus {
			if r.TxHash != et.Transactions[i] {
				res.Verdicts["CP-3"] = cpEchec("CP-3", "capture_incomplete", "reçu de rang %d de transactionHash %s au lieu de %s", i, r.TxHash, et.Transactions[i])
				break
			}
		}
		if res.Verdicts["CP-3"] == nil {
			if rr := RacineRecus(recus); !bytes.Equal(rr, et.RcptRoot) {
				res.Verdicts["CP-3"] = cpEchec("CP-3", "capture_incomplete", "racine des reçus recalculée %s différente de receiptsRoot %s", Hex0x(rr), Hex0x(et.RcptRoot))
			} else if ti >= len(et.Transactions) || et.Transactions[ti] != idx.Get("transaction_hash").S() {
				res.Verdicts["CP-3"] = cpEchec("CP-3", "capture_incomplete", "la transaction capturée n'est pas à transaction_index %d", ti)
			}
		}
	}

	// CP-4 : certificat.
	switch {
	case errCert != nil:
		res.Verdicts["CP-4"] = cpEchec("CP-4", "certificat_indisponible", "certificat illisible : %v", errCert)
	case jeu == nil:
		res.Verdicts["CP-4"] = cpEchec("CP-4", "certificat_invalide", "aucun jeu de validateurs pour la hauteur %s", h)
	default:
		cert, err := LireCertificat(certR)
		res.Cert = cert
		if err != nil {
			res.Verdicts["CP-4"] = cpEchec("CP-4", "certificat_invalide", "%v", err)
			break
		}
		if cert.ChainID != bft {
			res.Verdicts["CP-4"] = cpEchec("CP-4", "certificat_invalide", "chainId %q au lieu de %q", cert.ChainID, bft)
			break
		}
		if new(big.Int).SetUint64(cert.Height).Cmp(h) != 0 {
			res.Verdicts["CP-4"] = cpEchec("CP-4", "certificat_invalide", "height %d au lieu de %s", cert.Height, h)
			break
		}
		if errBloc != nil || !bytes.Equal(cert.BlockHash, et.Hash) {
			res.Verdicts["CP-4"] = cpEchec("CP-4", "certificat_invalide", "blockHash du certificat différent de hash de l'en-tête")
			break
		}
		txs, _, err := VerifierCertificat(cert, *jeu)
		if err != nil {
			res.Verdicts["CP-4"] = cpEchec("CP-4", "certificat_invalide", "%v", err)
			break
		}
		if idx.Get("validator_set_hash").S() != Hex0x(jeu.Hachage()) {
			res.Verdicts["CP-4"] = cpEchec("CP-4", "certificat_invalide", "validator_set_hash de l'index différent du hachage du jeu employé")
			break
		}
		res.Txs = txs
		if ti >= len(txs) || Hex0x(Keccak256(txs[ti])) != idx.Get("transaction_hash").S() {
			res.Verdicts["CP-4"] = cpEchec("CP-4", "certificat_invalide", "txsRaw[%d] n'a pas pour hachage transaction_hash", ti)
			break
		}
		if r := RacineIndexee(txs); !bytes.Equal(r, et.TxRoot) {
			res.Verdicts["CP-4"] = cpEchec("CP-4", "certificat_invalide", "racine des transactions %s différente de transactionsRoot", Hex0x(r))
		}
	}

	// CP-5 : journal prouvé.
	evts, aEvt := evenementsRole[role]
	li := idx.Get("log_index")
	switch {
	case !aEvt:
		if li != nil && !li.IsNull() {
			res.Verdicts["CP-5"] = cpEchec("CP-5", "capture_incomplete", "rôle %s sans événement mais log_index non nul", role)
		}
	case errRecus != nil || ti >= len(recus):
		res.Verdicts["CP-5"] = cpEchec("CP-5", "capture_incomplete", "reçu de la transaction illisible")
	case li == nil || li.IsNull():
		res.Verdicts["CP-5"] = cpEchec("CP-5", "capture_incomplete", "log_index nul pour un rôle à événement")
	default:
		n, _ := EntierLitteral(li.Num)
		js := recus[ti].Journaux
		if n == nil || int(n.Int64()) >= len(js) {
			res.Verdicts["CP-5"] = cpEchec("CP-5", "capture_incomplete", "log_index %s hors des %d journaux du reçu", li.Num, len(js))
			break
		}
		j := js[n.Int64()]
		if Hex0x(j.Adresse) != idx.Get("contract").S() {
			res.Verdicts["CP-5"] = cpEchec("CP-5", "capture_incomplete", "journal émis par %s au lieu de contract %s", Hex0x(j.Adresse), idx.Get("contract").S())
			break
		}
		ok := false
		for _, e := range evts {
			ok = ok || (len(j.Sujets) > 0 && bytes.Equal(j.Sujets[0], Keccak256([]byte(e))))
		}
		if !ok {
			res.Verdicts["CP-5"] = cpEchec("CP-5", "capture_incomplete", "topics[0] du journal n'est pas celui du rôle %s", role)
			break
		}
		if err := dispositionJournal(role, j); err != nil {
			res.Verdicts["CP-5"] = cpEchec("CP-5", "capture_incomplete", "%v", err)
		}
	}
	res.lu = true
	return res
}

// dispositionJournal contrôle la disposition de CT-6 EX-11.9 pour les rôles
// inscription, ancre et cloture (nombre de sujets, longueur des données,
// octets de tête nuls des adresses et entiers).
func dispositionJournal(role string, j Journal) error {
	zeros := func(b []byte) bool { return estNul(b) }
	switch role {
	case "ancre":
		if len(j.Sujets) != 3 || len(j.Donnees) != 32 {
			return fmt.Errorf("Anchored : 3 sujets et 32 octets attendus")
		}
		if !zeros(j.Sujets[2][:12]) {
			return fmt.Errorf("Anchored : émetteur mal disposé")
		}
	case "inscription":
		if len(j.Sujets) != 4 || len(j.Donnees) != 64 {
			return fmt.Errorf("RecorderRegistered : 4 sujets et 64 octets attendus")
		}
		if !zeros(j.Sujets[2][:12]) || !zeros(j.Donnees[32:44]) {
			return fmt.Errorf("RecorderRegistered : adresse mal disposée")
		}
	case "cloture":
		if len(j.Sujets) != 4 || len(j.Donnees) < 11*32 || len(j.Donnees)%32 != 0 {
			return fmt.Errorf("PeriodSubmitted : 4 sujets et au moins 11 mots attendus")
		}
		w := func(i int) []byte { return j.Donnees[32*i : 32*(i+1)] }
		for _, i := range []int{3, 4, 5, 6, 9} {
			if !zeros(w(i)[:24]) {
				return fmt.Errorf("PeriodSubmitted : mot %d au-delà de 64 bits", i)
			}
		}
		if !zeros(w(7)[:28]) {
			return fmt.Errorf("PeriodSubmitted : version au-delà de 32 bits")
		}
		if new(big.Int).SetBytes(w(8)).Cmp(big.NewInt(0x140)) != 0 {
			return fmt.Errorf("PeriodSubmitted : w8 différent de 0x140")
		}
		lu := new(big.Int).SetBytes(w(10))
		if !lu.IsInt64() || 32*11+32*((int(lu.Int64())+31)/32) != len(j.Donnees) {
			return fmt.Errorf("PeriodSubmitted : longueur de uri incohérente")
		}
		if !zeros(j.Donnees[32*11+int(lu.Int64()):]) || !zeros(j.Sujets[3][:12]) {
			return fmt.Errorf("PeriodSubmitted : octets de remplissage non nuls")
		}
	}
	return nil
}

// ------------------------------------------------------------ export

// champsEnTete sont les dix champs engagés (CT-6 §11.2.1).
var champsEnTete = []string{"number", "hash", "parentHash", "timestamp", "stateRoot", "transactionsRoot", "receiptsRoot", "gasUsed", "gasLimit", "baseFeePerGas"}

// EntreeRegistre construit l'entrée de registre.json d'une capture (EX-9.8).
func EntreeRegistre(res ResultatCapture) *Value {
	bloc := Objet()
	for _, k := range champsEnTete {
		bloc.Obj = append(bloc.Obj, Member{k, Chaine(strings.ToLower(res.BlocBrut.Get(k).S()))})
	}
	recus := Tableau()
	for _, r := range res.RecusBr {
		logs := Tableau()
		for _, l := range r.Get("logs").Arr {
			sujets := Tableau()
			for _, s := range l.Get("topics").Arr {
				sujets.Arr = append(sujets.Arr, Chaine(strings.ToLower(s.S())))
			}
			logs.Arr = append(logs.Arr, Objet("address", Chaine(strings.ToLower(l.Get("address").S())), "topics", sujets, "data", Chaine(strings.ToLower(l.Get("data").S()))))
		}
		recus.Arr = append(recus.Arr, Objet("type", Chaine(strings.ToLower(r.Get("type").S())), "status", Chaine(strings.ToLower(r.Get("status").S())),
			"cumulativeGasUsed", Chaine(strings.ToLower(r.Get("cumulativeGasUsed").S())), "logs", logs))
	}
	idx := res.Index
	return Objet("role", Chaine(idx.Get("role").S()), "block", bloc, "receipts", recus,
		"transaction_index", Copier(idx.Get("transaction_index")), "log_index", Copier(idx.Get("log_index")),
		"transaction_hash", Chaine(idx.Get("transaction_hash").S()))
}
