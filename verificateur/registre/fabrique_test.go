package registre

// Fabrique de parties synthétiques du contrôle 8 : un jeu de quatre
// validateurs de clés connues, des blocs dont l'en-tête, les reçus et le
// certificat se recalculent, et des modificateurs qui altèrent une chose à
// la fois. Elle sert aux tests de chaque vérification en réussite et en
// échec (R-1 à R-11, N-4, K-8, AV-R-1 à AV-R-3, AV-K-1, AV-K-3).

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/noorfinances-eng/noortrace/verificateur/ancres"
	"github.com/noorfinances-eng/noortrace/verificateur/cryptographie"
	"github.com/noorfinances-eng/noortrace/verificateur/entree"
)

// signerRSV signe un condensé et rend R ‖ S ‖ V (V dans {0, 1}).
func signerRSV(k *secp256k1.PrivateKey, m [32]byte) []byte {
	c := ecdsa.SignCompact(k, m[:], false)
	out := make([]byte, 65)
	copy(out, c[1:])
	out[64] = c[0] - 27
	return out
}

func octets32(etiquette string) [32]byte { return cryptographie.Sha256([]byte(etiquette)) }

func adr(etiquette string) [20]byte {
	h := octets32(etiquette)
	var a [20]byte
	copy(a[:], h[:20])
	return a
}

func motAdresse(a [20]byte) [32]byte {
	var m [32]byte
	copy(m[12:], a[:])
	return m
}

func motEntier(n uint64) []byte {
	m := make([]byte, 32)
	binary.BigEndian.PutUint64(m[24:], n)
	return m
}

// blocFab : une entrée à fabriquer.
type blocFab struct {
	role   string
	numero uint64
	recus  []recu
	tx, lg int
	txHash string
	// apresHachage altère l'en-tête après le calcul du hachage (R-6).
	apresHachage func(*entete)
	// alterRecus altère les reçus écrits après le calcul de la racine (R-7).
	alterRecus func([]recu) []recu
}

// monde : tout ce qui sert à fabriquer une entrée du contrôle 8.
type monde struct {
	cles          map[string]*secp256k1.PrivateKey
	ids           []string
	chainID       string
	pr, ar, rr    [20]byte
	org, jr, ph   [32]byte
	root          [32]byte
	ckA, ckB      [20]byte
	pubA, pubB    [32]byte
	ckPoint       [32]byte
	blocs         []*blocFab
	signataires   map[uint64][]string
	avant, apres  func(h uint64, i int, e *enveloppe)
	certAltere    func(c map[string]any)
	sansRegistre  bool
	jeuAncre      *ancres.JeuValidateurs
	recorders     []ancres.Enregistreur
	cles8         []ancres.CleDossier
	man           Manifeste
	point         *Point
	validateurs   []byte // nil : validateurs.json du jeu de l'ancre
	sansValidRais string // non vide : validateurs.json absent avec cette raison
}

func (m *monde) horodatage(n uint64) uint64 { return 1792700000 + n }

func (m *monde) jInscription(cle [32]byte, ck [20]byte) journal {
	ckm := motAdresse(ck)
	rel := motAdresse(adr("relayeur"))
	return journal{adresse: m.rr, sujets: [][32]byte{sujetInscription, m.org, ckm, m.jr}, donnees: append(append([]byte{}, cle[:]...), rel[:]...)}
}

func (m *monde) jAncre(fp [32]byte, emetteur [20]byte, doc [32]byte) journal {
	return journal{adresse: m.ar, sujets: [][32]byte{sujetAncre, fp, motAdresse(emetteur)}, donnees: append([]byte{}, doc[:]...)}
}

func (m *monde) jCloture(numero uint64, uri string) journal {
	var d []byte
	d = append(d, m.org[:]...)
	d = append(d, m.jr[:]...)
	d = append(d, m.root[:]...)
	for _, v := range []int64{m.man.PeriodStart, m.man.PeriodEnd, m.man.FirstSeq, m.man.LastSeq, m.man.Version} {
		d = append(d, motEntier(uint64(v))...)
	}
	d = append(d, motEntier(positionURI)...)
	d = append(d, motEntier(m.horodatage(numero))...)
	d = append(d, motEntier(uint64(len(uri)))...)
	u := []byte(uri)
	for len(u)%32 != 0 {
		u = append(u, 0)
	}
	d = append(d, u...)
	var id [32]byte
	id[31] = 5
	return journal{adresse: m.pr, sujets: [][32]byte{sujetCloture, id, m.ph, motAdresse(adr("relayeur"))}, donnees: d}
}

func recuDe(j journal) recu { return recu{genre: 2, statut: 1, cumul: 21000, journaux: []journal{j}} }

// nouveauMonde : quatre validateurs, deux clés d'enregistreur inscrites,
// l'ancre et la clôture de la période, l'ancre d'un point de contrôle et sa
// référence ; tout réussit.
func nouveauMonde() *monde {
	m := &monde{cles: map[string]*secp256k1.PrivateKey{}, chainID: "noortrace-essai", signataires: map[uint64][]string{}}
	for _, id := range []string{"v1", "v2", "v3", "v4"} {
		k := octets32("validateur/" + id)
		m.cles[id] = secp256k1.PrivKeyFromBytes(k[:])
		m.ids = append(m.ids, id)
	}
	m.pr, m.ar, m.rr = adr("PeriodRegistry"), adr("AttestationRegistry"), adr("RecorderRegistry")
	m.org, m.jr, m.ph, m.root = octets32("org"), octets32("journal"), octets32("periode"), octets32("racine")
	m.ckA, m.ckB = adr("chaine-A"), adr("chaine-B")
	m.pubA, m.pubB = octets32("ed25519-A"), octets32("ed25519-B")
	m.ckPoint = octets32("point")
	m.man = Manifeste{Valide: true, PeriodHash: m.ph, OrgID: cryptographie.Hex32(m.org), JournalID: cryptographie.Hex32(m.jr), Root: cryptographie.Hex32(m.root),
		PeriodStart: 1793869200, PeriodEnd: 1793872800, FirstSeq: 1, LastSeq: 9, Version: 0, RecorderKeyID: "rec-a"}
	m.cles8 = []ancres.CleDossier{{KeyID: "rec-a", ClePublique: cryptographie.Hex32(m.pubA)}, {KeyID: "rec-b", ClePublique: cryptographie.Hex32(m.pubB)}}
	fpPeriode := cryptographie.Keccak256(m.org[:], m.jr[:], m.ph[:])
	fpPoint := cryptographie.Keccak256(m.org[:], m.jr[:], m.ckPoint[:])
	m.blocs = []*blocFab{
		{role: roleInscription, numero: 100, recus: []recu{recuDe(m.jInscription(m.pubA, m.ckA))}},
		{role: roleInscription, numero: 104, recus: []recu{recuDe(m.jInscription(m.pubB, m.ckB))}},
		{role: roleAncre, numero: 108, recus: []recu{recuDe(m.jAncre(fpPeriode, m.ckA, docTypePeriode))}},
		{role: roleCloture, numero: 112, recus: []recu{{genre: 0, statut: 0, cumul: 100}, recuDe(m.jCloture(112, "e2e://essai"))}, tx: 1},
		{role: rolePoint, numero: 116, recus: []recu{recuDe(m.jAncre(fpPoint, m.ckB, docTypePoint))}},
	}
	for i, b := range m.blocs {
		b.txHash = cryptographie.Hex32(octets32(fmt.Sprintf("tx-%d", i)))
	}
	m.recorders = []ancres.Enregistreur{
		{Pointeur: "/recorders/0", OrgID: m.man.OrgID, JournalID: m.man.JournalID, KeyID: "rec-a", ClePublique: cryptographie.Hex32(m.pubA), CleChaine: hexA(m.ckA)},
		{Pointeur: "/recorders/1", OrgID: m.man.OrgID, JournalID: m.man.JournalID, KeyID: "rec-b", ClePublique: cryptographie.Hex32(m.pubB), CleChaine: hexA(m.ckB)},
	}
	m.point = &Point{K2: true, CheckpointHash: m.ckPoint, KeyID: "rec-b", Reference: &ReferencePoint{ChainID: 2124, Contract: hexA(m.ar),
		Fingerprint: cryptographie.Hex32(fpPoint), DocType: DocTypePoint, BlockNumber: 116, LogIndex: 0, TransactionHash: m.blocs[4].txHash}}
	return m
}

// bloc rend le bloc d'un rôle (le premier).
func (m *monde) bloc(role string) *blocFab {
	for _, b := range m.blocs {
		if b.role == role {
			return b
		}
	}
	return nil
}

// retirer retire les blocs d'un rôle.
func (m *monde) retirer(role string) {
	var out []*blocFab
	for _, b := range m.blocs {
		if b.role != role {
			out = append(out, b)
		}
	}
	m.blocs = out
}

func (m *monde) jeu() ancres.JeuValidateurs {
	j := ancres.JeuValidateurs{Pointeur: "/registry/validator_sets/0", De: 1, Source: "jeu d'essai"}
	for _, id := range m.ids {
		c := m.cles[id].PubKey().SerializeUncompressed()
		j.Validateurs = append(j.Validateurs, ancres.Validateur{ID: id, CleHex: cryptographie.Hex(c), Cle: c})
	}
	return j
}

func q(n uint64) string { return fmt.Sprintf("0x%x", n) }

// entree fabrique l'entrée du contrôle 8.
func (m *monde) entree() Entree {
	jeu := m.jeu()
	if m.jeuAncre != nil {
		jeu = *m.jeuAncre
	}
	j0 := m.jeu()
	vs := hachageJeu(&j0)
	var entrees []map[string]any
	var certs []map[string]any
	vus := map[uint64]bool{}
	for _, b := range m.blocs {
		racine, _ := racineRecus(b.recus)
		e := entete{numero: b.numero, horodatage: m.horodatage(b.numero), gazUtilise: 21000, gazLimite: 30000000,
			parent: octets32(fmt.Sprintf("parent-%d", b.numero)), etat: octets32("etat"), transactions: octets32("tx"), recus: racine}
		e.baseFee[31] = 1
		e.hachage = hachageBFT(&e)
		orig := e.hachage
		if b.apresHachage != nil {
			b.apresHachage(&e)
		}
		ecrits := b.recus
		if b.alterRecus != nil {
			ecrits = b.alterRecus(append([]recu{}, b.recus...))
		}
		var recus []map[string]any
		for _, r := range ecrits {
			var logs []map[string]any
			for _, j := range r.journaux {
				var t []string
				for _, s := range j.sujets {
					t = append(t, cryptographie.Hex32(s))
				}
				if t == nil {
					t = []string{}
				}
				logs = append(logs, map[string]any{"address": hexA(j.adresse), "topics": t, "data": cryptographie.Hex(j.donnees)})
			}
			if logs == nil {
				logs = []map[string]any{}
			}
			recus = append(recus, map[string]any{"type": q(uint64(r.genre)), "status": q(uint64(r.statut)), "cumulativeGasUsed": q(r.cumul), "logs": logs})
		}
		entrees = append(entrees, map[string]any{"role": b.role, "transaction_index": b.tx, "log_index": b.lg, "transaction_hash": b.txHash, "receipts": recus,
			"block": map[string]any{"number": q(e.numero), "hash": cryptographie.Hex32(e.hachage), "parentHash": cryptographie.Hex32(e.parent), "timestamp": q(e.horodatage),
				"stateRoot": cryptographie.Hex32(e.etat), "transactionsRoot": cryptographie.Hex32(e.transactions), "receiptsRoot": cryptographie.Hex32(e.recus),
				"gasUsed": q(e.gazUtilise), "gasLimit": q(e.gazLimite), "baseFeePerGas": "0x1"}})
		if b.role == rolePoint && m.point != nil && m.point.Reference != nil {
			m.point.Reference.BlockHash = cryptographie.Hex32(e.hachage)
		}
		if vus[b.numero] {
			continue
		}
		vus[b.numero] = true
		c := certificat{hauteur: b.numero, chainID: m.chainID, valset: vs, bloc: orig}
		sig := m.signataires[b.numero]
		if sig == nil {
			sig = []string{"v4", "v1", "v3"}
		}
		ligne := func(i int, typ, id string, corps any) map[string]any {
			body, _ := json.Marshal(corps)
			bh := sha256.Sum256(body)
			env := enveloppe{Domain: domaineBFT, ChainID: c.chainID, Type: typ, ValidatorID: id, ValsetHash: c.valset[:], Height: c.hauteur, Round: 0, BlockHash: c.bloc[:], BodyHash: bh[:], Body: body}
			if m.avant != nil {
				m.avant(b.numero, i, &env)
			}
			if k, ok := m.cles[id]; ok {
				env.Sig = signerRSV(k, condenseSigne(&env))
			} else {
				env.Sig = make([]byte, 65)
			}
			if m.apres != nil {
				m.apres(b.numero, i, &env)
			}
			l, _ := json.Marshal(&env)
			return map[string]any{"line": string(l), "validatorId": id}
		}
		bloc := cryptographie.Hex32(c.bloc)
		prop := ligne(0, typeProposition, "v1", corpsProposition{Height: c.hauteur, Proposer: "v1", BlockHash: bloc})
		var pre []map[string]any
		for k, id := range sig {
			pre = append(pre, ligne(k+1, typePrecommit, id, corpsVote{Height: c.hauteur, Voter: id, Type: 2, BlockHash: bloc}))
		}
		cm := map[string]any{"height": q(c.hauteur), "round": "0x0", "chainId": c.chainID, "valsetHash": cryptographie.Hex32(c.valset), "blockHash": bloc,
			"proposal": prop, "precommits": pre, "quorum": map[string]any{"required": 3}}
		if m.certAltere != nil {
			m.certAltere(cm)
		}
		certs = append(certs, cm)
	}
	reg, _ := json.Marshal(map[string]any{"version": 0, "source": "fabrique d'essai", "entries": entrees})
	cc, _ := json.Marshal(map[string]any{"version": 0, "certificates": certs})
	e := Entree{
		Registre:         Partie{Presente: true, Etat: entree.Lu, Octets: reg},
		Certificat:       Partie{Presente: true, Etat: entree.Lu, Octets: cc},
		Manifeste:        m.man,
		ClesExploitables: true,
		Cles:             m.cles8,
		OrgID:            cryptographie.Hex32(m.org),
		JournalID:        cryptographie.Hex32(m.jr),
		Point:            m.point,
	}
	switch {
	case m.sansValidRais != "":
		e.Validateurs = Partie{RaisonAbsence: m.sansValidRais}
	case m.validateurs != nil:
		e.Validateurs = Partie{Presente: true, Etat: entree.Lu, Octets: m.validateurs}
	default:
		j := m.jeu()
		var vals []map[string]any
		for _, v := range j.Validateurs {
			vals = append(vals, map[string]any{"id": v.ID, "pubKeyHex": v.CleHex})
		}
		b, _ := json.Marshal(map[string]any{"version": 0, "sets": []any{map[string]any{"from_height": 1, "to_height": nil, "validators": vals, "source": "déclaré"}}})
		e.Validateurs = Partie{Presente: true, Etat: entree.Lu, Octets: b}
	}
	if !m.sansRegistre {
		e.Ancres = &ancres.Ancres{Registre: &ancres.Registre{ChainID: m.chainID, PeriodRegistry: m.pr, AttestationRegistry: m.ar, RecorderRegistry: m.rr,
			Jeux: []ancres.JeuValidateurs{jeu}, Source: "ancre d'essai"}, Enregistreurs: m.recorders}
	} else {
		e.Ancres = &ancres.Ancres{Enregistreurs: m.recorders}
	}
	return e
}
