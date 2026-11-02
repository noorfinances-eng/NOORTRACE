package registre

// Journaux d'événements (11.3.4, EX-11.9) : forme du journal prouvé de
// chaque rôle et valeurs décodées (facts.registry.entries[].event, EX-11.21).

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/cryptographie"
)

// Sujets (topics[0]) et docType de la période (EX-11.9, EX-11.18).
const (
	hexSujetCloture     = "0x6d6cb8da98056d2abd84165b9f6d64d8097b1e28deaf23013228f6bdd5370fba"
	hexSujetAncre       = "0x4450fd19f5dafd45e52f91aa82897967b7469e348fd7d5083f4e0515df90706e"
	hexSujetInscription = "0xe29e846d78f0b22a87c669add67dec8daa3b0935e6f4c96d7f627a60e7ae44ec"
	hexDocTypePeriode   = "0x2970f32daf26845541b559f8505ddade17ab51994fab81cbfe0dbd81ab9671ee"
)

// Signatures des événements (EX-11.9) ; leurs keccak256 sont les sujets.
const (
	signatureCloture     = "PeriodSubmitted(uint256,bytes32,bytes32,bytes32,bytes32,uint64,uint64,uint64,uint64,uint32,address,string,uint64)"
	signatureAncre       = "Anchored(bytes32,address,bytes32)"
	signatureInscription = "RecorderRegistered(bytes32,address,bytes32,bytes32,address)"
)

// positionURI : w8, position de uri dans les données de PeriodSubmitted.
const positionURI = 0x140

func h32(s string) [32]byte {
	h, _ := hex32(s)
	return h
}

var (
	sujetCloture     = h32(hexSujetCloture)
	sujetAncre       = h32(hexSujetAncre)
	sujetInscription = h32(hexSujetInscription)
	docTypePeriode   = h32(hexDocTypePeriode)
	docTypePoint     = h32(DocTypePoint)
)

// teteNulle dit si les n premiers octets d'un mot sont nuls (un entier ou
// une adresse occupe un mot dont les octets de tête sont nuls, EX-11.9).
func teteNulle(m []byte, n int) bool {
	for _, b := range m[:n] {
		if b != 0 {
			return false
		}
	}
	return true
}

func mot(d []byte, i int) []byte { return d[32*i : 32*i+32] }

// motU64 lit un mot uint64 (24 octets de tête nuls).
func motU64(m []byte) (uint64, bool) {
	if !teteNulle(m, 24) {
		return 0, false
	}
	return binary.BigEndian.Uint64(m[24:]), true
}

// adresseDeMot rend les 20 derniers octets d'un mot.
func adresseDeMot(m []byte) [20]byte {
	var a [20]byte
	copy(a[:], m[12:])
	return a
}

func hexA(a [20]byte) string { return cryptographie.Hex(a[:]) }

// formeCloture : PeriodSubmitted décodé, ou la liste des défauts de forme
// (4 sujets, topics[0], disposition des données, octets de remplissage nuls).
type formeCloture struct {
	ev      EvenementCloture
	defauts []commun.Texte
}

func lireCloture(j *journal) formeCloture {
	var f formeCloture
	ajout := func(fr, en string) { f.defauts = append(f.defauts, commun.T(fr, en)) }
	if len(j.sujets) != 4 {
		ajout(fmt.Sprintf("%d sujets au lieu de 4", len(j.sujets)), fmt.Sprintf("%d topics instead of 4", len(j.sujets)))
		return f
	}
	if j.sujets[0] != sujetCloture {
		ajout("topics[0] n'est pas PeriodSubmitted", "topics[0] is not PeriodSubmitted")
	}
	f.ev.Name = "PeriodSubmitted"
	id := j.sujets[1][:]
	if !teteNulle(id, 24) || id[24]&0x80 != 0 {
		ajout("identifiant (topics[1]) au-delà de 2^63 − 1, que le rapport ne peut pas écrire", "id (topics[1]) beyond 2^63 − 1, which the report cannot write")
	} else {
		f.ev.ID = int64(binary.BigEndian.Uint64(id[24:]))
	}
	f.ev.PeriodHash = cryptographie.Hex32(j.sujets[2])
	if !teteNulle(j.sujets[3][:], 12) {
		ajout("relayeur (topics[3]) : octets de tête non nuls", "relayer (topics[3]): non-zero leading bytes")
	}
	f.ev.Publisher = hexA(adresseDeMot(j.sujets[3][:]))
	d := j.donnees
	if len(d) < 11*32 || len(d)%32 != 0 {
		ajout(fmt.Sprintf("données de %d octets, disposition différente de EX-11.9", len(d)), fmt.Sprintf("data of %d bytes, layout differs from EX-11.9", len(d)))
		return f
	}
	f.ev.OrgID = cryptographie.Hex(mot(d, 0))
	f.ev.JournalID = cryptographie.Hex(mot(d, 1))
	f.ev.Root = cryptographie.Hex(mot(d, 2))
	entiers := []struct {
		dst  *int64
		nom  string
		tete int
	}{{&f.ev.PeriodStart, "periodStart", 24}, {&f.ev.PeriodEnd, "periodEnd", 24}, {&f.ev.FirstSeq, "firstSeq", 24}, {&f.ev.LastSeq, "lastSeq", 24}, {&f.ev.Version, "version", 28}}
	for k, e := range entiers {
		m := mot(d, 3+k)
		if !teteNulle(m, e.tete) || m[24]&0x80 != 0 {
			ajout(e.nom+" : octets de tête non nuls", e.nom+": non-zero leading bytes")
			continue
		}
		*e.dst = int64(binary.BigEndian.Uint64(m[24:]))
	}
	if p, ok := motU64(mot(d, 8)); !ok || p != positionURI {
		ajout("w8 différent de 0x140 (position de uri)", "w8 differs from 0x140 (position of uri)")
	}
	if pa, ok := motU64(mot(d, 9)); !ok || pa >= 1<<63 {
		ajout("publishedAt : octets de tête non nuls ou valeur au-delà de 2^63 − 1", "publishedAt: non-zero leading bytes or value beyond 2^63 − 1")
	} else {
		f.ev.PublishedAt = int64(pa)
	}
	l, ok := motU64(mot(d, 10))
	reste := uint64(len(d) - 11*32)
	if !ok || l > reste || (l+31)/32*32 != reste {
		ajout("longueur de uri incohérente avec les données", "length of uri inconsistent with the data")
		return f
	}
	uri := d[11*32 : 11*32+int(l)]
	if !teteNulle(d[11*32+int(l):], len(d)-11*32-int(l)) {
		ajout("remplissage de uri non nul", "non-zero padding of uri")
	}
	f.ev.URI = string(uri)
	return f
}

// formeAncre : Anchored décodé (rôles ancre et ancre_point_de_controle).
type formeAncre struct {
	ev       EvenementAncre
	emetteur [20]byte
	defauts  []commun.Texte
}

// lireAncre applique la forme d'Anchored : 3 sujets, topics[0], 32 octets de
// données ; teteEmetteur exige les octets de tête nuls du mot de l'émetteur.
func lireAncre(j *journal, teteEmetteur bool) formeAncre {
	var f formeAncre
	ajout := func(fr, en string) { f.defauts = append(f.defauts, commun.T(fr, en)) }
	f.ev.Name = "Anchored"
	if len(j.sujets) != 3 {
		ajout(fmt.Sprintf("%d sujets au lieu de 3", len(j.sujets)), fmt.Sprintf("%d topics instead of 3", len(j.sujets)))
		if len(j.sujets) < 3 {
			return f
		}
	}
	if j.sujets[0] != sujetAncre {
		ajout("topics[0] n'est pas Anchored", "topics[0] is not Anchored")
	}
	f.ev.Fingerprint = cryptographie.Hex32(j.sujets[1])
	f.emetteur = adresseDeMot(j.sujets[2][:])
	f.ev.Issuer = hexA(f.emetteur)
	if teteEmetteur && !teteNulle(j.sujets[2][:], 12) {
		ajout("émetteur (topics[2]) : octets de tête non nuls", "issuer (topics[2]): non-zero leading bytes")
	}
	if len(j.donnees) != 32 {
		ajout(fmt.Sprintf("données de %d octets au lieu de 32", len(j.donnees)), fmt.Sprintf("data of %d bytes instead of 32", len(j.donnees)))
		return f
	}
	f.ev.DocType = cryptographie.Hex(j.donnees)
	return f
}

// emetteurAncre rend l'émetteur d'un journal Anchored (topics[2], 20
// derniers octets), s'il a au moins 3 sujets.
func emetteurAncre(j *journal) ([20]byte, bool) {
	if j == nil || len(j.sujets) < 3 {
		return [20]byte{}, false
	}
	return adresseDeMot(j.sujets[2][:]), true
}

// formeInscription : RecorderRegistered décodé.
type formeInscription struct {
	ev        EvenementInscription
	cleChaine [20]byte
	cle       [32]byte
	defauts   []commun.Texte
}

func lireInscription(j *journal) formeInscription {
	var f formeInscription
	ajout := func(fr, en string) { f.defauts = append(f.defauts, commun.T(fr, en)) }
	f.ev.Name = "RecorderRegistered"
	if len(j.sujets) != 4 {
		ajout(fmt.Sprintf("%d sujets au lieu de 4", len(j.sujets)), fmt.Sprintf("%d topics instead of 4", len(j.sujets)))
		return f
	}
	if j.sujets[0] != sujetInscription {
		ajout("topics[0] n'est pas RecorderRegistered", "topics[0] is not RecorderRegistered")
	}
	f.ev.OrgID = cryptographie.Hex32(j.sujets[1])
	if !teteNulle(j.sujets[2][:], 12) {
		ajout("clé de chaîne (topics[2]) : octets de tête non nuls", "chain key (topics[2]): non-zero leading bytes")
	}
	f.cleChaine = adresseDeMot(j.sujets[2][:])
	f.ev.ChainKey = hexA(f.cleChaine)
	f.ev.JournalID = cryptographie.Hex32(j.sujets[3])
	if len(j.donnees) != 64 {
		ajout(fmt.Sprintf("données de %d octets au lieu de 64", len(j.donnees)), fmt.Sprintf("data of %d bytes instead of 64", len(j.donnees)))
		return f
	}
	copy(f.cle[:], j.donnees[:32])
	f.ev.Ed25519PubKey = cryptographie.Hex(j.donnees[:32])
	if !teteNulle(j.donnees[32:], 12) {
		ajout("relayeur : octets de tête non nuls", "relayer: non-zero leading bytes")
	}
	f.ev.Publisher = hexA(adresseDeMot(j.donnees[32:]))
	return f
}

// evenement rend les valeurs décodées du journal prouvé d'une entrée
// (EX-11.21), dans le type de son rôle.
func evenement(e *entreeRegistre) any {
	j := e.journalProuve()
	if j == nil {
		return struct{}{}
	}
	switch e.role {
	case roleCloture:
		return lireCloture(j).ev
	case roleInscription:
		return lireInscription(j).ev
	}
	return lireAncre(j, false).ev
}

// joindreDefauts joint des défauts par « , ».
func joindreDefauts(d []commun.Texte) commun.Texte {
	var fr, en []string
	for _, t := range d {
		fr, en = append(fr, t.Fr), append(en, t.En)
	}
	return commun.T(strings.Join(fr, ", "), strings.Join(en, ", "))
}
