// Conventions calculées hors chaîne, CT-4 section 6 : RG-1 à RG-13.
//
// Chaque fonction rend la valeur recalculée, ou une erreur Echec qui nomme
// la vérification en échec et la raison. Les motifs d'échec des RG- ne sont
// pas fixés par la spécification (6.9 : « Chaque vérification rend reussi ou
// echoue ») : le texte de la raison est propre à ce vérificateur et n'est
// jamais confronté aux motifs des vecteurs.

package main

import (
	"bytes"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strings"
)

// Echec est l'échec d'une vérification.
type Echec struct {
	Check  string // RG-…, OP-…, CP-…
	Code   string // code de la spécification, quand elle en fixe un
	Fixe   bool   // vrai si la spécification fixe le code pour ce cas
	Raison string
}

func (e *Echec) Error() string {
	if e.Code != "" {
		return e.Check + " " + e.Code + " : " + e.Raison
	}
	return e.Check + " : " + e.Raison
}

func echec(check, format string, a ...any) *Echec {
	return &Echec{Check: check, Raison: fmt.Sprintf(format, a...)}
}

func echecCode(check, code string, fixe bool, format string, a ...any) *Echec {
	return &Echec{Check: check, Code: code, Fixe: fixe, Raison: fmt.Sprintf(format, a...)}
}

var (
	reSlug       = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)
	reSlugProd   = regexp.MustCompile(`^o-[0-9a-f]{32}$`)
	reLibelle    = regexp.MustCompile(`^noortrace/[a-z0-9][a-z0-9-]{0,31}/v(0|[1-9][0-9]{0,2})$`)
	deuxAMoins64 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 64), big.NewInt(1))
)

// TableDocType est la table de EX-6.5 : libellé → docType.
var TableDocType = []string{"noortrace/periode/v0"}

// RG1 : slug et org_id (EX-6.2).
func RG1(slug string, production bool) ([]byte, *Echec) {
	if !reSlug.MatchString(slug) {
		return nil, echec("RG-1", "slug %q hors de la grammaire", slug)
	}
	if production && !reSlugProd.MatchString(slug) {
		return nil, echec("RG-1", "slug de production %q : « o- » et 32 chiffres hexadécimaux attendus", slug)
	}
	id := Keccak256([]byte(slug))
	if estNul(id) {
		return nil, echec("RG-1", "org_id nul")
	}
	return id, nil
}

// RG2 : nom de journal et journal_id (EX-6.4).
func RG2(nom string) ([]byte, *Echec) {
	if !reSlug.MatchString(nom) {
		return nil, echec("RG-2", "nom de journal %q hors de la grammaire", nom)
	}
	id := Keccak256([]byte(nom))
	if estNul(id) {
		return nil, echec("RG-2", "journal_id nul")
	}
	return id, nil
}

// RG3Libelle : libellé → docType (EX-6.5).
func RG3Libelle(lib string) ([]byte, *Echec) {
	if !reLibelle.MatchString(lib) {
		return nil, echec("RG-3", "libellé %q hors de la grammaire", lib)
	}
	for _, t := range TableDocType {
		if t == lib {
			return Keccak256([]byte(lib)), nil
		}
	}
	return nil, echec("RG-3", "libellé %q absent de la table de EX-6.5", lib)
}

// RG3Valeur : docType → libellé de la table.
func RG3Valeur(dt []byte) (string, *Echec) {
	if estNul(dt) {
		return "", echec("RG-3", "docType nul (EX-6.6)")
	}
	for _, t := range TableDocType {
		if bytes.Equal(Keccak256([]byte(t)), dt) {
			return t, nil
		}
	}
	return "", echec("RG-3", "valeur hors de la table de EX-6.5")
}

// RG4 : empreinte d'ancre (6.5, EX-6.7).
func RG4(org, jou, ph []byte) ([]byte, []byte, *Echec) {
	if estNul(org) || estNul(jou) || estNul(ph) {
		return nil, nil, echec("RG-4", "org_id, journal_id ou periodHash nul")
	}
	pre := concat(org, jou, ph)
	fp := Keccak256(pre)
	if estNul(fp) {
		return nil, nil, echec("RG-4", "empreinte nulle")
	}
	return pre, fp, nil
}

// Precedente est la période précédente du journal, si connue.
type Precedente struct {
	PeriodEnd, LastSeq *big.Int
}

// RG5 : champs d'une clôture (EX-6.8).
func RG5(m MetaPeriode, prec *Precedente, slug, nomJournal string) *Echec {
	if estNul(m.OrgID) || estNul(m.JournalID) || estNul(m.PeriodHash) {
		return echec("RG-5", "orgId, journalId ou periodHash nul")
	}
	if !(m.PeriodStart.Cmp(m.PeriodEnd) < 0 && m.PeriodEnd.Cmp(deuxAMoins64) < 0) {
		return echec("RG-5", "periodStart < periodEnd < 2^64 − 1 non vérifié")
	}
	if m.LastSeq.Cmp(deuxAMoins64) >= 0 {
		return echec("RG-5", "lastSeq ≥ 2^64 − 1")
	}
	vide := new(big.Int).Add(m.LastSeq, big.NewInt(1)).Cmp(m.FirstSeq) == 0
	if vide {
		if !estNul(m.Root) {
			return echec("RG-5", "période vide à racine non nulle")
		}
	} else {
		if m.FirstSeq.Cmp(m.LastSeq) > 0 {
			return echec("RG-5", "firstSeq > lastSeq hors période vide")
		}
		if estNul(m.Root) {
			return echec("RG-5", "période non vide à racine nulle")
		}
	}
	if m.Version.Sign() < 0 || m.Version.BitLen() > 32 {
		return echec("RG-5", "version hors de uint32")
	}
	if len(m.URI) > 64 {
		return echec("RG-5", "uri de %d octets > 64", len(m.URI))
	}
	for i := 0; i < len(m.URI); i++ {
		if m.URI[i] < 0x20 || m.URI[i] > 0x7e {
			return echec("RG-5", "uri : octet 0x%02x non imprimable", m.URI[i])
		}
	}
	if slug != "" && strings.Contains(m.URI, slug) {
		return echec("RG-5", "uri contient le slug %q", slug)
	}
	if nomJournal != "" && strings.Contains(m.URI, nomJournal) {
		return echec("RG-5", "uri contient le nom du journal %q", nomJournal)
	}
	if prec != nil {
		if m.PeriodStart.Cmp(prec.PeriodEnd) != 0 {
			return echec("RG-5", "periodStart %s différent du periodEnd précédent %s", m.PeriodStart, prec.PeriodEnd)
		}
		if new(big.Int).Add(prec.LastSeq, big.NewInt(1)).Cmp(m.FirstSeq) != 0 {
			return echec("RG-5", "firstSeq %s différent du lastSeq précédent + 1", m.FirstSeq)
		}
	}
	return nil
}

// Étiquettes des condensés internes (6.6.2).
var (
	EtiqPeriode    = []byte("noortrace-periode")
	EtiqInscrit    = []byte("noortrace-enregistreur-inscrit")
	EtiqRevoque    = []byte("noortrace-enregistreur-revoque")
	EtiqAncre      = []byte("noor-attestation-ancre")
	EtiqRevoqueAtt = []byte("noor-attestation-revoque")
)

// OpsCuratorSet est la table des opérations d'un CuratorSet (6.6.2).
var OpsCuratorSet = []string{"CuratorSet.addCurator", "CuratorSet.removeCurator", "CuratorSet.setThreshold", "CuratorSet.proposeAdmin", "CuratorSet.acceptAdmin"}

// PreimagePeriode : u256(chainid) ‖ a20(PeriodRegistry) ‖ "noortrace-periode"
// ‖ keccak256(E(meta)).
func PreimagePeriode(chain *big.Int, contrat []byte, m MetaPeriode) []byte {
	return concat(u256(chain), contrat, EtiqPeriode, Keccak256(EMeta(m)))
}

// PreimageInscription (RG-7).
func PreimageInscription(chain *big.Int, contrat, org, jou, ck, ed []byte) ([]byte, *Echec) {
	if estNul(org) || estNul(jou) || estNul(ck) || estNul(ed) {
		return nil, echec("RG-7", "orgId, journalId, chainKey ou ed25519PubKey nul")
	}
	return concat(u256(chain), contrat, EtiqInscrit, org, jou, ck, ed), nil
}

// PreimageRevocation (RG-8).
func PreimageRevocation(chain *big.Int, contrat, org, ck []byte, reg *big.Int) ([]byte, *Echec) {
	if reg.Sign() == 0 {
		return nil, echec("RG-8", "registeredAt nul : révocation avant l'inscription")
	}
	if reg.BitLen() > 64 {
		return nil, echec("RG-8", "registeredAt hors de uint64")
	}
	return concat(u256(chain), contrat, EtiqRevoque, org, ck, u64be(reg.Uint64())), nil
}

// PreimageAncre (RG-9).
func PreimageAncre(chain *big.Int, contrat, fp, dt []byte) []byte {
	return concat(u256(chain), contrat, EtiqAncre, fp, dt)
}

// PreimageRevocationAncre (RG-10).
func PreimageRevocationAncre(chain *big.Int, contrat, fp []byte) []byte {
	return concat(u256(chain), contrat, EtiqRevoqueAtt, fp)
}

// PreimageAdmin (RG-11).
func PreimageAdmin(chain *big.Int, contrat []byte, op string, arg []byte, nonce *big.Int) ([]byte, *Echec) {
	connu := false
	for _, o := range OpsCuratorSet {
		connu = connu || o == op
	}
	if !connu {
		return nil, echec("RG-11", "opération %q absente de la table de 6.6.2", op)
	}
	return concat(u256(chain), contrat, Keccak256([]byte(op)), arg, u256(nonce)), nil
}

// RG12 vérifie une signature sur un condensé interne et rend le hachage
// signé et l'adresse recouvrée.
func RG12(condense []byte, s SignatureEVM, signer string, eipDeclare []byte) ([]byte, string, *Echec) {
	h := HachageSigne(condense)
	if eipDeclare != nil && !bytes.Equal(eipDeclare, h) {
		return h, "", echec("RG-12", "hachage signé déclaré %s au lieu de %s", Hex0x(eipDeclare), Hex0x(h))
	}
	if !s.Canonique() {
		return h, "", echec("RG-12", "signature non canonique (v %d, r ou s hors bornes, ou s haut)", s.V)
	}
	adr, err := s.Recouvrir(h)
	if err != nil {
		return h, "", echec("RG-12", "recouvrement impossible : %v", err)
	}
	if adr != signer {
		return h, adr, echec("RG-12", "adresse recouvrée %s au lieu du signataire déclaré %s", adr, signer)
	}
	return h, adr, nil
}

// RG13 vérifie un jeu de signatures au seuil (EX-6.16).
func RG13(signataires []string, membres []string, seuil int) *Echec {
	if len(signataires) != seuil {
		return echec("RG-13", "%d signatures au lieu d'exactement t = %d", len(signataires), seuil)
	}
	vus := map[string]bool{}
	for _, s := range signataires {
		if vus[s] {
			return echec("RG-13", "signataire %s en double", s)
		}
		vus[s] = true
	}
	if membres != nil {
		m := map[string]bool{}
		for _, x := range membres {
			m[x] = true
		}
		for _, s := range signataires {
			if !m[s] {
				return echec("RG-13", "signataire %s hors du jeu", s)
			}
		}
	}
	if !sort.StringsAreSorted(signataires) {
		return echec("RG-13", "signatures non rangées par adresse croissante")
	}
	return nil
}
