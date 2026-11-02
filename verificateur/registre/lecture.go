package registre

// Lecture des parties du contrôle 8 : registre.json et certificat-commit.json
// (R-1, EX-11.10), validateurs.json (R-3, EX-11.12). Chaque partie est lue
// par le lecteur JSON strict et borné (jsonv, profondeur 128), validée contre
// son schéma embarqué, puis convertie en valeurs typées ; les bornes de
// §15.1 sont celles du schéma (17 entrées, 256 reçus, 256 journaux, 4 sujets,
// 16 certificats, 128 lignes de precommit), plus la longueur d'une ligne en
// octets (4 Mio).

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/noorfinances-eng/noortrace/verificateur/ancres"
	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/cryptographie"
	"github.com/noorfinances-eng/noortrace/verificateur/jcs"
	"github.com/noorfinances-eng/noortrace/verificateur/jsonv"
	"github.com/noorfinances-eng/noortrace/verificateur/schema"
)

// Rôles des entrées de registre.json (11.2.1, EX-11.23).
const (
	roleCloture     = "cloture"
	roleAncre       = "ancre"
	roleInscription = "inscription"
	rolePoint       = "ancre_point_de_controle"
)

// longueurLigneMax : longueur d'une ligne de certificat, en octets (§15.1).
const longueurLigneMax = 4 << 20

// journal : un journal d'événement d'un reçu.
type journal struct {
	adresse [20]byte
	sujets  [][32]byte
	donnees []byte
}

// recu : un reçu, réduit aux champs que l'encodage de consensus engage.
type recu struct {
	genre    byte // type, de 0 à 4
	statut   byte // 0 ou 1
	cumul    uint64
	journaux []journal
}

// entete : les dix champs de l'en-tête que la préimage de EX-11.4 engage.
type entete struct {
	numero       uint64
	hachage      [32]byte
	hachageTexte string
	parent       [32]byte
	etat         [32]byte
	transactions [32]byte
	recus        [32]byte
	horodatage   uint64
	gazUtilise   uint64
	gazLimite    uint64
	baseFee      [32]byte
}

// entreeRegistre : une entrée de registre.json.
type entreeRegistre struct {
	role          string
	bloc          entete
	recus         []recu
	indiceTx      int
	indiceJournal int
	hachageTx     string
	// cert : indice du certificat de même hauteur (R-1).
	cert int
}

// journalProuve rend receipts[transaction_index].logs[log_index] (EX-11.9) ;
// R-1 a vérifié que les indices désignent un journal.
func (e *entreeRegistre) journalProuve() *journal {
	if e.indiceTx < 0 || e.indiceTx >= len(e.recus) {
		return nil
	}
	r := &e.recus[e.indiceTx]
	if e.indiceJournal < 0 || e.indiceJournal >= len(r.journaux) {
		return nil
	}
	return &r.journaux[e.indiceJournal]
}

// certificat : les seuls champs d'un certificat que lit EX-11.3.
type certificat struct {
	hauteur     uint64
	tour        uint64
	chainID     string
	valset      [32]byte
	bloc        [32]byte
	proposition string
	precommits  []string
}

func texte(fr, en string) commun.Texte { return commun.T(fr, en) }

// quantite lit une quantité JSON-RPC de 64 bits (« 0x » et hexadécimal
// minuscule sans zéro de tête, déjà contrôlés par le schéma).
func quantite(s string) (uint64, bool) {
	if !strings.HasPrefix(s, "0x") || len(s) < 3 {
		return 0, false
	}
	n, err := strconv.ParseUint(s[2:], 16, 64)
	return n, err == nil
}

// quantite256 lit une quantité de 256 bits et la rend sur 32 octets
// grand-boutistes complétés à gauche par des zéros (baseFeePerGas, EX-11.4).
func quantite256(s string) ([32]byte, bool) {
	var b [32]byte
	if !strings.HasPrefix(s, "0x") || len(s) < 3 || len(s) > 66 {
		return b, false
	}
	n, ok := new(big.Int).SetString(s[2:], 16)
	if !ok || n.Sign() < 0 || n.BitLen() > 256 {
		return b, false
	}
	n.FillBytes(b[:])
	return b, true
}

func hex32(s string) ([32]byte, bool) {
	var h [32]byte
	b, ok := cryptographie.LireHex(s, 32)
	if !ok {
		return h, false
	}
	copy(h[:], b)
	return h, true
}

func adresse(s string) ([20]byte, bool) {
	var a [20]byte
	b, ok := cryptographie.LireHex(s, 20)
	if !ok {
		return a, false
	}
	copy(a[:], b)
	return a, true
}

// analyser lit un document JSON borné et le valide contre un schéma.
func analyser(octets []byte, uri, nom string) (*jsonv.Valeur, *commun.Texte) {
	v, err := jsonv.Analyser(octets)
	if err != nil {
		t := texte(nom+" n'est pas du JSON exploitable ("+err.Error()+")", nom+" is not usable JSON ("+err.Error()+")")
		return nil, &t
	}
	if !v.EstObjet() {
		t := texte(nom+" n'est pas un objet JSON", nom+" is not a JSON object")
		return nil, &t
	}
	// Forme canonique exigée (« Lectures », point 9) : une clé en double ou
	// un nombre non entier rendrait la lecture ambiguë ; la partie est
	// refusée comme une partie contraire à son schéma (R-1 ou R-3).
	if err := jcs.Calculable(v); err != nil {
		m := err.Error()
		if e, ok := err.(*jcs.Erreur); ok {
			m = e.Motif
		}
		t := texte(nom+" sans forme canonique ("+m+")", nom+" without canonical form ("+m+")")
		return nil, &t
	}
	if err := schema.Valider(uri, v); err != nil {
		t := texte(nom+" contraire à son schéma ("+err.Error()+")", nom+" does not follow its schema ("+err.Error()+")")
		return nil, &t
	}
	return v, nil
}

// lireRegistre lit registre.json (schéma registre-v0).
func lireRegistre(octets []byte) ([]entreeRegistre, *commun.Texte) {
	v, d := analyser(octets, schema.Registre, "registre.json")
	if d != nil {
		return nil, d
	}
	defaut := func(i int, champ string) *commun.Texte {
		t := texte(fmt.Sprintf("registre.json : entrée %d, %s illisible", i, champ), fmt.Sprintf("registre.json: entry %d, unreadable %s", i, champ))
		return &t
	}
	var out []entreeRegistre
	for i, e := range v.Membre("entries").Elements {
		var x entreeRegistre
		x.role = e.Membre("role").S()
		b := e.Membre("block")
		var ok bool
		if x.bloc.numero, ok = quantite(b.Membre("number").S()); !ok {
			return nil, defaut(i, "block.number")
		}
		x.bloc.hachageTexte = b.Membre("hash").S()
		champs32 := []struct {
			nom string
			dst *[32]byte
		}{{"hash", &x.bloc.hachage}, {"parentHash", &x.bloc.parent}, {"stateRoot", &x.bloc.etat}, {"transactionsRoot", &x.bloc.transactions}, {"receiptsRoot", &x.bloc.recus}}
		for _, c := range champs32 {
			if *c.dst, ok = hex32(b.Membre(c.nom).S()); !ok {
				return nil, defaut(i, "block."+c.nom)
			}
		}
		champs64 := []struct {
			nom string
			dst *uint64
		}{{"timestamp", &x.bloc.horodatage}, {"gasUsed", &x.bloc.gazUtilise}, {"gasLimit", &x.bloc.gazLimite}}
		for _, c := range champs64 {
			if *c.dst, ok = quantite(b.Membre(c.nom).S()); !ok {
				return nil, defaut(i, "block."+c.nom)
			}
		}
		if x.bloc.baseFee, ok = quantite256(b.Membre("baseFeePerGas").S()); !ok {
			return nil, defaut(i, "block.baseFeePerGas")
		}
		for k, r := range e.Membre("receipts").Elements {
			var rc recu
			t, ok1 := quantite(r.Membre("type").S())
			s, ok2 := quantite(r.Membre("status").S())
			c, ok3 := quantite(r.Membre("cumulativeGasUsed").S())
			if !ok1 || !ok2 || !ok3 || t > 4 || s > 1 {
				return nil, defaut(i, fmt.Sprintf("receipts[%d]", k))
			}
			rc.genre, rc.statut, rc.cumul = byte(t), byte(s), c
			for l, j := range r.Membre("logs").Elements {
				var jn journal
				if jn.adresse, ok = adresse(j.Membre("address").S()); !ok {
					return nil, defaut(i, fmt.Sprintf("receipts[%d].logs[%d].address", k, l))
				}
				for _, s := range j.Membre("topics").Elements {
					h, ok := hex32(s.S())
					if !ok {
						return nil, defaut(i, fmt.Sprintf("receipts[%d].logs[%d].topics", k, l))
					}
					jn.sujets = append(jn.sujets, h)
				}
				if jn.donnees, ok = cryptographie.LireHex(j.Membre("data").S(), -1); !ok {
					return nil, defaut(i, fmt.Sprintf("receipts[%d].logs[%d].data", k, l))
				}
				rc.journaux = append(rc.journaux, jn)
			}
			x.recus = append(x.recus, rc)
		}
		ti, ok1 := e.Membre("transaction_index").Entier()
		li, ok2 := e.Membre("log_index").Entier()
		if !ok1 || !ok2 {
			return nil, defaut(i, "transaction_index ou log_index")
		}
		x.indiceTx, x.indiceJournal = int(ti), int(li)
		x.hachageTx = e.Membre("transaction_hash").S()
		out = append(out, x)
	}
	return out, nil
}

// lireCertificats lit certificat-commit.json (schéma
// registre-v0#/$defs/certificat_commit) ; seuls les champs d'EX-11.3 sont lus.
func lireCertificats(octets []byte) ([]certificat, *commun.Texte) {
	v, d := analyser(octets, schema.Registre+"#/$defs/certificat_commit", "certificat-commit.json")
	if d != nil {
		return nil, d
	}
	var out []certificat
	for i, c := range v.Membre("certificates").Elements {
		var x certificat
		var ok1, ok2, ok3, ok4 bool
		x.hauteur, ok1 = quantite(c.Membre("height").S())
		x.tour, ok2 = quantite(c.Membre("round").S())
		x.valset, ok3 = hex32(c.Membre("valsetHash").S())
		x.bloc, ok4 = hex32(c.Membre("blockHash").S())
		if !(ok1 && ok2 && ok3 && ok4) {
			t := texte(fmt.Sprintf("certificat-commit.json : certificat %d illisible", i), fmt.Sprintf("certificat-commit.json: certificate %d unreadable", i))
			return nil, &t
		}
		x.chainID = c.Membre("chainId").S()
		x.proposition = c.Chemin("proposal", "line").S()
		lignes := []string{x.proposition}
		for _, p := range c.Membre("precommits").Elements {
			x.precommits = append(x.precommits, p.Membre("line").S())
			lignes = append(lignes, p.Membre("line").S())
		}
		for _, l := range lignes {
			if len(l) > longueurLigneMax {
				t := texte(fmt.Sprintf("certificat-commit.json : certificat %d, ligne de plus de 4 Mio (§15.1)", i), fmt.Sprintf("certificat-commit.json: certificate %d, line longer than 4 MiB (§15.1)", i))
				return nil, &t
			}
		}
		out = append(out, x)
	}
	return out, nil
}

// lireValidateurs lit validateurs.json (schéma validateurs-v0) et charge
// chaque jeu comme le nœud le charge (ancres.LireJeu, EX-12.2).
func lireValidateurs(octets []byte) ([]ancres.JeuValidateurs, *commun.Texte) {
	v, d := analyser(octets, schema.Validateurs, "validateurs.json")
	if d != nil {
		return nil, d
	}
	var jeux []ancres.JeuValidateurs
	for i, j := range v.Membre("sets").Elements {
		jeu, d := ancres.LireJeu(j, fmt.Sprintf("validateurs.json/sets/%d", i))
		if d != nil {
			return nil, d
		}
		jeux = append(jeux, jeu)
	}
	return jeux, nil
}

// apparier applique la fin d'EX-11.10 : chaque hauteur d'entrée a exactement
// un certificat de même height, chaque certificat sert au moins une entrée,
// transaction_index désigne un reçu et log_index un journal de ce reçu.
func apparier(entrees []entreeRegistre, certs []certificat) *commun.Texte {
	parHauteur := map[uint64][]int{}
	for i, c := range certs {
		parHauteur[c.hauteur] = append(parHauteur[c.hauteur], i)
	}
	sert := make([]bool, len(certs))
	for i := range entrees {
		e := &entrees[i]
		l := parHauteur[e.bloc.numero]
		switch len(l) {
		case 0:
			t := texte(fmt.Sprintf("entrée %d (%s, bloc %d) sans certificat de même hauteur", i, e.role, e.bloc.numero), fmt.Sprintf("entry %d (%s, block %d) has no certificate of the same height", i, e.role, e.bloc.numero))
			return &t
		case 1:
			e.cert = l[0]
			sert[l[0]] = true
		default:
			t := texte(fmt.Sprintf("bloc %d : %d certificats de même hauteur", e.bloc.numero, len(l)), fmt.Sprintf("block %d: %d certificates of the same height", e.bloc.numero, len(l)))
			return &t
		}
		if e.journalProuve() == nil {
			t := texte(fmt.Sprintf("entrée %d (%s, bloc %d) : transaction_index %d et log_index %d ne désignent pas un journal", i, e.role, e.bloc.numero, e.indiceTx, e.indiceJournal),
				fmt.Sprintf("entry %d (%s, block %d): transaction_index %d and log_index %d do not designate a log", i, e.role, e.bloc.numero, e.indiceTx, e.indiceJournal))
			return &t
		}
	}
	for i, s := range sert {
		if !s {
			t := texte(fmt.Sprintf("certificat %d (hauteur %d) ne sert aucune entrée", i, certs[i].hauteur), fmt.Sprintf("certificate %d (height %d) serves no entry", i, certs[i].hauteur))
			return &t
		}
	}
	return nil
}
