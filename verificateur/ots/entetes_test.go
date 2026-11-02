package ots

// Lecture de la chaîne d'en-têtes (EX-10.9) : SetCompact, GetCompact,
// réajustement (valeurs des tests de Bitcoin Core), travail, et les six
// règles de O-5 en réussite et en échec.

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/noorfinances-eng/noortrace/verificateur/ancres"
	"github.com/noorfinances-eng/noortrace/verificateur/commun"
)

func TestSetCompact(t *testing.T) {
	cas := []struct {
		x        uint32
		valeur   string // hexadécimal
		neg, deb bool
		compact  uint32 // GetCompact(valeur), 0 : non vérifié
	}{
		{0x00000000, "0", false, false, 0},
		{0x00123456, "0", false, false, 0},
		{0x01003456, "0", false, false, 0},
		{0x02000056, "0", false, false, 0},
		{0x03000000, "0", false, false, 0},
		{0x04000000, "0", false, false, 0},
		{0x00923456, "0", false, false, 0},
		{0x01803456, "0", false, false, 0},
		{0x02800056, "0", false, false, 0},
		{0x03800000, "0", false, false, 0},
		{0x04800000, "0", false, false, 0},
		{0x01123456, "12", false, false, 0x01120000},
		{0x01fedcba, "7e", true, false, 0},
		{0x02123456, "1234", false, false, 0x02123400},
		{0x03123456, "123456", false, false, 0x03123456},
		{0x04123456, "12345600", false, false, 0x04123456},
		{0x04923456, "12345600", true, false, 0},
		{0x05009234, "92340000", false, false, 0x05009234},
		{0x20123456, "1234560000000000000000000000000000000000000000000000000000000000", false, false, 0x20123456},
		{0x207fffff, "7fffff0000000000000000000000000000000000000000000000000000000000", false, false, 0x207fffff},
		{0x1d00ffff, "ffff0000000000000000000000000000000000000000000000000000", false, false, 0x1d00ffff},
		{0xff123456, "", false, true, 0},
		{0x23000001, "", false, true, 0},
		{0x22000001, "", false, false, 0},
		{0x22000100, "", false, true, 0},
		{0x21000100, "", false, false, 0},
		{0x21010000, "", false, true, 0},
	}
	for _, c := range cas {
		n, neg, deb := SetCompact(c.x)
		if neg != c.neg || deb != c.deb {
			t.Errorf("SetCompact(%#x) : négatif %v, débordement %v", c.x, neg, deb)
		}
		if c.valeur != "" && n.Text(16) != c.valeur {
			t.Errorf("SetCompact(%#x) = %s, %s attendu", c.x, n.Text(16), c.valeur)
		}
		if c.compact != 0 {
			if g := GetCompact(n); g != c.compact {
				t.Errorf("GetCompact(SetCompact(%#x)) = %#x, %#x attendu", c.x, g, c.compact)
			}
		}
	}
	if g := GetCompact(big.NewInt(0x80)); g != 0x02008000 {
		t.Errorf("GetCompact(0x80) = %#x", g)
	}
}

func TestTravail(t *testing.T) {
	if g := travail(cibleDe(0x1d00ffff)).String(); g != "4295032833" {
		t.Errorf("travail de difficulté 1 : %s", g)
	}
	if g := travail(cibleDe(NBitsRegtest)).String(); g != "2" {
		t.Errorf("travail regtest : %s", g)
	}
	if LimitePuissance("testnet") != nil {
		t.Error("réseau inconnu accepté")
	}
}

// chaineFictive : en-têtes sans preuve de travail, seuls nTime et nBits
// comptent (réajustement du réseau principal).
func chaineFictive(debut uint64, n int, f func(i uint64) (uint32, uint32)) *chaine {
	c := &chaine{reseau: ReseauPrincipal, s: debut, t: debut + uint64(n) - 1, h: make([][80]byte, n)}
	for k := range c.h {
		tm, nb := f(debut + uint64(k))
		h := &c.h[k]
		h[68], h[69], h[70], h[71] = byte(tm), byte(tm>>8), byte(tm>>16), byte(tm>>24)
		h[72], h[73], h[74], h[75] = byte(nb), byte(nb>>8), byte(nb>>16), byte(nb>>24)
	}
	return c
}

// TestReajustement : les quatre cas de src/test/pow_tests.cpp de Bitcoin
// Core (R2-F49), recalculés indépendamment.
func TestReajustement(t *testing.T) {
	cas := []struct {
		hauteur        uint64 // i, hauteur du bloc réajusté
		premier, avant uint32 // nTime(i − 2016), nTime(i − 1)
		nbits, attendu uint32
	}{
		{32256, 1261130161, 1262152739, 0x1d00ffff, 0x1d00d86a},
		{2016, 1231006505, 1233061996, 0x1d00ffff, 0x1d00ffff},
		{68544, 1279008237, 1279297671, 0x1c05a3f4, 0x1c0168fd},
		{48384, 1263163443, 1269211443, 0x1c387f6f, 0x1d00e1fd},
	}
	limite := LimitePuissance(ReseauPrincipal)
	for _, x := range cas {
		c := chaineFictive(x.hauteur-IntervalleAjustement, IntervalleAjustement+1, func(i uint64) (uint32, uint32) {
			switch i {
			case x.hauteur - IntervalleAjustement:
				return x.premier, x.nbits
			case x.hauteur - 1:
				return x.avant, x.nbits
			case x.hauteur:
				return x.avant + 600, x.attendu
			}
			return x.premier, x.nbits
		})
		if g, ok := reajustement(c, x.hauteur, limite); !ok || g != x.attendu {
			t.Errorf("réajustement à %d : %#x, %#x attendu", x.hauteur, g, x.attendu)
		}
		if e, na := difficulte(c, x.hauteur, ReseauPrincipal, limite); e != nil || na != nil {
			t.Errorf("règle 5 à %d : %+v %+v", x.hauteur, e, na)
		}
		// Hors réajustement : nBits égal au précédent.
		if e, _ := difficulte(c, x.hauteur-1, ReseauPrincipal, limite); e != nil {
			t.Errorf("règle 5 à %d : %+v", x.hauteur-1, e)
		}
		// nBits faux au réajustement.
		c.h[len(c.h)-1][72] ^= 1
		if e, _ := difficulte(c, x.hauteur, ReseauPrincipal, limite); e == nil || !strings.Contains(e.Detail.Fr, "attendu par le réajustement") {
			t.Errorf("règle 5 à %d : échec attendu", x.hauteur)
		}
	}
	// nBits qui change hors réajustement.
	c := chaineFictive(100, 3, func(i uint64) (uint32, uint32) {
		if i == 102 {
			return 0, 0x1d00fffe
		}
		return 0, 0x1d00ffff
	})
	if e, _ := difficulte(c, 102, ReseauPrincipal, limite); e == nil || !strings.Contains(e.Detail.Fr, "hors réajustement") {
		t.Errorf("règle 5 : échec attendu, %+v", e)
	}
	// Réajustement dont l'en-tête i − 2016 manque : non applicable.
	c = chaineFictive(2000, 20, func(i uint64) (uint32, uint32) { return 0, 0x1d00ffff })
	if e, na := difficulte(c, 2016, ReseauPrincipal, limite); e != nil || na == nil || na.Raison != commun.AncreAbsente {
		t.Errorf("règle 5 : non applicable attendue, %+v %+v", e, na)
	}
	// Cible précédente invalide.
	c = chaineFictive(0, IntervalleAjustement+1, func(i uint64) (uint32, uint32) { return 0, 0x01fedcba })
	if e, _ := difficulte(c, IntervalleAjustement, ReseauPrincipal, limite); e == nil {
		t.Error("règle 5 : cible précédente négative acceptée")
	}
	// regtest.
	c.reseau = ReseauRegtest
	if e, _ := difficulte(c, 5, ReseauRegtest, LimitePuissance(ReseauRegtest)); e == nil || !strings.Contains(e.Detail.Fr, "0x207fffff attendu") {
		t.Errorf("règle 5 regtest : %+v", e)
	}
}

// enteteReel : en-tête du bloc 358391 du réseau principal (CT-6 §10.3,
// R2-F30).
const enteteReel = "02000000b96394585a281b7e5f438fd1c9ed492645a1fd61cb3802040000000000000000007ee445d23ad061af4a36b809501fab1ac4f2d7e7a739817dd0cbb7ec661b8a1e376755f58616186272def6"

func entetesReels(t *testing.T) *ancres.Entetes {
	t.Helper()
	b, err := hex.DecodeString(enteteReel)
	if err != nil {
		t.Fatal(err)
	}
	var h [80]byte
	copy(h[:], b)
	return &ancres.Entetes{Reseau: ReseauPrincipal, Debut: 358391, Entetes: [][80]byte{h}}
}

func TestEnteteReel(t *testing.T) {
	c := nouvelleChaine(entetesReels(t))
	h := c.hachageAffiche(358391)
	if g := hex.EncodeToString(h[:]); g != "000000000000000003e892881a8cdcdc117c06d444057c98b6f04a9ee75a2319" {
		t.Errorf("hachage affiché %s", g)
	}
	cible, motif := cibleValable(c.nBits(358391), LimitePuissance(ReseauPrincipal))
	if cible == nil || !satisfait(c.H(358391), cible) {
		t.Errorf("preuve de travail du bloc réel refusée (%s)", motif)
	}
	if c.nTime(358391) != 1432827678 || c.nBits(358391) != 0x181686f5 {
		t.Errorf("nTime %d, nBits %#x", c.nTime(358391), c.nBits(358391))
	}
	if g := hex.EncodeToString(c.racine(358391)); g != "007ee445d23ad061af4a36b809501fab1ac4f2d7e7a739817dd0cbb7ec661b8a" {
		t.Errorf("racine %s", g)
	}
	// Point de contrôle au bloc lui-même : t = c, règles 4 à 6 vides.
	a := &ancres.Bitcoin{Reseau: ReseauPrincipal, Hauteur: 358391, Hachage: h, MinConfirmations: 1}
	if r := verifierChaine(c, a); r.Statut != commun.Reussi || !strings.Contains(r.Detail.Fr, "aucun travail recalculé") {
		t.Errorf("O-5 : %+v", r)
	}
	// Point de contrôle sous le bloc réel : la règle 4 s'applique au bloc et
	// réussit, la règle 6 n'a pas de fenêtre, la règle 5 vaut nBits(c).
	e := entetesReels(t)
	var ancetre [80]byte
	copy(ancetre[:], e.Entetes[0][:])
	ancetre[72], ancetre[73], ancetre[74], ancetre[75] = 0xf5, 0x86, 0x16, 0x18
	ancetre[0] ^= 1 // en-tête fictif : seul son hachage compte pour la règle 2
	e2 := &ancres.Entetes{Reseau: ReseauPrincipal, Debut: 358390, Entetes: [][80]byte{ancetre, e.Entetes[0]}}
	c2 := nouvelleChaine(e2)
	a2 := &ancres.Bitcoin{Reseau: ReseauPrincipal, Hauteur: 358390, Hachage: c2.hachageAffiche(358390), MinConfirmations: 1}
	if r := verifierChaine(c2, a2); r.Statut != commun.Echoue || !strings.Contains(r.Detail.Fr, "règle 2") {
		t.Errorf("O-5 : chaînage rompu attendu, %+v", r)
	}
}

// TestRegles : les six règles d'EX-10.9 sur des chaînes regtest minées.
func TestRegles(t *testing.T) {
	nominal := nouveauScenario(t, nil)
	c := nouvelleChaine(nominal.entetes)
	if r := verifierChaine(c, nominal.ancre); r.Statut != commun.Reussi {
		t.Fatalf("O-5 nominale : %+v", r)
	}
	verifier := func(nom string, e *ancres.Entetes, a *ancres.Bitcoin, statut commun.Statut, raison commun.Raison, motif string) {
		t.Helper()
		r := verifierChaine(nouvelleChaine(e), a)
		if r.Statut != statut || r.Raison != raison || !strings.Contains(r.Detail.Fr, motif) || r.Detail.En == "" {
			t.Errorf("%s : %s %s %q", nom, r.Statut, r.Raison, r.Detail.Fr)
		}
	}
	a := *nominal.ancre
	// Règle 1 : autre réseau.
	am := a
	am.Reseau = ReseauPrincipal
	verifier("règle 1", nominal.entetes, &am, commun.Echoue, "", "règle 1")
	// Règle 2 : hashPrevBlock faux sous le point de contrôle.
	casse := [32]byte{1}
	e := nouveauScenario(t, func(i uint64, s *specEntete) {
		if i == 995 {
			s.prev = &casse
		}
	}).entetes
	verifier("règle 2", e, &a, commun.Echoue, "", "règle 2")
	// Règle 3 : point de contrôle au-dessus et au-dessous du fichier, hachage
	// différent.
	ah := a
	ah.Hauteur = 1021
	verifier("règle 3 haut", nominal.entetes, &ah, commun.NonExecute, commun.AncreAbsente, "règle 3")
	ah.Hauteur = 989
	verifier("règle 3 bas", nominal.entetes, &ah, commun.NonExecute, commun.AncreAbsente, "règle 3")
	ah = a
	ah.Hachage[5] ^= 1
	verifier("règle 3 hachage", nominal.entetes, &ah, commun.Echoue, "", "règle 3")
	// Règle 2 prévaut sur la règle 3 non applicable.
	ah.Hauteur = 1021
	verifier("règle 2 avant 3", e, &ah, commun.Echoue, "", "règle 2")
	// Règle 4 : travail absent au-dessus du point de contrôle ; travail
	// absent sous le point de contrôle (non contrôlé, règle 2 seule).
	e = nouveauScenario(t, func(i uint64, s *specEntete) { s.sansTravail = i == 1010 }).entetes
	ae := a
	ae.Hachage = nouvelleChaine(e).hachageAffiche(1000)
	verifier("règle 4", e, &ae, commun.Echoue, "", "preuve de travail absente")
	e = nouveauScenario(t, func(i uint64, s *specEntete) { s.sansTravail = i == 995 }).entetes
	ae.Hachage = nouvelleChaine(e).hachageAffiche(1000)
	verifier("règle 4 sous c", e, &ae, commun.Reussi, "", "rattachés")
	// Règle 4 : cible au-delà de powLimit (regtest), cible nulle.
	for _, x := range []struct {
		nbits uint32
		motif string
	}{{0x2100ffff, "supérieure à powLimit"}, {0x03000000, "nulle"}, {0x04923456, "négative"}, {0xff123456, "en débordement"}} {
		e = &ancres.Entetes{Reseau: ReseauRegtest, Debut: 1000, Entetes: [][80]byte{nominal.entetes.Entetes[10], nominal.entetes.Entetes[11]}}
		e.Entetes[1][72], e.Entetes[1][73], e.Entetes[1][74], e.Entetes[1][75] = byte(x.nbits), byte(x.nbits>>8), byte(x.nbits>>16), byte(x.nbits>>24)
		verifier("règle 4 "+x.motif, e, &a, commun.Echoue, "", x.motif)
	}
	// Règle 5 : nBits regtest différent de 0x207fffff, cible valable.
	e = nouveauScenario(t, func(i uint64, s *specEntete) {
		if i == 1005 {
			s.nBits = 0x1f7fffff
		}
	}).entetes
	ae.Hachage = nouvelleChaine(e).hachageAffiche(1000)
	verifier("règle 5", e, &ae, commun.Echoue, "", "0x207fffff attendu")
	// Règle 6 : heure non supérieure à la médiane des onze précédentes.
	e = nouveauScenario(t, func(i uint64, s *specEntete) {
		if i == 1015 {
			s.nTime = 1793880000 + (1009-990)*600
		}
	}).entetes
	ae.Hachage = nouvelleChaine(e).hachageAffiche(1000)
	verifier("règle 6", e, &ae, commun.Echoue, "", "règle 6")
	// Règle 6 : égalité stricte refusée, un de plus admis.
	e = nouveauScenario(t, func(i uint64, s *specEntete) {
		if i == 1015 {
			s.nTime = 1793880000 + (1009-990)*600 + 1
		}
	}).entetes
	ae.Hachage = nouvelleChaine(e).hachageAffiche(1000)
	verifier("règle 6 limite", e, &ae, commun.Reussi, "", "rattachés")
	// Règle 6 sous le point de contrôle : non contrôlée.
	e = nouveauScenario(t, func(i uint64, s *specEntete) {
		if i == 1002 {
			s.nTime = 1
		}
	}).entetes
	ae.Hauteur = 1005
	ae.Hachage = nouvelleChaine(e).hachageAffiche(1005)
	verifier("règle 6 sous c", e, &ae, commun.Reussi, "", "rattachés")
}

func TestMediane(t *testing.T) {
	c := chaineFictive(0, 11, func(i uint64) (uint32, uint32) { return []uint32{9, 1, 8, 2, 7, 3, 6, 4, 5, 10, 0}[i], 0 })
	if m := c.mediane(0); m != 5 {
		t.Errorf("médiane %d", m)
	}
	// Travail cumulé : de max(h, c + 1) à t.
	r := chaineFictive(10, 5, func(i uint64) (uint32, uint32) { return 0, NBitsRegtest })
	if g := travailCumule(r, 11, 12).String(); g != "4" {
		t.Errorf("travail %s", g)
	}
	if g := travailCumule(r, 13, 10).String(); g != "4" {
		t.Errorf("travail %s", g)
	}
	if g := travailCumule(r, 14, 14).String(); g != "0" {
		t.Errorf("travail %s", g)
	}
}
