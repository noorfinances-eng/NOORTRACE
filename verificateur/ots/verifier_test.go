package ots

// Chaque vérification O-1 à O-7 en réussite, en échec et non exécutée,
// statut du contrôle (EX-10.12), faits (EX-10.14), proposition (EX-10.15),
// avertissements (§10.7) et K-9 (EX-10.16), sur des scénarios construits.

import (
	"strings"
	"testing"

	"github.com/noorfinances-eng/noortrace/verificateur/ancres"
	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/cryptographie"
	"github.com/noorfinances-eng/noortrace/verificateur/entree"
)

// attendre compare les sept statuts à une description « O-1 r, O-2 e,
// O-3 n:prerequis_en_echec … » (r : reussi, e : echoue, n:raison).
func attendre(t *testing.T, r Resultat, sept string, statut string) {
	t.Helper()
	parts := strings.Fields(sept)
	if len(parts) != 7 {
		t.Fatalf("description %q", sept)
	}
	for i, p := range parts {
		v := r.Verifications[i]
		g := map[commun.Statut]string{commun.Reussi: "r", commun.Echoue: "e", commun.NonExecute: "n"}[v.Statut]
		if v.Statut == commun.NonExecute {
			g += ":" + string(v.Raison)
		}
		if g != p {
			t.Errorf("%s : %s, %s attendu (%s)", v.ID, g, p, v.Detail.Fr)
		}
	}
	g := map[commun.Statut]string{commun.Reussi: "r", commun.Echoue: "e", commun.NonExecute: "n"}[r.Statut]
	if r.Statut == commun.NonExecute {
		g += ":" + string(r.Raison)
	}
	if g != statut {
		t.Errorf("statut %s, %s attendu", g, statut)
	}
}

func avertissements(r Resultat) string {
	var s []string
	for _, a := range r.Avertissements {
		s = append(s, a.ID+"/"+a.Verification)
	}
	return strings.Join(s, " ")
}

func verifierEtControler(t *testing.T, e Entree) Resultat {
	t.Helper()
	r := Verifier(e)
	verifierForme(t, e, r)
	return r
}

const (
	pre = "n:prerequis_en_echec"
	pa  = "n:partie_absente"
	aa  = "n:ancre_absente"
	hp  = "n:hors_perimetre_version"
)

func TestNominal(t *testing.T) {
	sc := nouveauScenario(t, nil)
	r := verifierEtControler(t, sc.entree())
	attendre(t, r, "r r r r r r r", "r")
	if g := avertissements(r); g != "AV-O-3/O-5" {
		t.Errorf("avertissements %s", g)
	}
	if len(r.AncresEmployees) != 1 || r.AncresEmployees[0] != "/bitcoin" {
		t.Errorf("ancres %v", r.AncresEmployees)
	}
	f := r.Faits
	c := nouvelleChaine(sc.entetes)
	if f.RetainedHeight != 1001 || f.Confirmations != 20 || f.CumulativeWork != "40" || f.Network != "regtest" ||
		f.Checkpoint.Height != 1000 || f.Checkpoint.Hash != cryptographie.Hex32(c.hachageAffiche(1000)) ||
		f.BlockHash != cryptographie.Hex32(c.hachageAffiche(1001)) || f.FileDigest != cryptographie.Hex32(sc.empreinte) {
		t.Errorf("faits %+v", f)
	}
	// nTime(1001) = 1793880000 + 11 × 600 ; médiane de 1002 … 1012 : 1007.
	if f.BlockTime != "2026-11-05T13:50:00Z" || f.MedianBound == nil || *f.MedianBound != "2026-11-05T14:50:00Z" ||
		commun.FormaterInstant(f.BlockTimeInstant) != f.BlockTime {
		t.Errorf("temps %s %v", f.BlockTime, f.MedianBound)
	}
	if len(f.Attestations) != 1 || f.Attestations[0].Kind != "bitcoin" || *f.Attestations[0].Height != 1001 || f.Attestations[0].Status != commun.Reussi {
		t.Errorf("attestations %+v", f.Attestations)
	}
	ph := cryptographie.Hex32(sc.empreinte)
	wfr := "le manifeste d'empreinte " + ph + " existait avant la création du bloc Bitcoin 1001 (" + f.BlockHash +
		", réseau regtest), sous 20 blocs dont le travail se rattache au point de contrôle 1000 du réviseur ; heure inscrite par le mineur : 2026-11-05T13:50:00Z UTC, précision non garantie par le protocole ; borne sous hypothèse : 2026-11-05T14:50:00Z UTC (réseau d'essai, sans valeur probante)"
	wen := "the manifest with digest " + ph + " existed before Bitcoin block 1001 (" + f.BlockHash +
		", regtest network) was created, under 20 blocks whose work connects to the reviewer's checkpoint 1000; time written by the miner: 2026-11-05T13:50:00Z UTC, accuracy not guaranteed by the protocol; bound under assumption: 2026-11-05T14:50:00Z UTC (test network, no evidential value)"
	if r.Proposition.Fr != wfr || r.Proposition.En != wen {
		t.Errorf("proposition\n%s\n%s", r.Proposition.Fr, r.Proposition.En)
	}
	if r.Resume.Fr != "bloc Bitcoin 1001 du réseau regtest, 20 confirmations (réseau d'essai)" ||
		r.Resume.En != "Bitcoin block 1001 on network regtest, 20 confirmations (test network)" {
		t.Errorf("résumé %+v", r.Resume)
	}
}

func TestEtatsDeLecture(t *testing.T) {
	sc := nouveauScenario(t, nil)
	for _, et := range []entree.Etat{entree.Absent, entree.Illisible} {
		e := sc.entree()
		e.Etat, e.Preuve = et, nil
		r := verifierEtControler(t, e)
		attendre(t, r, strings.Repeat(pre+" ", 7), pre)
		if len(r.Avertissements) != 0 || len(r.AncresEmployees) != 0 {
			t.Error("avertissement ou ancre sans preuve")
		}
	}
	e := sc.entree()
	e.Etat = entree.TropGrand
	r := verifierEtControler(t, e)
	attendre(t, r, "e "+strings.Repeat(pre+" ", 6), "e")
	// Lu mais plus grand que la limite (défense) : O-1 échoue.
	e = sc.entree()
	e.Preuve = append(append([]byte{}, sc.preuve...), make([]byte, TailleMax)...)
	attendre(t, verifierEtControler(t, e), "e "+strings.Repeat(pre+" ", 6), "e")
}

func TestO1Echec(t *testing.T) {
	sc := nouveauScenario(t, nil)
	e := sc.entree()
	e.Preuve = append(append([]byte{}, sc.preuve...), 0)
	r := verifierEtControler(t, e)
	attendre(t, r, "e "+strings.Repeat(pre+" ", 6), "e")
	if !strings.Contains(r.Verifications[0].Detail.Fr, "octet(s) après l'arbre") || len(r.Avertissements) != 0 {
		t.Errorf("O-1 : %s ; %s", r.Verifications[0].Detail.Fr, avertissements(r))
	}
}

func TestO2(t *testing.T) {
	sc := nouveauScenario(t, nil)
	e := sc.entree()
	e.EmpreinteAttendue[0] ^= 1
	r := verifierEtControler(t, e)
	attendre(t, r, "r e r r r r r", "e")
	if !strings.Contains(r.Verifications[1].Detail.Fr, "différente du periodHash recalculé") {
		t.Errorf("O-2 : %s", r.Verifications[1].Detail.Fr)
	}
	// periodHash non recalculé (P-1) : O-2 non exécutée, les autres
	// s'exécutent (EX-5.4, EX-10.6).
	e = sc.entree()
	e.EmpreinteDisponible = false
	r = verifierEtControler(t, e)
	attendre(t, r, "r "+pre+" r r r r r", pre)
	if !strings.Contains(r.Verifications[1].Detail.Fr, "P-1") {
		t.Errorf("O-2 : %s", r.Verifications[1].Detail.Fr)
	}
}

func TestO3(t *testing.T) {
	sc := nouveauScenario(t, nil)
	// Branche dont le résultat dépasse 4096 octets, à côté de la branche
	// attestée : O-3 échoue, O-4 et O-6 non exécutées, O-5 et O-7 exécutées.
	e := sc.entree()
	e.Preuve = fichierOTS(sc.empreinte, fourche(), opAp(make([]byte, 4096)), opSHA(), attAttente("u"), opAp(nonceTest), opSHA(), attBitcoin(1001))
	r := verifierEtControler(t, e)
	attendre(t, r, "r r e "+pre+" r "+pre+" r", "e")
	if g := avertissements(r); g != "AV-O-3/O-5 AV-O-2/O-7" {
		t.Errorf("avertissements %s", g)
	}
	// Seule attestation Bitcoin sous une opération hors profil : O-3
	// réussie, O-4 non exécutée (hors_perimetre_version), contrôle idem.
	e.Preuve = fichierOTS(sc.empreinte, []byte{opKeccak256}, attBitcoin(1001))
	r = verifierEtControler(t, e)
	attendre(t, r, "r r r "+hp+" r "+hp+" r", hp)
	if g := avertissements(r); g != "AV-O-2/O-3 AV-O-3/O-5" {
		t.Errorf("avertissements %s", g)
	}
	// Textes imposés par EX-10.12 (révision 0.4) : detail de O-3, summary,
	// aucun fait ni proposition.
	if d := r.Verifications[2].Detail; d.Fr != "attestation sous une opération hors du profil de la version 0 : non vérifiée ; aucune date n'est établie" ||
		d.En != "attestation under an operation outside the version 0 profile: not verified; no time is established" {
		t.Errorf("O-3 : %s / %s", d.Fr, d.En)
	}
	if r.Resume.Fr != "preuve hors du profil de la version 0, non vérifiée : aucune date établie" || r.Faits != nil || !r.Proposition.Vide() {
		t.Errorf("résumé %q, faits %v", r.Resume.Fr, r.Faits)
	}
	// Opération hors profil à côté de la branche attestée : contrôle réussi,
	// attestation hors profil non_execute dans les faits.
	e.Preuve = fichierOTS(sc.empreinte, fourche(), []byte{opReverse}, attAttente("x"), opAp(nonceTest), opSHA(), attBitcoin(1001))
	r = verifierEtControler(t, e)
	attendre(t, r, "r r r r r r r", "r")
	if g := avertissements(r); g != "AV-O-2/O-3 AV-O-3/O-5" {
		t.Errorf("avertissements %s", g)
	}
	if a := r.Faits.Attestations; len(a) != 2 || a[0].Kind != "en_attente" || *a[0].URI != "x" || a[0].Status != commun.NonExecute || a[1].Status != commun.Reussi {
		t.Errorf("attestations %+v", a)
	}
}

func TestO4(t *testing.T) {
	sc := nouveauScenario(t, nil)
	e := sc.entree()
	// Attestation qui désigne un autre bloc : O-4 échoue, O-6 non exécutée.
	e.Preuve = fichierOTS(sc.empreinte, opAp(nonceTest), opSHA(), attBitcoin(1002))
	r := verifierEtControler(t, e)
	attendre(t, r, "r r r e r "+pre+" r", "e")
	// Résultat de 48 octets (sans 08 final) : comparé, ne concorde pas.
	e.Preuve = fichierOTS(sc.empreinte, opAp(make([]byte, 16)), attBitcoin(1001))
	r = verifierEtControler(t, e)
	attendre(t, r, "r r r e r "+pre+" r", "e")
	if !strings.Contains(r.Verifications[3].Detail.Fr, "résultat de 48 octets") {
		t.Errorf("O-4 : %s", r.Verifications[3].Detail.Fr)
	}
	// Hauteur hors du fichier d'en-têtes : non exécutée (ancre_absente).
	e.Preuve = fichierOTS(sc.empreinte, opAp(nonceTest), opSHA(), attBitcoin(1021))
	r = verifierEtControler(t, e)
	attendre(t, r, "r r r "+aa+" r "+aa+" r", aa)
	e.Preuve = fichierOTS(sc.empreinte, opAp(nonceTest), opSHA(), attBitcoin(989))
	attendre(t, verifierEtControler(t, e), "r r r "+aa+" r "+aa+" r", aa)
	// Hors fichier et hors profil : hors_perimetre_version passe avant
	// ancre_absente (EX-6.5).
	e.Preuve = fichierOTS(sc.empreinte, fourche(), []byte{opSHA1}, attBitcoin(1001), attBitcoin(5000))
	r = verifierEtControler(t, e)
	attendre(t, r, "r r r "+hp+" r "+hp+" r", hp)
	// Une attestation du profil existe : pas les textes du hors-profil seul.
	if strings.Contains(r.Verifications[2].Detail.Fr, "aucune date n'est établie") || !r.Resume.Vide() {
		t.Errorf("O-3 : %s ; résumé %q", r.Verifications[2].Detail.Fr, r.Resume.Fr)
	}
	// Deux attestations, l'une concorde : AV-O-1 pour l'autre (EX-10.8),
	// retenue la concordante de plus petite hauteur.
	e.Preuve = fichierOTS(sc.empreinte, opAp(nonceTest), opSHA(), fourche(), attBitcoin(1003), fourche(), attBitcoin(1001), attBitcoin(1021))
	r = verifierEtControler(t, e)
	attendre(t, r, "r r r r r r r", "r")
	if g := avertissements(r); g != "AV-O-1/O-4 AV-O-3/O-5" {
		t.Errorf("avertissements %s", g)
	}
	a := r.Faits.Attestations
	if len(a) != 3 || a[0].Status != commun.Echoue || a[1].Status != commun.Reussi || a[2].Status != commun.NonExecute || r.Faits.RetainedHeight != 1001 {
		t.Errorf("attestations %+v", a)
	}
}

func TestO4PlusPetiteHauteur(t *testing.T) {
	// Deux attestations concordantes (1001 et 1003, même résultat) : la
	// retenue est 1001 (EX-10.12, R2-F31), quel que soit leur ordre.
	sc := nouveauScenario(t, func(i uint64, s *specEntete) {
		if i == 1003 {
			s.racine = resultatChemin(sha256Test("manifeste de test"))
		}
	})
	e := sc.entree()
	e.Preuve = fichierOTS(sc.empreinte, opAp(nonceTest), opSHA(), fourche(), attBitcoin(1003), attBitcoin(1001))
	r := verifierEtControler(t, e)
	attendre(t, r, "r r r r r r r", "r")
	if r.Faits.RetainedHeight != 1001 || r.Faits.Confirmations != 20 || len(r.Avertissements) != 1 {
		t.Errorf("faits %+v ; %s", r.Faits, avertissements(r))
	}
}

func TestO5(t *testing.T) {
	sc := nouveauScenario(t, nil)
	// Sans fichier d'en-têtes (EX-4.5) : O-4 à O-6 partie_absente.
	e := sc.entree()
	e.Entetes = nil
	r := verifierEtControler(t, e)
	attendre(t, r, "r r r "+pa+" "+pa+" "+pa+" r", pa)
	if len(r.Avertissements) != 0 || len(r.AncresEmployees) != 0 {
		t.Errorf("%s %v", avertissements(r), r.AncresEmployees)
	}
	// Sans ancre (EX-4.9).
	e = sc.entree()
	e.Ancre = nil
	attendre(t, verifierEtControler(t, e), "r r r "+aa+" "+aa+" "+aa+" r", aa)
	// Ni l'un ni l'autre : partie_absente d'abord (EX-6.5).
	e.Entetes = nil
	attendre(t, verifierEtControler(t, e), "r r r "+pa+" "+pa+" "+pa+" r", pa)
	// Fichier vide (impossible après N-2) : ancre_absente.
	e = sc.entree()
	e.Entetes = &ancres.Entetes{Reseau: ReseauRegtest, Debut: 0}
	attendre(t, verifierEtControler(t, e), "r r r "+aa+" "+aa+" "+aa+" r", aa)
	// Point de contrôle hors du fichier : non exécutée, pas d'AV-O-3.
	e = sc.entree()
	a := *sc.ancre
	a.Hauteur = 1030
	e.Ancre = &a
	r = verifierEtControler(t, e)
	attendre(t, r, "r r r "+aa+" "+aa+" "+aa+" r", aa)
	if len(r.Avertissements) != 0 {
		t.Errorf("avertissements %s", avertissements(r))
	}
	// Ancre d'un autre réseau : O-5 échoue (EX-4.9) ; pas d'AV-O-3, le
	// réseau de l'ancre n'est pas regtest.
	a = *sc.ancre
	a.Reseau = ReseauPrincipal
	e.Ancre = &a
	r = verifierEtControler(t, e)
	attendre(t, r, "r r r "+pre+" e "+pre+" r", "e")
	if len(r.Avertissements) != 0 || len(r.AncresEmployees) != 1 {
		t.Errorf("%s %v", avertissements(r), r.AncresEmployees)
	}
	// Chaîne sans travail : O-5 échoue, AV-O-3 levé (O-5 exécutée).
	sc2 := nouveauScenario(t, func(i uint64, s *specEntete) { s.sansTravail = i == 1015 })
	r = verifierEtControler(t, sc2.entree())
	attendre(t, r, "r r r "+pre+" e "+pre+" r", "e")
	if g := avertissements(r); g != "AV-O-3/O-5" {
		t.Errorf("avertissements %s", g)
	}
}

func TestO6(t *testing.T) {
	sc := nouveauScenario(t, nil)
	e := sc.entree()
	a := *sc.ancre
	a.MinConfirmations = 21
	e.Ancre = &a
	r := verifierEtControler(t, e)
	attendre(t, r, "r r r r r "+aa+" r", aa)
	a.MinConfirmations = 20
	attendre(t, verifierEtControler(t, e), "r r r r r r r", "r")
}

func TestO7(t *testing.T) {
	sc := nouveauScenario(t, nil)
	e := sc.entree()
	// Seulement des attestations en attente et inconnues (EX-10.11).
	tag := [8]byte{0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3}
	e.Preuve = fichierOTS(sc.empreinte, opAp(nonceTest), opSHA(), fourche(), attAttente("https://alice.btc.calendar.opentimestamps.org"), attInconnue(tag, []byte("litecoin")))
	r := verifierEtControler(t, e)
	attendre(t, r, "r r r "+pa+" "+pa+" "+pa+" "+pa, pa)
	if g := avertissements(r); g != "AV-O-2/O-7 AV-O-2/O-7" {
		t.Errorf("avertissements %s", g)
	}
	if !strings.Contains(r.Avertissements[1].Detail.Fr, "0xdeadbeef00010203") {
		t.Errorf("AV-O-2 : %s", r.Avertissements[1].Detail.Fr)
	}
	// Une inconnue à côté de la branche attestée : contrôle réussi, étiquette
	// dans les faits.
	e.Preuve = fichierOTS(sc.empreinte, opAp(nonceTest), opSHA(), fourche(), attInconnue(tag, nil), attBitcoin(1001))
	r = verifierEtControler(t, e)
	attendre(t, r, "r r r r r r r", "r")
	if at := r.Faits.Attestations[0]; at.Kind != "inconnue" || at.Tag == nil || *at.Tag != "0xdeadbeef00010203" || at.Height != nil || at.URI != nil {
		t.Errorf("attestation %+v", at)
	}
}

func TestPoint(t *testing.T) {
	sc := nouveauScenario(t, nil)
	e := sc.entree()
	e.Usage = Point
	r := verifierEtControler(t, e)
	attendre(t, r, "r r r r r r r", "r")
	if !r.Proposition.Vide() || r.Faits == nil || !strings.Contains(r.Verifications[1].Detail.Fr, "checkpoint_hash") {
		t.Errorf("point : %+v", r)
	}
	e.EmpreinteAttendue[3] ^= 1
	r = verifierEtControler(t, e)
	attendre(t, r, "r e r r r r r", "e")
	e.EmpreinteDisponible = false
	r = verifierEtControler(t, e)
	attendre(t, r, "r "+pre+" r r r r r", pre)
	if !strings.Contains(r.Verifications[1].Detail.Fr, "K-2") {
		t.Errorf("O-2 : %s", r.Verifications[1].Detail.Fr)
	}
}

// TestReseauPrincipal : contrôle réussi sur le bloc réel 358391, point de
// contrôle au bloc lui-même (t = c) : travail cumulé nul, pas de borne
// médiane, pas d'AV-O-3, proposition sans suffixe d'essai.
func TestReseauPrincipal(t *testing.T) {
	e := entetesReels(t)
	c := nouvelleChaine(e)
	var racine [32]byte
	copy(racine[:], c.racine(358391))
	ent := Entree{Usage: Cloture, Etat: entree.Lu, Preuve: fichierOTS(racine, attBitcoin(358391)), EmpreinteAttendue: racine, EmpreinteDisponible: true,
		Entetes: e, Ancre: &ancres.Bitcoin{Reseau: ReseauPrincipal, Hauteur: 358391, Hachage: c.hachageAffiche(358391), MinConfirmations: 1}}
	r := verifierEtControler(t, ent)
	attendre(t, r, "r r r r r r r", "r")
	f := r.Faits
	if f.CumulativeWork != "0" || f.MedianBound != nil || f.Confirmations != 1 || len(r.Avertissements) != 0 ||
		f.BlockHash != "0x000000000000000003e892881a8cdcdc117c06d444057c98b6f04a9ee75a2319" || f.BlockTime != "2015-05-28T15:41:18Z" {
		t.Errorf("faits %+v ; %s", f, avertissements(r))
	}
	if strings.Contains(r.Proposition.Fr, "réseau d'essai") || strings.Contains(r.Proposition.Fr, "borne sous hypothèse") ||
		!strings.HasSuffix(r.Proposition.Fr, "UTC, précision non garantie par le protocole") || !strings.Contains(r.Proposition.En, ", mainnet network)") {
		t.Errorf("proposition %+v", r.Proposition)
	}
	if strings.Contains(r.Resume.Fr, "essai") {
		t.Errorf("résumé %s", r.Resume.Fr)
	}
	// min_confirmations 2 : profondeur insuffisante.
	ent.Ancre.MinConfirmations = 2
	attendre(t, verifierEtControler(t, ent), "r r r r r "+aa+" r", aa)
}

func TestTextesSansContradiction(t *testing.T) {
	// Les détails des vérifications réussies ne parlent ni d'échec ni de
	// non-exécution, et inversement (contrôle des textes).
	sc := nouveauScenario(t, nil)
	r := verifierEtControler(t, sc.entree())
	for _, v := range r.Verifications {
		if strings.Contains(v.Detail.Fr, "prérequis") || strings.Contains(v.Detail.En, "prerequisite") {
			t.Errorf("%s : %s", v.ID, v.Detail.Fr)
		}
	}
	e := sc.entree()
	e.Etat = entree.Absent
	for _, v := range verifierEtControler(t, e).Verifications[1:] {
		if !strings.Contains(v.Detail.Fr, "O-1 non exécutée (prerequis_en_echec)") {
			t.Errorf("%s : %s", v.ID, v.Detail.Fr)
		}
	}
}
