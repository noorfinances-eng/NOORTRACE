package registre

// Proposition de l'énoncé (EX-11.22, fragment F6) et résumé du contrôle 8
// (summary, §8.5).

import (
	"fmt"
	"sort"
	"strings"

	"github.com/noorfinances-eng/noortrace/verificateur/ancres"
	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/cryptographie"
)

// groupe : certificats groupés par jeu de l'ancre retenu par R-2.
type groupe struct {
	jeu      *ancres.JeuValidateurs
	hauteurs []uint64
	n        int // plus petit nombre de signataires distincts
}

// groupes rend les groupes dans l'ordre de leur plus petite hauteur.
func (c *calcul) groupes() []*groupe {
	par := map[string]*groupe{}
	var out []*groupe
	for i := range c.certs {
		j := c.jeux[i]
		g, ok := par[j.Pointeur]
		if !ok {
			g = &groupe{jeu: j, n: -1}
			par[j.Pointeur] = g
			out = append(out, g)
		}
		g.hauteurs = append(g.hauteurs, c.certs[i].hauteur)
		if n := len(c.sig[i].signataires); g.n < 0 || n < g.n {
			g.n = n
		}
	}
	for _, g := range out {
		sort.Slice(g.hauteurs, func(a, b int) bool { return g.hauteurs[a] < g.hauteurs[b] })
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].hauteurs[0] < out[b].hauteurs[0] })
	return out
}

func entiers(h []uint64) []string {
	s := make([]string, len(h))
	for i, x := range h {
		s[i] = fmt.Sprint(x)
	}
	return s
}

// propositionSignature rend la proposition de signature d'EX-11.22.
func (c *calcul) propositionSignature() commun.Texte {
	gs := c.groupes()
	queue := func(g *groupe) (string, string) {
		hj := cryptographie.Hex32(hachageJeu(g.jeu))
		n, N := g.n, len(g.jeu.Validateurs)
		return fmt.Sprintf("%d des %d validateurs du jeu %s que le réviseur déclare (%s)", n, N, hj, g.jeu.Source),
			fmt.Sprintf("%d of the %d validators of set %s declared by the reviewer (%s)", n, N, hj, g.jeu.Source)
	}
	if len(gs) == 1 {
		fr, en := queue(gs[0])
		return commun.T("chacun de ces blocs est signé par "+fr, "each of these blocks is signed by "+en)
	}
	var fr, en []string
	for k, g := range gs {
		qfr, qen := queue(g)
		h := entiers(g.hauteurs)
		var tfr, ten string
		if len(h) == 1 {
			tfr, ten = "le bloc "+h[0], "block "+h[0]
			if k == 0 {
				tfr, ten = tfr+" est signé par ", ten+" is signed by "
			} else {
				tfr, ten = tfr+" par ", ten+" by "
			}
		} else {
			tfr = "les blocs " + commun.JoindreListe(h, ", ", " et ")
			ten = "blocks " + commun.JoindreListe(h, ", ", " and ")
			if k == 0 {
				tfr, ten = tfr+" sont signés par ", ten+" are signed by "
			} else {
				tfr, ten = tfr+" par ", ten+" by "
			}
		}
		fr, en = append(fr, tfr+qfr), append(en, ten+qen)
	}
	return commun.T(commun.JoindreListe(fr, ", ", " et "), commun.JoindreListe(en, ", ", " and "))
}

// proposition rend la proposition d'EX-11.22 (contrôle 8 réussi), sans
// « ; » de tête.
func (c *calcul) proposition() commun.Texte {
	m := c.e.Manifeste
	cl, an := c.indiceRole(roleCloture), c.indiceRole(roleAncre)
	if cl < 0 || an < 0 {
		return commun.Texte{}
	}
	ecl, ean := &c.entrees[cl], &c.entrees[an]
	fa := lireAncre(ean.journalProuve(), true)
	tcl := commun.FormaterSecondes(int64(ecl.bloc.horodatage))
	tan := commun.FormaterSecondes(int64(ean.bloc.horodatage))
	adrPR := hexA(ecl.journalProuve().adresse)
	adrAR := hexA(ean.journalProuve().adresse)
	fr := fmt.Sprintf("sur le registre %s, la clôture de cette période (organisation %s, journal %s) figure au bloc %d (heure déclarée par le bloc : %s UTC), émise par le contrat PeriodRegistry %s, et son ancre %s au bloc %d (heure déclarée %s UTC), émise par AttestationRegistry %s pour l'émetteur %s",
		c.reg.ChainID, m.OrgID, m.JournalID, ecl.bloc.numero, tcl, adrPR, fa.ev.Fingerprint, ean.bloc.numero, tan, adrAR, fa.ev.Issuer)
	en := fmt.Sprintf("on registry %s, the closing of this period (organisation %s, journal %s) is in block %d (time declared by the block: %s UTC), emitted by contract PeriodRegistry %s, and its anchor %s in block %d (declared time %s UTC), emitted by AttestationRegistry %s for issuer %s",
		c.reg.ChainID, m.OrgID, m.JournalID, ecl.bloc.numero, tcl, adrPR, fa.ev.Fingerprint, ean.bloc.numero, tan, adrAR, fa.ev.Issuer)
	if c.r10 == commun.Reussi && c.inscCleMan >= 0 {
		h := c.entrees[c.inscCleMan].bloc.numero
		fr += fmt.Sprintf(", clé de chaîne inscrite au bloc %d pour la clé d'enregistreur %s", h, m.RecorderKeyID)
		en += fmt.Sprintf(", chain key registered in block %d for recorder key %s", h, m.RecorderKeyID)
	}
	if c.n4 != nil && c.n4.Statut == commun.Reussi {
		fr += ", que le réviseur tient pour la clé de chaîne de " + m.RecorderKeyID
		en += ", which the reviewer holds as the chain key of " + m.RecorderKeyID
	}
	s := c.propositionSignature()
	return commun.T(fr+" ; "+s.Fr, en+"; "+s.En)
}

// resume rend le summary du contrôle 8 réussi, par exemple
// « noortrace-2124-dev : inscriptions blocs 16648 et 16652, ancre bloc
// 16660, clôture bloc 16668, 3 validateurs sur 4 à chaque bloc ».
func (c *calcul) resume() commun.Texte {
	roles := []struct{ role, un, plusieurs, unEn, plusieursEn string }{
		{roleInscription, "inscription bloc ", "inscriptions blocs ", "registration block ", "registrations blocks "},
		{roleAncre, "ancre bloc ", "ancres blocs ", "anchor block ", "anchor blocks "},
		{rolePoint, "ancre de point de contrôle bloc ", "ancres de point de contrôle blocs ", "checkpoint anchor block ", "checkpoint anchor blocks "},
		{roleCloture, "clôture bloc ", "clôtures blocs ", "closing block ", "closing blocks "},
	}
	var fr, en []string
	for _, r := range roles {
		var h []uint64
		for i := range c.entrees {
			if c.entrees[i].role == r.role {
				h = append(h, c.entrees[i].bloc.numero)
			}
		}
		if len(h) == 0 {
			continue
		}
		s := entiers(h)
		if len(h) == 1 {
			fr, en = append(fr, r.un+s[0]), append(en, r.unEn+s[0])
		} else {
			fr, en = append(fr, r.plusieurs+commun.JoindreListe(s, ", ", " et ")), append(en, r.plusieursEn+commun.JoindreListe(s, ", ", " and "))
		}
	}
	nMin, nMax, tailles := -1, -1, map[int]bool{}
	taille := 0
	for i := range c.certs {
		n := len(c.sig[i].signataires)
		if nMin < 0 || n < nMin {
			nMin = n
		}
		if n > nMax {
			nMax = n
		}
		taille = len(c.jeux[i].Validateurs)
		tailles[taille] = true
	}
	switch {
	case len(tailles) > 1:
		fr, en = append(fr, fmt.Sprintf("au moins %d validateurs à chaque bloc", nMin)), append(en, fmt.Sprintf("at least %d validators in each block", nMin))
	case nMin == nMax:
		fr, en = append(fr, fmt.Sprintf("%d validateurs sur %d à chaque bloc", nMin, taille)), append(en, fmt.Sprintf("%d of %d validators in each block", nMin, taille))
	default:
		fr, en = append(fr, fmt.Sprintf("au moins %d validateurs sur %d à chaque bloc", nMin, taille)), append(en, fmt.Sprintf("at least %d of %d validators in each block", nMin, taille))
	}
	return commun.T(c.reg.ChainID+" : "+strings.Join(fr, ", "), c.reg.ChainID+": "+strings.Join(en, ", "))
}
