package moteur

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/cryptographie"
	"github.com/noorfinances-eng/noortrace/verificateur/dossier"
	"github.com/noorfinances-eng/noortrace/verificateur/rapport"
)

var (
	motifHex32    = regexp.MustCompile(`^0x[0-9a-f]{64}$`)
	motifHorodate = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$`)
)

func ptr[T any](v T) *T { return &v }

// provenance d'une clé (EX-6.8) : « ancres » si N-3 l'a confirmée,
// « registre » si le contrôle 8 a réussi et que R-10 prouve l'inscription de
// sa clé publique, « dossier » sinon.
func (c *calcul) provenance(kid string, ctrl8 bool) string {
	if c.n3.Confirmees[kid] {
		return rapport.ProvAncres
	}
	if ctrl8 && c.reg != nil {
		if k, ok := c.an.Cles[kid]; ok {
			for _, i := range c.reg.Inscriptions {
				if i.ClePublique == k.Hex {
					return rapport.ProvRegistre
				}
			}
		}
	}
	return rapport.ProvDossier
}

func (c *calcul) construireRapport(verifs []commun.Verification, parID map[string]commun.Verification, ctrls [9]commun.Resultat, echecs, bloquantes []string, exiges []int, avert []commun.Avertissement) *rapport.Rapport {
	an := c.an
	l := c.o.Langue
	ver, _ := Verificateur(c.o.Version)
	r := &rapport.Rapport{
		Format: rapport.Format, Version: rapport.Version, Verifier: ver, Language: l,
		Inputs: *c.res.Entrees, Verdict: c.res.Verdict, ExitCode: c.res.Code,
		FailedChecks: nonNul(echecs), BlockingUnexecuted: nonNul(bloquantes),
		AbsentParts: []rapport.PartieAbsente{}, Warnings: []rapport.Avertissement{}, Checks: []rapport.Verification{},
	}
	r.Lisible.ExigesNonReussis = exiges
	ev := an.Evenement
	// Désignation de l'événement (EX-6.13).
	if ev != nil {
		seq, okS := ev.Seq()
		h, ts := ev.V.Membre("hash").S(), ev.V.Membre("ts").S()
		outil := ev.V.Chemin("execution", "tool")
		if okS && seq >= 0 && motifHex32.MatchString(h) && motifHorodate.MatchString(ts) && (outil.EstChaine() || outil.EstNul()) {
			e := &rapport.Evenement{Seq: seq, Hash: h, Ts: ts}
			if outil.EstChaine() {
				e.Tool = ptr(outil.Chaine)
			}
			r.Event = e
		}
		if o, j := ev.V.Membre("org_id").S(), ev.V.Membre("journal_id").S(); motifHex32.MatchString(o) && motifHex32.MatchString(j) {
			r.OrgID, r.JournalID = ptr(o), ptr(j)
		}
	}
	if m := an.Manifeste; m != nil && an.PeriodHashOK {
		ps, ok1 := m.Membre("period_start").Entier()
		pe, ok2 := m.Membre("period_end").Entier()
		if ok1 && ok2 && ps >= 0 && pe >= 0 {
			r.Period = &rapport.Periode{PeriodStart: ps, PeriodEnd: pe, PeriodHash: cryptographie.Hex32(an.PeriodHash)}
		}
	}
	// Vérifications.
	for _, v := range verifs {
		rv := rapport.Verification{ID: v.ID, Controls: nonNulInt(v.Controles), Status: v.Statut, DetailBilingue: v.Detail}
		if v.Statut == commun.NonExecute {
			rv.Reason = ptr(v.Raison)
			rv.Admitted = ptr(v.Raison.Admise())
		}
		if d := v.Detail.Langue(l); d != "" {
			rv.Detail = ptr(d)
		}
		r.Checks = append(r.Checks, rv)
	}
	for _, p := range an.PartiesAbsentes {
		pa := rapport.PartieAbsente{Name: p.Nom, File: p.Fichier}
		if p.Raison != "" {
			pa.Reason = ptr(p.Raison)
		}
		r.AbsentParts = append(r.AbsentParts, pa)
	}
	for _, a := range avert {
		ra := rapport.Avertissement{ID: a.ID, Detail: a.Detail.Langue(l), DetailBilingue: a.Detail}
		if a.Verification != "" {
			ra.Check = ptr(a.Verification)
		}
		r.Warnings = append(r.Warnings, ra)
	}
	ctrl8 := ctrls[8].Statut == commun.Reussi
	// Faits (EX-6.13).
	cleEv := ""
	if ev != nil {
		cleEv = ev.Cle()
	}
	cleMan := an.CleManifeste
	provEv, provMan := c.provenance(cleEv, ctrl8), c.provenance(cleMan, ctrl8)
	if ctrls[6].Statut == commun.Reussi {
		src := provEv
		if provEv != provMan {
			src = "mixte"
		}
		r.Facts.RecorderKeys = &rapport.FaitsCles{EventKeyID: cleEv, ManifestKeyID: cleMan, Source: src, EventKeySource: provEv, ManifestKeySource: provMan}
	}
	var approbation *rapport.Approbation
	if ctrls[7].Statut == commun.Reussi {
		ap := ev.V.Membre("approval")
		fa := &rapport.FaitsApprobation{Decision: ap.Membre("decision").S(), Ticket: ap.Membre("ticket").S(), Approvers: []string{}, SetSource: "dossier"}
		for _, x := range ap.Membre("approvers").Elements {
			fa.Approvers = append(fa.Approvers, x.S())
		}
		fa.Required, _ = ap.Chemin("threshold", "required").Entier()
		fa.Size, _ = ap.Chemin("threshold", "size").Entier()
		r.Facts.Approval = fa
		approbation = &rapport.Approbation{Decision: fa.Decision, Approbateurs: fa.Approvers, Required: fa.Required, Size: fa.Size}
	}
	if ctrls[4].Statut == commun.Reussi && c.jeton != nil {
		r.Facts.Timestamp = c.jeton.Faits
	}
	if ctrls[5].Statut == commun.Reussi && c.preuve != nil {
		r.Facts.Bitcoin = c.preuve.Faits
	}
	if ctrl8 && c.reg != nil {
		r.Facts.Registry = c.reg.Faits
	}
	// facts.checkpoint (EX-6.17) et FK (EX-6.16).
	var fk commun.Texte
	if pt := an.Point; pt != nil {
		ok := ctrls[1].Statut == commun.Reussi && ctrls[3].Statut == commun.Reussi && ctrls[6].Statut == commun.Reussi
		for _, id := range []string{"K-1", "K-2", "K-3", "K-4", "K-5"} {
			if parID[id].Statut != commun.Reussi {
				ok = false
			}
		}
		k6 := parID["K-6"]
		if !(k6.Statut == commun.Reussi || (k6.Statut == commun.NonExecute && k6.Raison == commun.PieceHorsDossier)) {
			ok = false
		}
		if pt.K1 && pt.K2 {
			lp := commun.T(fmt.Sprintf("taille %d, last_seq %d, empreinte %s", pt.TreeSize, pt.LastSeq, cryptographie.Hex32(pt.CheckpointHash)),
				fmt.Sprintf("size %d, last_seq %d, digest %s", pt.TreeSize, pt.LastSeq, cryptographie.Hex32(pt.CheckpointHash)))
			if parID["K-7"].Statut == commun.Reussi && c.jetonPt != nil && c.jetonPt.Faits != nil {
				b := c.jetonPt.Faits.GenTime
				if c.jetonPt.Faits.UpperBound != nil {
					b = *c.jetonPt.Faits.UpperBound
				}
				lp = lp.Joindre(" ; ", "; ", commun.T("horodaté au plus tard "+b+" (K-7)", "time-stamped no later than "+b+" (K-7)"))
			}
			r.Lisible.LignePoint = &lp
		}
		if ok {
			fp := &rapport.FaitsPoint{TreeSize: pt.TreeSize, LastSeq: pt.LastSeq, LeafIndex: pt.LeafIndex, CheckpointTs: pt.CheckpointTsTexte,
				CheckpointHash: cryptographie.Hex32(pt.CheckpointHash), KeyID: pt.KeyID, KeySource: c.provenance(pt.KeyID, ctrl8),
				Consistency:     rapport.Coherence{FirstSize: pt.PremiereTaille, SecondSize: pt.SecondeTaille, PathLength: pt.LongueurChemin},
				LastHashChecked: pt.DernierHashVerifie}
			dk := rapport.DonneesFK{TreeSize: pt.TreeSize, CheckpointHash: fp.CheckpointHash, KeyID: pt.KeyID, Provenance: fp.KeySource}
			if parID["K-7"].Statut == commun.Reussi && c.jetonPt != nil && c.jetonPt.Faits != nil {
				fp.Timestamp = c.jetonPt.Faits
				dk.Jeton = c.jetonPt.Faits
				if ub := c.jetonPt.Faits.UpperBoundInstant; ub != nil {
					fp.RewriteWindowEnd = ptr(commun.FormaterInstant(*ub))
					if ts, okTs := ev.Ts(); okTs {
						fp.RewriteWindowMs = ptr(ub.Sub(ts).Milliseconds())
					}
				}
			}
			if parID["K-9"].Statut == commun.Reussi && c.preuvePt != nil && c.preuvePt.Faits != nil {
				fp.Bitcoin = c.preuvePt.Faits
				dk.Bitcoin = c.preuvePt.Faits
			}
			if parID["K-8"].Statut == commun.Reussi && c.reg != nil && c.reg.FaitsPoint != nil {
				fp.Registry = c.reg.FaitsPoint
				if c.reg.FaitsPoint.Inclusion == "prouvee" && ctrl8 && c.anc != nil && c.anc.Registre != nil {
					dk.Registre = c.reg.FaitsPoint
					dk.ChainID = c.anc.Registre.ChainID
				}
			}
			r.Facts.Checkpoint = fp
			fk = rapport.FragmentFK(dk)
		}
	}
	// facts.perimeter (EX-6.20) et FP (EX-6.19).
	var fpTexte commun.Texte
	if at := an.Attestation; at != nil {
		lp := c.lignePerimetre(at, parID)
		r.Lisible.LignePerimetre = &lp
		d := rapport.DonneesFP{Retenue: at.Retenue, IDs: at.IDs, IDsEnEchec: at.IDsEnEchec}
		if at.Retenue {
			P := at.V.Chemin("signed", "attestation")
			jeu := at.V.Membre("approver_set")
			de, _ := commun.LireHorodatage(P.Chemin("validity", "from").S())
			fin, _ := commun.LireHorodatage(P.Chemin("validity", "until").S())
			d.Digest = cryptographie.Hex32(at.Digest)
			d.From, d.Until = commun.FormaterInstant(de), commun.FormaterInstant(fin)
			for _, s := range at.V.Chemin("signed", "signatures").Elements {
				d.Signataires = append(d.Signataires, s.Membre("address").S())
			}
			d.Required, _ = jeu.Chemin("threshold", "required").Entier()
			d.Size, _ = jeu.Chemin("threshold", "size").Entier()
			d.Exceptions = len(P.Membre("not_captured").Elements)
			v6 := parID["AT-6"]
			switch {
			case v6.Statut == commun.Reussi:
				d.Inscription = "reussie"
				d.SeqI, _ = at.Inscription.Seq()
				d.CleI = at.Inscription.Cle()
				d.ProvI = c.provenance(d.CleI, ctrl8)
				d.MemeVersion = parID["AT-7"].Statut == commun.Reussi
			case v6.Raison == commun.AncreAbsente:
				d.Inscription = "ancre_absente"
			default:
				d.Inscription = "partie_absente"
			}
			fpp := &rapport.FaitsPerimetre{Provenance: "declaree", Digest: d.Digest, OrgID: P.Chemin("org", "org_id").S(), JournalIDs: []string{},
				ValidFrom: P.Chemin("validity", "from").S(), ValidUntil: P.Chemin("validity", "until").S(), IssuedAt: P.Membre("issued_at").S(),
				Signers: nonNul(at.Signataires), Required: d.Required, Size: d.Size, SetSource: jeu.Membre("source").S(),
				Agents: len(P.Membre("agents").Elements), CaptureChannels: nonNul(at.CanauxCapture()), Exceptions: d.Exceptions,
				EgressDefaultPolicy: P.Chemin("egress", "default_policy").S(), EgressRulesSha256: P.Chemin("egress", "rules_sha256").S()}
			for _, j := range P.Membre("journals").Elements {
				fpp.JournalIDs = append(fpp.JournalIDs, j.Membre("journal_id").S())
			}
			if d.Inscription == "reussie" {
				ins := at.Inscription
				val := ins.V.Chemin("execution", "arguments", "value")
				s, _ := ins.Seq()
				fpp.Inscription = &rapport.InscriptionPerimetre{Seq: s, Hash: ins.HashHex(), Ts: ins.V.Membre("ts").S(), KeyID: ins.Cle(),
					PolicyVersion: val.Membre("policy_version").S(), PolicySha256: val.Membre("policy_sha256").S(), SamePolicyVersion: d.MemeVersion}
			}
			r.Facts.Perimeter = fpp
		}
		fpTexte = rapport.FragmentFP(d)
	}
	// Contrôles.
	var nonExec []rapport.ControleNonExecute
	nonExecutes := map[int]bool{}
	for n := 1; n <= 8; n++ {
		ct := rapport.Controle{Number: n, Status: ctrls[n].Statut, Checks: []string{}, AnchorsUsed: []string{}}
		if ctrls[n].Statut == commun.NonExecute {
			ct.Reason = ptr(ctrls[n].Raison)
			nonExec = append(nonExec, rapport.ControleNonExecute{Numero: n, Raison: ctrls[n].Raison})
			nonExecutes[n] = true
		}
		for _, v := range verifs {
			for _, k := range v.Controles {
				if k == n {
					ct.Checks = append(ct.Checks, v.ID)
				}
			}
		}
		ct.AnchorsUsed = nonNul(c.ancresEmployees(n, parID))
		ct.ResumeBilingue = c.resume(n, ctrls[n], verifs)
		if s := ct.ResumeBilingue.Langue(l); s != "" {
			ct.Summary = ptr(s)
		}
		r.Controls = append(r.Controls, ct)
	}
	// Énoncé et borne.
	if c.res.Verdict == "invalide" {
		e := rapport.EnonceInvalide(echecs, bloquantes)
		r.Statement = rapport.Enonce{Fr: e.Fr, En: e.En}
	} else {
		seq, _ := ev.Seq()
		d := rapport.DonneesEnonce{Seq: seq, Hash: ev.V.Membre("hash").S(), JournalID: ev.V.Membre("journal_id").S(), OrgID: ev.V.Membre("org_id").S(),
			PeriodHash: cryptographie.Hex32(an.PeriodHash), CleEvenement: cleEv, CleManifeste: cleMan, ProvEvenement: provEv, ProvManifeste: provMan,
			Approbation: approbation, FK: fk, FP: fpTexte, NonExecutes: nonExecutes}
		d.PeriodStart, _ = an.Manifeste.Membre("period_start").Entier()
		d.PeriodEnd, _ = an.Manifeste.Membre("period_end").Entier()
		if an.Precedent != nil {
			s, _ := an.Precedent.Seq()
			d.Precedent = ptr(s)
		}
		if an.Suivant != nil {
			s, _ := an.Suivant.Seq()
			d.Suivant = ptr(s)
		}
		if ctrls[4].Statut == commun.Reussi && c.jeton != nil {
			d.F4 = c.jeton.Proposition
		}
		if ctrls[5].Statut == commun.Reussi && c.preuve != nil {
			d.F5 = c.preuve.Proposition
		}
		if ctrl8 && c.reg != nil {
			d.F6 = c.reg.Proposition
		}
		e := rapport.ConstruireEnonce(d)
		r.Statement = rapport.Enonce{Fr: e.Fr, En: e.En}
	}
	if b := rapport.Borne(nonExec); b != nil {
		r.Bound = ptr(b.Langue(l))
		r.Lisible.BorneBilingue = b
	}
	return r
}

func nonNul(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nonNulInt(s []int) []int {
	if s == nil {
		return []int{}
	}
	return s
}

func (c *calcul) ancresEmployees(n int, parID map[string]commun.Verification) []string {
	var out []string
	switch n {
	case 4:
		if c.jeton != nil {
			out = append(out, c.jeton.AncresEmployees...)
		}
		if c.jetonPt != nil && parID["K-7"].Statut == commun.Reussi {
			for _, a := range c.jetonPt.AncresEmployees {
				if !contientChaine(out, a) {
					out = append(out, a)
				}
			}
		}
	case 5:
		if c.preuve != nil {
			out = append(out, c.preuve.AncresEmployees...)
		}
		if c.preuvePt != nil && parID["K-9"].Statut == commun.Reussi {
			for _, a := range c.preuvePt.AncresEmployees {
				if !contientChaine(out, a) {
					out = append(out, a)
				}
			}
		}
	case 6:
		out = append(out, c.n3.Pointeurs...)
	case 8:
		if c.reg != nil {
			out = append(out, c.reg.AncresEmployees...)
		}
	}
	return out
}

func contientChaine(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// resume : summary d'un contrôle (CT-6 §8.5, §8.6 ; libellés libres, V-5 ne
// les compare pas).
func (c *calcul) resume(n int, st commun.Resultat, verifs []commun.Verification) commun.Texte {
	an := c.an
	var siennes []commun.Verification
	for _, v := range verifs {
		for _, k := range v.Controles {
			if k == n {
				siennes = append(siennes, v)
			}
		}
	}
	if st.Statut == commun.Echoue {
		var ids []string
		for _, v := range siennes {
			if v.Statut == commun.Echoue && !strings.HasPrefix(v.ID, "AT-") {
				ids = append(ids, v.ID)
			}
		}
		return commun.T("vérification(s) en échec : "+commun.ListeIDs(ids), "failed check(s): "+commun.ListeIDs(ids))
	}
	// Partie requise absente (EX-4.3).
	if st.Statut == commun.NonExecute && (st.Raison == commun.HorsPerimetreVersion || st.Raison == commun.PartieAbsente) {
		var noms []string
		switch n {
		case 4:
			noms = []string{dossier.PJeton}
		case 5:
			noms = []string{dossier.PPreuveOTS}
		case 7:
			noms = []string{dossier.PApprobations}
		case 8:
			noms = []string{dossier.PRegistre, dossier.PCertificat, dossier.PValidateurs}
		}
		var fichiers []string
		raison := ""
		for _, nom := range noms {
			if p := c.dos.Partie(nom); p != nil && !p.Present {
				fichiers = append(fichiers, p.Fichier)
				raison = p.Raison
			}
		}
		if n == 7 && len(fichiers) == 0 {
			fichiers = []string{"approbations.json"}
			raison = "aucune approbation liée"
		}
		if len(fichiers) > 0 && (n != 8 || !c.reg8) {
			if len(fichiers) == 1 {
				return commun.T(fichiers[0]+" absent ("+raison+")", fichiers[0]+" absent ("+raison+")")
			}
			s := strings.Join(fichiers, ", ")
			return commun.T(s+" absents ("+raison+")", s+" absent ("+raison+")")
		}
	}
	var pkg commun.Texte
	switch n {
	case 4:
		if c.jeton != nil {
			pkg = c.jeton.Resume
		}
	case 5:
		if c.preuve != nil {
			pkg = c.preuve.Resume
		}
	case 8:
		if c.reg != nil {
			pkg = c.reg.Resume
		}
	}
	if st.Statut == commun.Reussi {
		switch n {
		case 1:
			return commun.T("hachage canonique recalculé égal à hash", "recomputed canonical hash equals hash")
		case 2:
			p, s := an.Precedent, an.Suivant
			switch {
			case p != nil && s != nil:
				ps, _ := p.Seq()
				ss, _ := s.Seq()
				return commun.T(fmt.Sprintf("chaîné aux voisins seq %d et %d", ps, ss), fmt.Sprintf("chained to neighbours seq %d and %d", ps, ss))
			case p != nil:
				ps, _ := p.Seq()
				return commun.T(fmt.Sprintf("chaîné au voisin précédent seq %d", ps), fmt.Sprintf("chained to the previous neighbour seq %d", ps))
			case s != nil:
				ss, _ := s.Seq()
				return commun.T(fmt.Sprintf("premier événement, chaîné au voisin suivant seq %d", ss), fmt.Sprintf("first event, chained to the next neighbour seq %d", ss))
			}
			return commun.T("premier événement, sans voisin", "first event, no neighbour")
		case 3:
			idx, taille := int64(0), int64(0)
			if ch := an.Dossier.Partie(dossier.PChemin); ch.Exploitable() {
				idx, _ = ch.Valeur.Membre("leaf_index").Entier()
				taille, _ = ch.Valeur.Membre("tree_size").Entier()
			}
			ph := cryptographie.Hex32(an.PeriodHash)
			return commun.T(fmt.Sprintf("feuille %d de l'arbre de %d du manifeste %s", idx, taille, ph), fmt.Sprintf("leaf %d of the %d-leaf tree of manifest %s", idx, taille, ph))
		case 6:
			ctrl8 := c.res.Controles[8].Statut == commun.Reussi
			kev, kman := an.Evenement.Cle(), an.CleManifeste
			pe, pm := c.provenance(kev, ctrl8), c.provenance(kman, ctrl8)
			if kev == kman {
				t := rapport.TexteProvenance(pe)
				return commun.T(kev+" (événement et manifeste), clé "+t.Fr, kev+" (event and manifest), key "+t.En)
			}
			if pe == pm {
				t := map[string]commun.Texte{rapport.ProvAncres: commun.T("clés fournies par le fichier d'ancres", "keys given by the anchors file"),
					rapport.ProvRegistre: commun.T("clés inscrites au registre", "keys registered in the registry"),
					rapport.ProvDossier:  commun.T("clés déclarées par le dossier", "keys declared by the dossier")}[pe]
				return commun.T(kev+" (événement), "+kman+" (manifeste), "+t.Fr, kev+" (event), "+kman+" (manifest), "+t.En)
			}
			t1, t2 := rapport.TexteProvenance(pe), rapport.TexteProvenance(pm)
			return commun.T(kev+" (événement) "+t1.Fr+", "+kman+" (manifeste) "+t2.Fr, kev+" (event) "+t1.En+", "+kman+" (manifest) "+t2.En)
		case 7:
			ap := an.Evenement.V.Membre("approval")
			t := ap.Membre("ticket").S()
			req, _ := ap.Chemin("threshold", "required").Entier()
			taille, _ := ap.Chemin("threshold", "size").Entier()
			nb := len(ap.Membre("approvers").Elements)
			var fr, en string
			if ap.Membre("decision").S() == "expire" {
				fr = fmt.Sprintf("%s : demande expirée sans signature, seuil %d sur %d", t, req, taille)
				en = fmt.Sprintf("%s: request expired without signature, threshold %d of %d", t, req, taille)
			} else {
				fr = fmt.Sprintf("%s : %s, seuil %d sur %d", t, commun.Pluriel(nb, "1 signature", fmt.Sprintf("%d signatures", nb)), req, taille)
				en = fmt.Sprintf("%s: %s, threshold %d of %d", t, commun.Pluriel(nb, "1 signature", fmt.Sprintf("%d signatures", nb)), req, taille)
			}
			if v, ok := c.an.Statut("A-4"); ok && v.Statut == commun.NonExecute && v.Raison == commun.PieceHorsDossier {
				fr += " ; A-4 hors dossier"
				en += "; A-4 outside the dossier"
			}
			return commun.T(fr, en)
		}
		return pkg
	}
	if !pkg.Vide() {
		return pkg
	}
	var ids []string
	for _, v := range siennes {
		if v.Statut == commun.NonExecute && !sansEffet(v.ID) && v.Raison != commun.PieceHorsDossier {
			ids = append(ids, v.ID)
		}
	}
	if len(ids) == 0 {
		return commun.Texte{}
	}
	return commun.T("vérification(s) non exécutée(s) : "+commun.ListeIDs(ids), "check(s) not run: "+commun.ListeIDs(ids))
}

// lignePerimetre : ligne « Périmètre » du rapport lisible (EX-8.10).
func (c *calcul) lignePerimetre(at *dossier.Attestation, parID map[string]commun.Verification) commun.Texte {
	if !at.Retenue {
		ids := commun.ListeIDs(at.IDs)
		if at.IDsEnEchec {
			return commun.T("attestation non retenue ("+ids+" en échec)", "attestation not retained ("+ids+" failed)")
		}
		return commun.T("attestation non retenue ("+ids+" non exécutée(s))", "attestation not retained ("+ids+" not run)")
	}
	P := at.V.Chemin("signed", "attestation")
	jeu := at.V.Membre("approver_set")
	de, _ := commun.LireHorodatage(P.Chemin("validity", "from").S())
	fin, _ := commun.LireHorodatage(P.Chemin("validity", "until").S())
	req, _ := jeu.Chemin("threshold", "required").Entier()
	taille, _ := jeu.Chemin("threshold", "size").Entier()
	nb := len(at.V.Chemin("signed", "signatures").Elements)
	t := commun.T(fmt.Sprintf("déclaré, non prouvé : attestation %s, du %s au %s, %d signatures, seuil de %d sur %d", cryptographie.Hex32(at.Digest), commun.FormaterInstant(de), commun.FormaterInstant(fin), nb, req, taille),
		fmt.Sprintf("declared, not proven: attestation %s, from %s to %s, %d signatures, threshold %d of %d", cryptographie.Hex32(at.Digest), commun.FormaterInstant(de), commun.FormaterInstant(fin), nb, req, taille))
	v6 := parID["AT-6"]
	switch {
	case v6.Statut == commun.Reussi:
		s, _ := at.Inscription.Seq()
		t = t.Joindre(" ; ", "; ", commun.T(fmt.Sprintf("inscrite au seq %d", s), fmt.Sprintf("recorded at seq %d", s)))
	case v6.Raison == commun.AncreAbsente:
		t = t.Joindre(" ; ", "; ", commun.T("inscription non reliée à la clé de l'événement", "inscription not tied to the event's key"))
	default:
		t = t.Joindre(" ; ", "; ", commun.T("non inscrite", "not recorded"))
	}
	return t
}
