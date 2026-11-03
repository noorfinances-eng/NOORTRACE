package registre

// Implémentation du contrôle 8 (CT-6 §11) : R-1 à R-11, N-4 (EX-12.5) et
// K-8 (EX-11.25). Aucune entrée-sortie : tout est lu dans Entree.

import (
	"fmt"
	"sort"
	"strings"

	"github.com/noorfinances-eng/noortrace/verificateur/ancres"
	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/cryptographie"
	"github.com/noorfinances-eng/noortrace/verificateur/entree"
)

// construit : l'implémentation du contrôle 8 est complète (voir Construit).
const construit = true

// raisonHorsPerimetreCT1 : raison d'absence qui donne hors_perimetre_version
// (EX-4.3).
const raisonHorsPerimetreCT1 = "hors périmètre CT-1"

// calcul : état du contrôle 8 pendant une vérification.
type calcul struct {
	e   Entree
	reg *ancres.Registre

	entrees []entreeRegistre
	certs   []certificat
	// r1ok : R-1 a réussi (parties lues, conformes et appariées).
	r1ok bool

	// Par certificat.
	r2, r4, r5 []commun.Resultat
	jeux       []*ancres.JeuValidateurs
	sig        []resultatR5
	// Par entrée.
	r6, r7 []commun.Resultat

	verifs map[string]commun.Verification

	// R-10.
	cleParPub  map[string]string // public_key de cles.json → key_id
	inscOK     []int             // entrées inscription valides (R-10)
	r10        commun.Statut
	inscCleMan int // entrée d'inscription de la clé du manifeste sous l'émetteur, ou -1
	// R-11.
	r11       *commun.Verification
	rattachee bool
	pointIdx  int // entrée ancre_point_de_controle, ou -1
	// N-4 et K-8.
	n4, k8    *commun.Verification
	recorder  string
	avR, avR5 []commun.Avertissement
	avK1      []commun.Avertissement
	avR11     []commun.Avertissement
}

func nouvelle(id string, st commun.Statut, raison commun.Raison, d commun.Texte) commun.Verification {
	return commun.Nouvelle(id, st, raison, d, 8)
}

func verifier(e Entree) Resultat {
	c := &calcul{e: e, verifs: map[string]commun.Verification{}, inscCleMan: -1, pointIdx: -1}
	if e.Ancres != nil {
		c.reg = e.Ancres.Registre
	}
	res := Resultat{Verifications: []commun.Verification{}, Inscriptions: []Inscription{}, Avertissements: []commun.Avertissement{}, AncresEmployees: []string{}}
	if e.PartiesPresentes() {
		c.controle8()
		for _, id := range IDs {
			if v, ok := c.verifs[id]; ok {
				res.Verifications = append(res.Verifications, v)
			}
		}
		if c.n4 != nil {
			v := *c.n4
			res.N4 = &v
		}
	}
	if e.Point != nil && e.Point.Reference != nil && e.Point.K2 {
		c.verifierK8()
		v := *c.k8
		res.K8 = &v
	}
	c.synthese(&res)
	return res
}

// raisonDe : raison d'une vérification qui dépend d'un résultat (EX-5.5).
func raisonDe(r commun.Resultat) commun.Raison {
	if r.Statut == commun.Echoue {
		return commun.PrerequisEnEchec
	}
	return r.Raison
}

// agreger : statut et détail d'une vérification à portée multiple (§11.4).
func agreger(id string, res []commun.Resultat, details []commun.Texte) commun.Verification {
	st, raison := commun.Agreger(res)
	var fr, en []string
	for _, d := range details {
		if !d.Vide() {
			fr, en = append(fr, d.Fr), append(en, d.En)
		}
	}
	return nouvelle(id, st, raison, commun.T(strings.Join(fr, " ; "), strings.Join(en, "; ")))
}

func ok() commun.Resultat { return commun.Resultat{Statut: commun.Reussi} }
func ko() commun.Resultat { return commun.Resultat{Statut: commun.Echoue} }
func ne(r commun.Raison) commun.Resultat {
	return commun.Resultat{Statut: commun.NonExecute, Raison: r}
}

// controle8 exécute R-1 à R-11 et N-4 (parties présentes).
func (c *calcul) controle8() {
	c.verifs["R-1"] = c.verifierR1()
	if !c.r1ok {
		d := commun.T("R-1 non réussie", "R-1 not passed")
		for _, id := range IDs[1:10] {
			c.verifs[id] = nouvelle(id, commun.NonExecute, commun.PrerequisEnEchec, d)
		}
		// R-11 : figure avec la partie points-de-controle.json ou une entrée
		// ancre_point_de_controle (EX-6.18 ; INDEX.md des vecteurs).
		aEntree := false
		for _, x := range c.entrees {
			if x.role == rolePoint {
				aEntree = true
			}
		}
		if aEntree || c.e.Point != nil || c.e.PointDeclare {
			v := nouvelle("R-11", commun.NonExecute, commun.PrerequisEnEchec, d)
			if c.entrees != nil && !aEntree {
				v = nouvelle("R-11", commun.NonExecute, commun.PartieAbsente, commun.T("aucune entrée ancre_point_de_controle", "no ancre_point_de_controle entry"))
			}
			c.r11 = &v
			c.verifs["R-11"] = v
		}
		if c.e.N4Figure() {
			v := nouvelle("N-4", commun.NonExecute, commun.PrerequisEnEchec, d)
			c.n4 = &v
		}
		return
	}
	c.verifierCertificats()
	c.verifierEntrees()
	c.verifs["R-9"] = c.verifierR9()
	c.verifs["R-10"] = c.verifierR10()
	c.verifierR11()
	if c.e.N4Figure() {
		c.verifierN4()
	}
}

// verifierR1 applique EX-11.10.
func (c *calcul) verifierR1() commun.Verification {
	parties := []struct {
		p   Partie
		nom string
	}{{c.e.Registre, "registre.json"}, {c.e.Certificat, "certificat-commit.json"}}
	var fr, en []string
	prerequis := false
	for _, x := range parties {
		switch x.p.Etat {
		case entree.Lu:
		case entree.TropGrand:
			fr, en = append(fr, x.nom+" dépasse 64 Mio (EX-4.13)"), append(en, x.nom+" exceeds 64 MiB (EX-4.13)")
		default:
			prerequis = true
		}
	}
	if len(fr) > 0 {
		return nouvelle("R-1", commun.Echoue, "", commun.T(strings.Join(fr, " ; "), strings.Join(en, "; ")))
	}
	if prerequis {
		return nouvelle("R-1", commun.NonExecute, commun.PrerequisEnEchec, commun.T("partie absente du répertoire ou illisible (D-2)", "part missing from the directory or unreadable (D-2)"))
	}
	entrees, d1 := lireRegistre(c.e.Registre.Octets)
	certs, d2 := lireCertificats(c.e.Certificat.Octets)
	c.entrees, c.certs = entrees, certs
	if d1 != nil || d2 != nil {
		var t commun.Texte
		for _, d := range []*commun.Texte{d1, d2} {
			if d != nil {
				t = t.Joindre(" ; ", "; ", *d)
			}
		}
		return nouvelle("R-1", commun.Echoue, "", t)
	}
	if d := apparier(c.entrees, c.certs); d != nil {
		return nouvelle("R-1", commun.Echoue, "", *d)
	}
	c.r1ok = true
	return nouvelle("R-1", commun.Reussi, "", commun.T(
		fmt.Sprintf("%d entrées et %d certificats conformes, appariés par hauteur", len(c.entrees), len(c.certs)),
		fmt.Sprintf("%d entries and %d certificates well-formed, matched by height", len(c.entrees), len(c.certs))))
}

// verifierCertificats applique R-2 à R-5 à chaque certificat.
func (c *calcul) verifierCertificats() {
	n := len(c.certs)
	c.r2, c.r4, c.r5 = make([]commun.Resultat, n), make([]commun.Resultat, n), make([]commun.Resultat, n)
	c.jeux, c.sig = make([]*ancres.JeuValidateurs, n), make([]resultatR5, n)
	d2, d3, d4, d5 := make([]commun.Texte, n), make([]commun.Texte, n), make([]commun.Texte, n), make([]commun.Texte, n)
	r3 := make([]commun.Resultat, n)
	// validateurs.json (R-3).
	var jeuxDeclares []ancres.JeuValidateurs
	r3Partie := commun.Resultat{}
	var d3Partie commun.Texte
	v := c.e.Validateurs
	switch {
	case !v.Presente:
		r := commun.PartieAbsente
		if v.RaisonAbsence == raisonHorsPerimetreCT1 {
			r = commun.HorsPerimetreVersion
		}
		r3Partie = ne(r)
		d3Partie = commun.T("validateurs.json absent ("+v.RaisonAbsence+")", "validateurs.json absent ("+v.RaisonAbsence+")")
	case v.Etat == entree.TropGrand:
		r3Partie = ko()
		d3Partie = commun.T("validateurs.json dépasse 1 Mio (EX-4.13)", "validateurs.json exceeds 1 MiB (EX-4.13)")
	case v.Etat != entree.Lu:
		r3Partie = ne(commun.PrerequisEnEchec)
		d3Partie = commun.T("validateurs.json absent du répertoire ou illisible (D-2)", "validateurs.json missing from the directory or unreadable (D-2)")
	default:
		j, d := lireValidateurs(v.Octets)
		if d != nil {
			r3Partie, d3Partie = ko(), *d
		} else {
			jeuxDeclares = j
		}
	}
	for i := range c.certs {
		ct := &c.certs[i]
		h := ct.hauteur
		// R-2.
		switch {
		case c.reg == nil:
			c.r2[i] = ne(commun.AncreAbsente)
			d2[i] = commun.T(fmt.Sprintf("bloc %d : aucune ancre registry", h), fmt.Sprintf("block %d: no registry anchor", h))
		default:
			jeu := c.reg.JeuPourHauteur(h)
			if jeu == nil {
				c.r2[i] = ne(commun.AncreAbsente)
				d2[i] = commun.T(fmt.Sprintf("bloc %d : l'ancre ne déclare aucun jeu pour cette hauteur", h), fmt.Sprintf("block %d: the anchor declares no set for this height", h))
				break
			}
			c.jeux[i] = jeu
			hj := hachageJeu(jeu)
			if hj == ct.valset {
				c.r2[i] = ok()
				d2[i] = commun.T(fmt.Sprintf("bloc %d : jeu %s, hachage %s égal à valsetHash", h, jeu.Pointeur, cryptographie.Hex32(hj)), fmt.Sprintf("block %d: set %s, hash %s equals valsetHash", h, jeu.Pointeur, cryptographie.Hex32(hj)))
			} else {
				c.r2[i] = ko()
				d2[i] = commun.T(fmt.Sprintf("bloc %d : jeu %s de hachage %s, valsetHash %s", h, jeu.Pointeur, cryptographie.Hex32(hj), cryptographie.Hex32(ct.valset)),
					fmt.Sprintf("block %d: set %s with hash %s, valsetHash %s", h, jeu.Pointeur, cryptographie.Hex32(hj), cryptographie.Hex32(ct.valset)))
			}
		}
		// R-3.
		if r3Partie.Statut != "" {
			r3[i] = r3Partie
		} else {
			r3[i], d3[i] = ko(), commun.T(fmt.Sprintf("bloc %d : aucun jeu déclaré de hachage égal à valsetHash pour cette hauteur", h), fmt.Sprintf("block %d: no declared set with a hash equal to valsetHash for this height", h))
			for k := range jeuxDeclares {
				j := &jeuxDeclares[k]
				if h >= j.De && (j.A == nil || h <= *j.A) && hachageJeu(j) == ct.valset {
					r3[i], d3[i] = ok(), commun.T(fmt.Sprintf("bloc %d : %s", h, j.Pointeur), fmt.Sprintf("block %d: %s", h, j.Pointeur))
					break
				}
			}
		}
		// R-4.
		switch {
		case c.reg == nil:
			c.r4[i] = ne(commun.AncreAbsente)
		case ct.chainID == c.reg.ChainID:
			c.r4[i] = ok()
			d4[i] = commun.T(fmt.Sprintf("bloc %d : chainId %s", h, ct.chainID), fmt.Sprintf("block %d: chainId %s", h, ct.chainID))
		default:
			c.r4[i] = ko()
			d4[i] = commun.T(fmt.Sprintf("bloc %d : chainId %q, l'ancre déclare %q", h, ct.chainID, c.reg.ChainID), fmt.Sprintf("block %d: chainId %q, the anchor declares %q", h, ct.chainID, c.reg.ChainID))
		}
		// R-5.
		if c.r2[i].Statut != commun.Reussi {
			c.r5[i] = ne(raisonDe(c.r2[i]))
			d5[i] = commun.T(fmt.Sprintf("bloc %d : R-2 non réussie", h), fmt.Sprintf("block %d: R-2 not passed", h))
			continue
		}
		s := verifierCertificat(ct, c.jeux[i])
		c.sig[i] = s
		d5[i] = s.detail
		if s.valide {
			c.r5[i] = ok()
		} else {
			c.r5[i] = ko()
		}
		for _, l := range s.nonCanonique {
			ligne, ligneEn := "proposition", "proposal"
			if l.indice > 0 {
				ligne, ligneEn = fmt.Sprintf("precommit %d", l.indice-1), fmt.Sprintf("precommit %d", l.indice-1)
			}
			c.avR5 = append(c.avR5, commun.Avertissement{ID: "AV-R-2", Verification: "R-5", Detail: commun.T(
				fmt.Sprintf("ligne de certificat acceptée sous une forme non canonique : bloc %d, %s (%s)", h, ligne, l.validateur),
				fmt.Sprintf("certificate line accepted in a non-canonical form: block %d, %s (%s)", h, ligneEn, l.validateur))})
		}
	}
	if c.reg == nil {
		d4 = []commun.Texte{commun.T("aucune ancre registry", "no registry anchor")}
	}
	if r3Partie.Statut != "" {
		d3 = []commun.Texte{d3Partie}
	}
	c.verifs["R-2"] = agreger("R-2", c.r2, d2)
	c.verifs["R-3"] = agreger("R-3", r3, d3)
	c.verifs["R-4"] = agreger("R-4", c.r4, d4)
	c.verifs["R-5"] = agreger("R-5", c.r5, d5)
}

// verifierEntrees applique R-6, R-7 et R-8 à chaque entrée.
func (c *calcul) verifierEntrees() {
	n := len(c.entrees)
	c.r6, c.r7 = make([]commun.Resultat, n), make([]commun.Resultat, n)
	r8 := make([]commun.Resultat, n)
	d6, d7, d8 := make([]commun.Texte, n), make([]commun.Texte, n), make([]commun.Texte, n)
	for i := range c.entrees {
		e := &c.entrees[i]
		h := e.bloc.numero
		ct := &c.certs[e.cert]
		// R-6.
		bft := hachageBFT(&e.bloc)
		switch {
		case bft == ct.bloc && bft == e.bloc.hachage && h == ct.hauteur:
			c.r6[i] = ok()
			d6[i] = commun.T(fmt.Sprintf("bloc %d : BFTBlockHash %s", h, cryptographie.Hex32(bft)), fmt.Sprintf("block %d: BFTBlockHash %s", h, cryptographie.Hex32(bft)))
		default:
			c.r6[i] = ko()
			d6[i] = commun.T(fmt.Sprintf("bloc %d (%s) : BFTBlockHash recalculé %s, blockHash du certificat %s, block.hash %s", h, e.role, cryptographie.Hex32(bft), cryptographie.Hex32(ct.bloc), e.bloc.hachageTexte),
				fmt.Sprintf("block %d (%s): recomputed BFTBlockHash %s, certificate blockHash %s, block.hash %s", h, e.role, cryptographie.Hex32(bft), cryptographie.Hex32(ct.bloc), e.bloc.hachageTexte))
		}
		// R-7.
		racine, okR := racineRecus(e.recus)
		switch {
		case okR && racine == e.bloc.recus:
			c.r7[i] = ok()
			d7[i] = commun.T(fmt.Sprintf("bloc %d : %d reçu(s), racine %s", h, len(e.recus), cryptographie.Hex32(racine)), fmt.Sprintf("block %d: %d receipt(s), root %s", h, len(e.recus), cryptographie.Hex32(racine)))
		default:
			c.r7[i] = ko()
			d7[i] = commun.T(fmt.Sprintf("bloc %d (%s) : racine recalculée %s, receiptsRoot %s", h, e.role, cryptographie.Hex32(racine), cryptographie.Hex32(e.bloc.recus)),
				fmt.Sprintf("block %d (%s): recomputed root %s, receiptsRoot %s", h, e.role, cryptographie.Hex32(racine), cryptographie.Hex32(e.bloc.recus)))
		}
		// R-8.
		switch {
		case c.r6[i].Statut != commun.Reussi || c.r7[i].Statut != commun.Reussi:
			r8[i] = ne(commun.PrerequisEnEchec)
			d8[i] = commun.T(fmt.Sprintf("bloc %d (%s) : R-6 ou R-7 non réussie", h, e.role), fmt.Sprintf("block %d (%s): R-6 or R-7 not passed", h, e.role))
		case c.reg == nil:
			r8[i] = ne(commun.AncreAbsente)
			d8[i] = commun.T(fmt.Sprintf("bloc %d (%s) : aucune ancre registry", h, e.role), fmt.Sprintf("block %d (%s): no registry anchor", h, e.role))
		default:
			attendu, nom := c.contratAttendu(e.role)
			j := e.journalProuve()
			if j.adresse == attendu {
				r8[i] = ok()
				d8[i] = commun.T(fmt.Sprintf("bloc %d (%s) : émis par %s %s", h, e.role, nom, hexA(attendu)), fmt.Sprintf("block %d (%s): emitted by %s %s", h, e.role, nom, hexA(attendu)))
			} else {
				r8[i] = ko()
				d8[i] = commun.T(fmt.Sprintf("bloc %d (%s) : émis par %s, l'ancre déclare %s %s", h, e.role, hexA(j.adresse), nom, hexA(attendu)),
					fmt.Sprintf("block %d (%s): emitted by %s, the anchor declares %s %s", h, e.role, hexA(j.adresse), nom, hexA(attendu)))
			}
		}
	}
	c.verifs["R-6"] = agreger("R-6", c.r6, d6)
	c.verifs["R-7"] = agreger("R-7", c.r7, d7)
	c.verifs["R-8"] = agreger("R-8", r8, d8)
}

// contratAttendu : adresse que l'ancre déclare pour un rôle (EX-11.17).
func (c *calcul) contratAttendu(role string) ([20]byte, string) {
	switch role {
	case roleCloture:
		return c.reg.PeriodRegistry, "PeriodRegistry"
	case roleInscription:
		return c.reg.RecorderRegistry, "RecorderRegistry"
	}
	return c.reg.AttestationRegistry, "AttestationRegistry"
}

func (c *calcul) r67(i int) bool {
	return c.r6[i].Statut == commun.Reussi && c.r7[i].Statut == commun.Reussi
}

// indiceRole rend la première entrée d'un rôle, ou -1.
func (c *calcul) indiceRole(role string) int {
	for i := range c.entrees {
		if c.entrees[i].role == role {
			return i
		}
	}
	return -1
}

// verifierR9 applique EX-11.18 aux entrées cloture et ancre.
func (c *calcul) verifierR9() commun.Verification {
	var res []commun.Resultat
	var det []commun.Texte
	m := c.e.Manifeste
	for i := range c.entrees {
		e := &c.entrees[i]
		if e.role != roleCloture && e.role != roleAncre {
			continue
		}
		h := e.bloc.numero
		if !m.Valide {
			res, det = append(res, ne(commun.PrerequisEnEchec)), append(det, commun.T(fmt.Sprintf("bloc %d (%s) : P-1 non réussie, periodHash non recalculé", h, e.role), fmt.Sprintf("block %d (%s): P-1 not passed, periodHash not recomputed", h, e.role)))
			continue
		}
		if !c.r67(i) {
			res, det = append(res, ne(commun.PrerequisEnEchec)), append(det, commun.T(fmt.Sprintf("bloc %d (%s) : R-6 ou R-7 non réussie", h, e.role), fmt.Sprintf("block %d (%s): R-6 or R-7 not passed", h, e.role)))
			continue
		}
		j := e.journalProuve()
		var defauts []commun.Texte
		ecart := func(champ, lu, attendu string) {
			defauts = append(defauts, commun.T(champ+" "+lu+" au lieu de "+attendu, champ+" "+lu+" instead of "+attendu))
		}
		if e.role == roleCloture {
			f := lireCloture(j)
			defauts = append(defauts, f.defauts...)
			if len(f.defauts) == 0 {
				ev := f.ev
				if ph := cryptographie.Hex32(m.PeriodHash); ev.PeriodHash != ph {
					ecart("topics[2] (periodHash)", ev.PeriodHash, ph)
				}
				for _, x := range []struct{ champ, lu, att string }{{"orgId", ev.OrgID, m.OrgID}, {"journalId", ev.JournalID, m.JournalID}, {"root", ev.Root, m.Root}} {
					if x.lu != x.att {
						ecart(x.champ, x.lu, x.att)
					}
				}
				for _, x := range []struct {
					champ   string
					lu, att int64
				}{{"periodStart", ev.PeriodStart, m.PeriodStart}, {"periodEnd", ev.PeriodEnd, m.PeriodEnd}, {"firstSeq", ev.FirstSeq, m.FirstSeq}, {"lastSeq", ev.LastSeq, m.LastSeq}, {"version", ev.Version, m.Version}} {
					if x.lu != x.att {
						ecart(x.champ, commun.Entier(x.lu), commun.Entier(x.att))
					}
				}
				if uint64(ev.PublishedAt) != e.bloc.horodatage {
					ecart("w9 (publishedAt)", commun.Entier(ev.PublishedAt), fmt.Sprint(e.bloc.horodatage))
				}
			}
		} else {
			f := lireAncre(j, true)
			defauts = append(defauts, f.defauts...)
			if len(f.defauts) == 0 {
				attendue, okE := empreinte(m.OrgID, m.JournalID, m.PeriodHash)
				if !okE {
					defauts = append(defauts, commun.T("org_id ou journal_id du manifeste illisibles", "unreadable org_id or journal_id of the manifest"))
				} else if f.ev.Fingerprint != cryptographie.Hex32(attendue) {
					ecart("topics[1] (empreinte)", f.ev.Fingerprint, cryptographie.Hex32(attendue))
				}
				if f.ev.DocType != hexDocTypePeriode {
					ecart("docType", f.ev.DocType, hexDocTypePeriode)
				}
			}
		}
		if len(defauts) > 0 {
			t := joindreDefauts(defauts)
			res, det = append(res, ko()), append(det, commun.T(fmt.Sprintf("bloc %d (%s) : %s", h, e.role, t.Fr), fmt.Sprintf("block %d (%s): %s", h, e.role, t.En)))
			continue
		}
		res, det = append(res, ok()), append(det, commun.T(fmt.Sprintf("bloc %d (%s) : valeurs de la période égales au manifeste", h, e.role), fmt.Sprintf("block %d (%s): period values equal the manifest", h, e.role)))
	}
	return agreger("R-9", res, det)
}

// empreinte rend keccak256(org_id ‖ journal_id ‖ h) (préimage de 96 octets,
// CT-1 §10.4 et §10.6).
func empreinte(org, journal string, h [32]byte) ([32]byte, bool) {
	o, ok1 := cryptographie.LireHex(org, 32)
	j, ok2 := cryptographie.LireHex(journal, 32)
	if !ok1 || !ok2 {
		return [32]byte{}, false
	}
	return cryptographie.Keccak256(o, j, h[:]), true
}

// clePubliqueDe rend la public_key d'un key_id de cles.json, ou "".
func (c *calcul) clePubliqueDe(kid string) string {
	for _, k := range c.e.Cles {
		if k.KeyID == kid {
			return k.ClePublique
		}
	}
	return ""
}

// verifierR10 applique EX-11.19.
func (c *calcul) verifierR10() commun.Verification {
	m := c.e.Manifeste
	var idx []int
	for i := range c.entrees {
		if c.entrees[i].role == roleInscription {
			idx = append(idx, i)
		}
	}
	switch {
	case !m.Valide:
		c.r10 = commun.NonExecute
		return nouvelle("R-10", commun.NonExecute, commun.PrerequisEnEchec, commun.T("P-1 non réussie : clé du manifeste non établie", "P-1 not passed: manifest key not established"))
	case !c.e.ClesExploitables:
		c.r10 = commun.NonExecute
		return nouvelle("R-10", commun.NonExecute, commun.PrerequisEnEchec, commun.T("cles.json ne remplit pas la première partie de E-8", "cles.json does not meet the first part of E-8"))
	}
	c.cleParPub = map[string]string{}
	for _, k := range c.e.Cles {
		if _, deja := c.cleParPub[k.ClePublique]; !deja {
			c.cleParPub[k.ClePublique] = k.KeyID
		}
	}
	cleMan := c.clePubliqueDe(m.RecorderKeyID)
	if len(idx) == 0 {
		c.r10 = commun.NonExecute
		c.avR = append(c.avR, c.avR1())
		return nouvelle("R-10", commun.NonExecute, commun.PartieAbsente, commun.T("registre.json ne porte aucune entrée inscription", "registre.json carries no inscription entry"))
	}
	var res []commun.Resultat
	var det []commun.Texte
	var duManifeste []int
	for _, i := range idx {
		e := &c.entrees[i]
		h := e.bloc.numero
		if !c.r67(i) {
			res, det = append(res, ne(commun.PrerequisEnEchec)), append(det, commun.T(fmt.Sprintf("bloc %d : R-6 ou R-7 non réussie", h), fmt.Sprintf("block %d: R-6 or R-7 not passed", h)))
			continue
		}
		f := lireInscription(e.journalProuve())
		defauts := f.defauts
		if len(defauts) == 0 {
			if f.ev.OrgID != m.OrgID {
				defauts = append(defauts, commun.T("topics[1] "+f.ev.OrgID+" différent de org_id du manifeste", "topics[1] "+f.ev.OrgID+" differs from the manifest org_id"))
			}
			if f.ev.JournalID != m.JournalID {
				defauts = append(defauts, commun.T("topics[3] "+f.ev.JournalID+" différent de journal_id du manifeste", "topics[3] "+f.ev.JournalID+" differs from the manifest journal_id"))
			}
			if _, connue := c.cleParPub[f.ev.Ed25519PubKey]; !connue {
				defauts = append(defauts, commun.T("clé Ed25519 "+f.ev.Ed25519PubKey+" absente de cles.json", "Ed25519 key "+f.ev.Ed25519PubKey+" not in cles.json"))
			}
		}
		if len(defauts) > 0 {
			t := joindreDefauts(defauts)
			res, det = append(res, ko()), append(det, commun.T(fmt.Sprintf("bloc %d : %s", h, t.Fr), fmt.Sprintf("block %d: %s", h, t.En)))
			continue
		}
		kid := c.cleParPub[f.ev.Ed25519PubKey]
		res, det = append(res, ok()), append(det, commun.T(fmt.Sprintf("bloc %d : %s sous la clé de chaîne %s", h, kid, f.ev.ChainKey), fmt.Sprintf("block %d: %s under chain key %s", h, kid, f.ev.ChainKey)))
		c.inscOK = append(c.inscOK, i)
		if cleMan != "" && f.ev.Ed25519PubKey == cleMan {
			duManifeste = append(duManifeste, i)
		}
	}
	// Règle de l'émetteur de l'ancre (clé du manifeste, CT-2 EX-11.19).
	if a := c.indiceRole(roleAncre); a >= 0 && c.r67(a) && len(duManifeste) > 0 {
		if em, okE := emetteurAncre(c.entrees[a].journalProuve()); okE {
			sous := -1
			for _, i := range duManifeste {
				if lireInscription(c.entrees[i].journalProuve()).cleChaine == em && sous < 0 {
					sous = i
				}
			}
			if sous < 0 {
				res = append(res, ko())
				det = append(det, commun.T(fmt.Sprintf("aucune inscription de %s sous l'émetteur de l'ancre %s, alors qu'il en existe sous d'autres clés de chaîne", m.RecorderKeyID, hexA(em)),
					fmt.Sprintf("no registration of %s under the anchor issuer %s, while some exist under other chain keys", m.RecorderKeyID, hexA(em))))
			} else {
				c.inscCleMan = sous
				for _, i := range duManifeste {
					f := lireInscription(c.entrees[i].journalProuve())
					if f.cleChaine != em {
						c.avR = append(c.avR, commun.Avertissement{ID: "AV-R-3", Verification: "R-10", Detail: commun.T(
							fmt.Sprintf("inscription de la clé du manifeste %s au bloc %d sous la clé de chaîne %s, autre que l'émetteur de l'ancre %s", m.RecorderKeyID, c.entrees[i].bloc.numero, f.ev.ChainKey, hexA(em)),
							fmt.Sprintf("registration of the manifest key %s in block %d under chain key %s, other than the anchor issuer %s", m.RecorderKeyID, c.entrees[i].bloc.numero, f.ev.ChainKey, hexA(em)))})
					}
				}
			}
		}
	}
	if len(duManifeste) == 0 {
		c.avR = append(c.avR, c.avR1())
	}
	v := agreger("R-10", res, det)
	c.r10 = v.Statut
	return v
}

func (c *calcul) avR1() commun.Avertissement {
	kid := c.e.Manifeste.RecorderKeyID
	em := ""
	if a := c.indiceRole(roleAncre); a >= 0 {
		if x, okE := emetteurAncre(c.entrees[a].journalProuve()); okE {
			em = " " + hexA(x)
		}
	}
	return commun.Avertissement{ID: "AV-R-1", Verification: "R-10", Detail: commun.T(
		"aucune inscription de la clé du manifeste "+kid+" : l'émetteur de l'ancre"+em+" n'est relié à aucune clé d'enregistreur",
		"no registration of the manifest key "+kid+": the anchor issuer"+em+" is tied to no recorder key")}
}

// verifierR11 applique EX-11.24. R-11 figure au rapport avec la partie
// points-de-controle.json (Entree.Point non nil) ou une entrée
// ancre_point_de_controle.
func (c *calcul) verifierR11() {
	c.pointIdx = c.indiceRole(rolePoint)
	pt := c.e.Point
	if c.pointIdx < 0 {
		if pt != nil || c.e.PointDeclare {
			v := nouvelle("R-11", commun.NonExecute, commun.PartieAbsente, commun.T("registre.json ne porte aucune entrée ancre_point_de_controle", "registre.json carries no ancre_point_de_controle entry"))
			c.r11 = &v
			c.verifs["R-11"] = v
		}
		return
	}
	e := &c.entrees[c.pointIdx]
	h := e.bloc.numero
	if !c.r67(c.pointIdx) {
		v := nouvelle("R-11", commun.NonExecute, commun.PrerequisEnEchec, commun.T(fmt.Sprintf("bloc %d : R-6 ou R-7 non réussie", h), fmt.Sprintf("block %d: R-6 or R-7 not passed", h)))
		c.r11 = &v
		c.verifs["R-11"] = v
		return
	}
	j := e.journalProuve()
	f := lireAncre(j, false)
	var fr, en []string
	echec := false
	// Règle 1 : forme.
	defauts := f.defauts
	if len(f.defauts) == 0 && f.ev.DocType != DocTypePoint {
		lib, libEn := "autre", "other"
		if f.ev.DocType == hexDocTypePeriode {
			lib, libEn = "de période", "of a period"
		}
		defauts = append(defauts, commun.T("docType "+f.ev.DocType+" ("+lib+") au lieu de celui d'un point de contrôle", "docType "+f.ev.DocType+" ("+libEn+") instead of a checkpoint's"))
	}
	if len(defauts) > 0 {
		echec = true
		t := joindreDefauts(defauts)
		fr, en = append(fr, "règle 1 : "+t.Fr), append(en, "rule 1: "+t.En)
	} else {
		fr, en = append(fr, fmt.Sprintf("bloc %d, émetteur %s, docType %s", h, f.ev.Issuer, f.ev.DocType)), append(en, fmt.Sprintf("block %d, issuer %s, docType %s", h, f.ev.Issuer, f.ev.DocType))
	}
	// Règle 2 : rattachement à la partie.
	var raison commun.Raison
	switch {
	case pt == nil && c.e.PointDeclare:
		// Partie déclarée présente mais K-1 en échec : la règle 2 ne peut
		// pas rattacher l'entrée (EX-11.24, EX-5.9).
		raison = commun.PrerequisEnEchec
		fr, en = append(fr, "règle 2 : K-1 non réussie"), append(en, "rule 2: K-1 not passed")
	case pt == nil || pt.Reference == nil:
		raison = commun.PartieAbsente
		fr, en = append(fr, "entrée sans partie points-de-controle.json à rattacher"), append(en, "entry with no points-de-controle.json part to attach")
	case !pt.K2:
		raison = commun.PrerequisEnEchec
		fr, en = append(fr, "règle 2 : K-2 non réussie"), append(en, "rule 2: K-2 not passed")
	default:
		ref := pt.Reference
		var d []commun.Texte
		att, okE := empreinte(c.e.OrgID, c.e.JournalID, pt.CheckpointHash)
		switch {
		case !okE:
			d = append(d, commun.T("org_id ou journal_id de l'événement illisibles", "unreadable org_id or journal_id of the event"))
		case len(j.sujets) < 2 || j.sujets[1] != att:
			d = append(d, commun.T("topics[1] différent de l'empreinte du point "+cryptographie.Hex32(att), "topics[1] differs from the checkpoint fingerprint "+cryptographie.Hex32(att)))
		}
		if ref.BlockNumber < 0 || uint64(ref.BlockNumber) != h {
			d = append(d, commun.T(fmt.Sprintf("bloc %d au lieu de block_number %d", h, ref.BlockNumber), fmt.Sprintf("block %d instead of block_number %d", h, ref.BlockNumber)))
		}
		if e.bloc.hachageTexte != ref.BlockHash {
			d = append(d, commun.T("block.hash différent de block_hash", "block.hash differs from block_hash"))
		}
		if e.hachageTx != ref.TransactionHash {
			d = append(d, commun.T("transaction_hash différent de celui de la partie", "transaction_hash differs from the part's"))
		}
		if int64(e.indiceJournal) != ref.LogIndex {
			d = append(d, commun.T(fmt.Sprintf("log_index %d au lieu de %d", e.indiceJournal, ref.LogIndex), fmt.Sprintf("log_index %d instead of %d", e.indiceJournal, ref.LogIndex)))
		}
		if len(d) > 0 {
			echec = true
			t := joindreDefauts(d)
			fr, en = append(fr, "règle 2 : "+t.Fr), append(en, "rule 2: "+t.En)
		} else {
			c.rattachee = true
			fr, en = append(fr, "rattachée à la référence de la partie"), append(en, "attached to the part's reference")
		}
	}
	// Règle 3 : émetteur relié à une inscription de la clé du point.
	if pt != nil && len(f.defauts) == 0 {
		cle := c.clePubliqueDe(pt.KeyID)
		var chaines [][20]byte
		if c.r10 == commun.Reussi && cle != "" {
			for _, i := range c.inscOK {
				g := lireInscription(c.entrees[i].journalProuve())
				if g.ev.Ed25519PubKey == cle {
					chaines = append(chaines, g.cleChaine)
				}
			}
		}
		r10 := c.verifs["R-10"]
		switch {
		case r10.Statut != commun.Reussi && !(r10.Statut == commun.NonExecute && r10.Raison == commun.PartieAbsente):
			// R-10 en échec ou non exécutée faute de prérequis : les
			// inscriptions du dossier ne sont pas prouvées, la règle 3 ne
			// s'applique pas (EX-5.5).
			raison = commun.PremiereRaison(raison, commun.PrerequisEnEchec)
			fr, en = append(fr, "règle 3 : R-10 non réussie"), append(en, "rule 3: R-10 not passed")
		case len(chaines) == 0:
			c.avR11 = append(c.avR11, commun.Avertissement{ID: "AV-K-3", Verification: "R-11", Detail: commun.T(
				"émetteur "+f.ev.Issuer+" de l'ancre du point relié à aucune inscription de la clé "+pt.KeyID+" dans le dossier",
				"issuer "+f.ev.Issuer+" of the checkpoint anchor tied to no registration of key "+pt.KeyID+" in the dossier")})
		default:
			relie := false
			for _, ck := range chaines {
				if ck == f.emetteur {
					relie = true
				}
			}
			if relie {
				fr, en = append(fr, "émetteur inscrit pour "+pt.KeyID), append(en, "issuer registered for "+pt.KeyID)
			} else {
				echec = true
				fr, en = append(fr, "règle 3 : émetteur "+f.ev.Issuer+" sous aucune inscription de "+pt.KeyID), append(en, "rule 3: issuer "+f.ev.Issuer+" under no registration of "+pt.KeyID)
			}
		}
	}
	d := commun.T(strings.Join(fr, " ; "), strings.Join(en, "; "))
	var v commun.Verification
	switch {
	case echec:
		c.rattachee = false
		v = nouvelle("R-11", commun.Echoue, "", d)
	case raison != "":
		v = nouvelle("R-11", commun.NonExecute, raison, d)
	default:
		v = nouvelle("R-11", commun.Reussi, "", d)
	}
	c.r11 = &v
	c.verifs["R-11"] = v
}

// verifierN4 applique EX-12.5 (N-4 figure : N4Figure).
func (c *calcul) verifierN4() {
	m := c.e.Manifeste
	en := c.e.Ancres.CleChainePour(m.OrgID, m.JournalID, m.RecorderKeyID)
	set := func(v commun.Verification) { c.n4 = &v }
	a := c.indiceRole(roleAncre)
	if a < 0 || !c.r67(a) {
		set(nouvelle("N-4", commun.NonExecute, commun.PrerequisEnEchec, commun.T("l'entrée ancre n'a pas passé R-6 et R-7", "the ancre entry did not pass R-6 and R-7")))
		return
	}
	if r := c.r5[c.entrees[a].cert]; r.Statut != commun.Reussi {
		set(nouvelle("N-4", commun.NonExecute, raisonDe(r), commun.T("R-5 non réussie pour le certificat du bloc de l'ancre : émetteur non authentifié", "R-5 not passed for the certificate of the anchor block: issuer not authenticated")))
		return
	}
	c.recorder = en.Pointeur
	em, okE := emetteurAncre(c.entrees[a].journalProuve())
	if !okE {
		set(nouvelle("N-4", commun.Echoue, "", commun.T("journal de l'ancre sans émetteur (moins de 3 sujets)", "anchor log without issuer (fewer than 3 topics)")))
		return
	}
	if hexA(em) == en.CleChaine {
		set(nouvelle("N-4", commun.Reussi, "", commun.T("émetteur de l'ancre "+hexA(em)+" égal à la clé de chaîne de "+m.RecorderKeyID+" ("+en.Pointeur+")", "anchor issuer "+hexA(em)+" equals the chain key of "+m.RecorderKeyID+" ("+en.Pointeur+")")))
		return
	}
	set(nouvelle("N-4", commun.Echoue, "", commun.T("émetteur de l'ancre "+hexA(em)+", l'ancre déclare "+en.CleChaine+" pour "+m.RecorderKeyID+" ("+en.Pointeur+")", "anchor issuer "+hexA(em)+", the anchor declares "+en.CleChaine+" for "+m.RecorderKeyID+" ("+en.Pointeur+")")))
}

// verifierK8 applique EX-11.25 (référence non nulle, K-2 réussie).
func (c *calcul) verifierK8() {
	pt := c.e.Point
	ref := pt.Reference
	set := func(v commun.Verification) { c.k8 = &v }
	att, okE := empreinte(c.e.OrgID, c.e.JournalID, pt.CheckpointHash)
	if !okE {
		set(nouvelle("K-8", commun.NonExecute, commun.PrerequisEnEchec, commun.T("org_id ou journal_id de l'événement illisibles : empreinte non recalculée", "unreadable org_id or journal_id of the event: fingerprint not recomputed")))
		return
	}
	var fr, en []string
	if ref.Fingerprint != cryptographie.Hex32(att) {
		fr, en = append(fr, "fingerprint "+ref.Fingerprint+" au lieu de "+cryptographie.Hex32(att)), append(en, "fingerprint "+ref.Fingerprint+" instead of "+cryptographie.Hex32(att))
	} else if att == ([32]byte{}) {
		fr, en = append(fr, "empreinte nulle"), append(en, "null fingerprint")
	}
	if ref.DocType != DocTypePoint {
		fr, en = append(fr, "doc_type "+ref.DocType+" au lieu de "+DocTypePoint), append(en, "doc_type "+ref.DocType+" instead of "+DocTypePoint)
	}
	if c.reg != nil {
		if a := hexA(c.reg.AttestationRegistry); ref.Contract != a {
			fr, en = append(fr, "contract "+ref.Contract+" au lieu de attestation_registry "+a), append(en, "contract "+ref.Contract+" instead of attestation_registry "+a)
		}
	}
	switch {
	case len(fr) > 0:
		set(nouvelle("K-8", commun.Echoue, "", commun.T(strings.Join(fr, " ; "), strings.Join(en, "; "))))
	case c.reg == nil:
		set(nouvelle("K-8", commun.NonExecute, commun.AncreAbsente, commun.T("empreinte et doc_type recalculés égaux ; aucune ancre registry pour comparer contract", "fingerprint and doc_type equal the recomputed values; no registry anchor to compare contract")))
	default:
		set(nouvelle("K-8", commun.Reussi, "", commun.T("empreinte "+ref.Fingerprint+", doc_type du point, contract "+ref.Contract+" (attestation_registry de l'ancre)", "fingerprint "+ref.Fingerprint+", checkpoint doc_type, contract "+ref.Contract+" (attestation_registry of the anchor)")))
	}
}

// synthese : statut du contrôle (EX-11.20), faits, proposition, résumé,
// avertissements et ancres employées.
func (c *calcul) synthese(res *Resultat) {
	presentes := c.e.PartiesPresentes()
	// Statut.
	switch {
	case !presentes:
		res.Statut, res.Raison = commun.NonExecute, commun.PartieAbsente
		if c.k8 != nil && c.k8.Statut == commun.Echoue {
			res.Statut, res.Raison = commun.Echoue, ""
		}
	default:
		echec := false
		for _, v := range res.Verifications {
			if v.Statut == commun.Echoue {
				echec = true
			}
		}
		for _, v := range []*commun.Verification{c.n4, c.k8} {
			if v != nil && v.Statut == commun.Echoue {
				echec = true
			}
		}
		if echec {
			res.Statut = commun.Echoue
			break
		}
		var rs []commun.Resultat
		for _, id := range []string{"R-1", "R-2", "R-4", "R-5", "R-6", "R-7", "R-8", "R-9"} {
			v := c.verifs[id]
			rs = append(rs, commun.Resultat{Statut: v.Statut, Raison: v.Raison})
		}
		res.Statut, res.Raison = commun.Agreger(rs)
	}
	reussi := presentes && res.Statut == commun.Reussi
	// K-8 : faits du point et AV-K-1.
	if c.k8 != nil {
		rattachee := presentes && c.r11 != nil && c.r11.Statut == commun.Reussi && c.rattachee
		if c.k8.Statut == commun.Reussi {
			ref := c.e.Point.Reference
			fp := &FaitsAncrePoint{ChainIDDeclared: ref.ChainID, Contract: ref.Contract, Fingerprint: ref.Fingerprint, DocType: ref.DocType,
				BlockNumber: ref.BlockNumber, BlockHash: ref.BlockHash, TransactionHashDeclared: ref.TransactionHash, LogIndex: ref.LogIndex, Inclusion: "declarative"}
			if rattachee && reussi {
				e := &c.entrees[c.pointIdx]
				bt := commun.FormaterSecondes(int64(e.bloc.horodatage))
				iss := lireAncre(e.journalProuve(), false).ev.Issuer
				fp.Inclusion, fp.BlockTime, fp.Issuer = "prouvee", &bt, &iss
			}
			res.FaitsPoint = fp
		}
		// AV-K-1 qualifie une référence que K-8 a acceptée : levé seulement
		// quand K-8 a réussi (EX-11.25, révision 0.4) ; K-8 en échec ou non
		// exécutée ne le lève pas, quelle que soit la présence des parties
		// du contrôle 8.
		admise := c.r11 != nil && c.r11.Statut == commun.NonExecute && c.r11.Raison.Admise()
		if c.k8.Statut == commun.Reussi && (!presentes || admise) {
			c.avK1 = append(c.avK1, commun.Avertissement{ID: "AV-K-1", Verification: "K-8", Detail: commun.T(
				"référence au registre du point déclarative : aucune entrée ancre_point_de_controle de registre.json rattachée par R-11, l'inclusion de l'ancre du point n'est pas prouvée",
				"declarative registry reference of the checkpoint: no ancre_point_de_controle entry of registre.json attached by R-11, the inclusion of the checkpoint anchor is not proven")})
		}
	}
	// Avertissements, dans l'ordre des vérifications qui les lèvent.
	res.Avertissements = append(res.Avertissements, c.avK1...)
	res.Avertissements = append(res.Avertissements, c.avR5...)
	res.Avertissements = append(res.Avertissements, c.avR...)
	res.Avertissements = append(res.Avertissements, c.avR11...)
	// Ancres employées.
	if presentes && c.r1ok && c.reg != nil {
		res.AncresEmployees = append(res.AncresEmployees, "/registry")
		vus := map[string]bool{}
		var ptrs []string
		for _, j := range c.jeux {
			if j != nil && !vus[j.Pointeur] {
				vus[j.Pointeur] = true
				ptrs = append(ptrs, j.Pointeur)
			}
		}
		sort.Strings(ptrs)
		res.AncresEmployees = append(res.AncresEmployees, ptrs...)
	}
	if c.recorder != "" {
		res.AncresEmployees = append(res.AncresEmployees, c.recorder)
	}
	if !reussi {
		return
	}
	res.Faits = c.faits()
	if c.r10 == commun.Reussi {
		for _, i := range c.inscOK {
			f := lireInscription(c.entrees[i].journalProuve())
			res.Inscriptions = append(res.Inscriptions, Inscription{ClePublique: f.ev.Ed25519PubKey, CleChaine: f.ev.ChainKey, Bloc: int64(c.entrees[i].bloc.numero)})
		}
	}
	res.Proposition = c.proposition()
	res.Resume = c.resume()
}

// faits rend facts.registry (EX-11.21).
func (c *calcul) faits() *Faits {
	f := &Faits{ChainID: c.reg.ChainID, Entries: []EntreeFaits{}, Certificates: []CertificatFaits{}}
	for i := range c.entrees {
		e := &c.entrees[i]
		j := e.journalProuve()
		f.Entries = append(f.Entries, EntreeFaits{Role: e.role, BlockNumber: int64(e.bloc.numero), BlockHash: e.bloc.hachageTexte,
			BlockTime: commun.FormaterSecondes(int64(e.bloc.horodatage)), TransactionIndex: int64(e.indiceTx),
			TransactionHashDeclared: e.hachageTx, Emitter: hexA(j.adresse), Event: evenement(e)})
	}
	for i := range c.certs {
		jeu := c.jeux[i]
		sg := append([]string{}, c.sig[i].signataires...)
		f.Certificates = append(f.Certificates, CertificatFaits{Height: int64(c.certs[i].hauteur), ValsetHash: cryptographie.Hex32(c.certs[i].valset),
			SetSource: jeu.Source, SetSize: len(jeu.Validateurs), Quorum: quorum(len(jeu.Validateurs)), Signers: sg})
	}
	return f
}
