// Paquet moteur : enchaîne la vérification d'un dossier dans l'ordre de
// CT-6 EX-5.2, isole chaque étape (une panique devient une erreur interne,
// code 2, EX-15.2), calcule les statuts des contrôles (§6.3), le verdict
// (§6.4), les faits (§6.7), l'énoncé (§6.5) et la borne (§6.6), et produit
// le rapport du paquet rapport.
package moteur

import (
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/noorfinances-eng/noortrace/verificateur/ancres"
	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/cryptographie"
	"github.com/noorfinances-eng/noortrace/verificateur/dossier"
	"github.com/noorfinances-eng/noortrace/verificateur/entree"
	"github.com/noorfinances-eng/noortrace/verificateur/horodatage"
	"github.com/noorfinances-eng/noortrace/verificateur/jcs"
	"github.com/noorfinances-eng/noortrace/verificateur/jsonv"
	"github.com/noorfinances-eng/noortrace/verificateur/ots"
	"github.com/noorfinances-eng/noortrace/verificateur/rapport"
	"github.com/noorfinances-eng/noortrace/verificateur/registre"
	"github.com/noorfinances-eng/noortrace/verificateur/schema"
)

// Nom du binaire (CT-8, EX-8.1).
const Nom = "noortrace-verifier"

// Options : la ligne de commande, une fois analysée (CT-6 §8.2).
type Options struct {
	Repertoire      string
	Ancres          string
	Entetes         string
	Pieces          string
	SecondManifeste string
	// Exiger : contrôles exigés, croissants, sans doublon.
	Exiger []int
	// Langue : « fr » ou « en ».
	Langue string
	// Version : version du binaire (main.version).
	Version string
}

// Erreur : entrée inutilisable (code 2, CT-6 §8.3, EX-8.4).
type Erreur struct {
	// Genre : error.kind.
	Genre string
	// Message : error.message.
	Message commun.Texte
	// Verification : error.check (« N-1 », « N-2 ») ou "".
	Verification string
}

// Resultat : le résultat d'une exécution.
type Resultat struct {
	// Erreur : non nil pour le code 2 ; Rapport est alors nil.
	Erreur *Erreur
	// Rapport : rapport des codes 0, 1 et 3.
	Rapport *rapport.Rapport
	// Entrees : inputs (aussi pour un rapport d'erreur, quand connues).
	Entrees *rapport.Entrees
	// Verifs : toutes les vérifications dans l'ordre du rapport, y compris
	// celles que les paquets provisoires laissent « a_construire ».
	Verifs []commun.Verification
	// Controles : statut et raison internes des huit contrôles (index 1 à
	// 8), raison AConstruire comprise.
	Controles [9]commun.Resultat
	// AConstruire : vérifications laissées à construire par un paquet
	// provisoire ; non vide, l'exécution rend une erreur interne.
	AConstruire []string
	// Avertissements : dans l'ordre d'EX-6.15.
	Avertissements []commun.Avertissement
	// Verdict et Code (0, 1, 2 ou 3).
	Verdict string
	Code    int
}

// Verificateur rend le bloc `verifier` du rapport (EX-8.7, EX-8.11).
func Verificateur(version string) (rapport.Verificateur, error) {
	v := rapport.Verificateur{Name: Nom, Implementation: "binaire_go", Version: version, Runtime: runtime.Version()}
	liste, err := schema.Liste()
	if err != nil {
		return v, err
	}
	for _, s := range liste {
		v.Schemas = append(v.Schemas, rapport.Schema{ID: s.ID, Sha256: s.Sha256})
	}
	return v, nil
}

// isoler exécute une étape et rend une panique comme erreur interne
// (EX-15.2) : jamais comme un statut, jamais comme un plantage.
func isoler(etape string, f func()) (err *Erreur) {
	defer func() {
		if p := recover(); p != nil {
			err = &Erreur{Genre: "erreur_interne", Message: commun.T(
				fmt.Sprintf("erreur interne du vérificateur pendant %s : %v", etape, p),
				fmt.Sprintf("internal verifier error during %s: %v", etape, p))}
		}
	}()
	f()
	return nil
}

// Verifier exécute la vérification complète.
func Verifier(o Options) (res *Resultat) {
	res = &Resultat{}
	rep, _ := filepath.Abs(o.Repertoire)
	ent := &rapport.Entrees{Dossier: rapport.EntreeDossier{Path: rep}, RequiredControls: append([]int{}, o.Exiger...)}
	res.Entrees = ent
	echec := func(e *Erreur) *Resultat {
		res.Erreur = e
		res.Code = 2
		return res
	}
	// Étape 1 : fichier d'ancres (N-1), fichier d'en-têtes (N-2), autres
	// entrées à part (EX-4.12).
	var anc *ancres.Ancres
	if o.Ancres != "" {
		chemin, _ := filepath.Abs(o.Ancres)
		var d *ancres.Defaut
		if e := isoler("la lecture du fichier d'ancres", func() { anc, d = ancres.Lire(chemin, horodatage.ControleurAncres{}) }); e != nil {
			return echec(e)
		}
		if d != nil {
			return echec(&Erreur{Genre: d.Genre, Message: d.Message, Verification: d.Verification})
		}
		ent.Anchors = &rapport.FichierLu{Path: chemin, Sha256: cryptographie.Hex32(anc.Sha256)}
	}
	var hdr *ancres.Entetes
	if o.Entetes != "" {
		chemin, _ := filepath.Abs(o.Entetes)
		var d *ancres.Defaut
		if e := isoler("la lecture du fichier d'en-têtes", func() { hdr, d = ancres.LireEntetes(chemin) }); e != nil {
			return echec(e)
		}
		if d != nil {
			return echec(&Erreur{Genre: d.Genre, Message: d.Message, Verification: d.Verification})
		}
		ent.BitcoinHeaders = &rapport.FichierLu{Path: chemin, Sha256: cryptographie.Hex32(hdr.Sha256)}
	}
	var second *jsonv.Valeur
	if o.SecondManifeste != "" {
		chemin, _ := filepath.Abs(o.SecondManifeste)
		l := entree.Lire(chemin, entree.LimiteSecondManifeste)
		switch l.Etat {
		case entree.Absent, entree.Illisible:
			return echec(&Erreur{Genre: "entree_illisible", Message: commun.T(fmt.Sprintf("second manifeste illisible (%v)", l.Err), fmt.Sprintf("second manifest unreadable (%v)", l.Err))})
		case entree.TropGrand:
			return echec(&Erreur{Genre: "taille_depassee", Message: commun.T("second manifeste de plus de 1 Mio", "second manifest larger than 1 MiB")})
		}
		// EX-4.12, point 3, et EX-4.16 (révision 0.4) : un second manifeste
		// qui n'est pas du JSON, ou du JSON sans forme canonique, rend
		// l'entrée inutilisable (code 2, entree_illisible) ; la forme
		// canonique se contrôle avant le schéma.
		v, err := jsonv.Analyser(l.Octets)
		if err == nil {
			if e := jcs.Calculable(v); e != nil {
				return echec(&Erreur{Genre: "entree_illisible", Message: commun.T("second manifeste sans forme canonique de CT-1 §4 ("+e.Error()+")", "second manifest without CT-1 §4 canonical form ("+e.Error()+")")})
			}
			err = schema.Valider(schema.Manifeste, v)
		}
		if err == nil {
			if _, ok := commun.LireHorodatage(v.Membre("generated_at").S()); !ok {
				err = fmt.Errorf("generated_at n'est pas une date existante")
			}
		}
		if err != nil {
			return echec(&Erreur{Genre: "entree_illisible", Message: commun.T("second manifeste non conforme au schéma manifeste-v0 ("+err.Error()+")", "second manifest does not follow the manifeste-v0 schema ("+err.Error()+")")})
		}
		second = v
		ent.SecondManifest = &rapport.FichierLu{Path: chemin, Sha256: cryptographie.Hex32(l.Sha256)}
	}
	pieces := ""
	if o.Pieces != "" {
		pieces, _ = filepath.Abs(o.Pieces)
		if !entree.EstRepertoire(pieces) {
			return echec(&Erreur{Genre: "entree_illisible", Message: commun.T("--pieces ne désigne pas un répertoire lisible : "+pieces, "--pieces does not designate a readable directory: "+pieces)})
		}
	}
	// Étape 2 : dossier.json.
	var dos *dossier.Dossier
	var dd *dossier.Defaut
	if e := isoler("la lecture de dossier.json", func() { dos, dd = dossier.Ouvrir(rep) }); e != nil {
		return echec(e)
	}
	if dd != nil {
		return echec(&Erreur{Genre: dd.Genre, Message: dd.Message})
	}
	if dos.Index != nil {
		h := cryptographie.Hex32(dos.IndexSha256)
		ent.Dossier.IndexSha256 = &h
	}
	// Étape 3 : vérifications de CT-1.
	var an *dossier.Analyse
	if e := isoler("les vérifications de CT-1", func() {
		an, dd = dossier.Analyser(dos, dossier.Options{RepertoirePieces: pieces, SecondManifeste: second})
	}); e != nil {
		return echec(e)
	}
	if dd != nil {
		return echec(&Erreur{Genre: dd.Genre, Message: dd.Message})
	}
	if pieces != "" {
		ent.Pieces = &rapport.EntreePieces{Path: pieces, Files: an.PiecesLues()}
	}
	// Étapes 4 à 6.
	c := &calcul{o: o, res: res, anc: anc, hdr: hdr, an: an, dos: dos}
	if e := isoler("les contrôles 4, 5 et 8", c.controlesReserves); e != nil {
		return echec(e)
	}
	if e := isoler("la synthèse du rapport", c.synthese); e != nil {
		return echec(e)
	}
	if len(res.AConstruire) > 0 {
		return echec(&Erreur{Genre: "erreur_interne", Message: commun.T(
			"binaire provisoire : les vérifications "+strings.Join(res.AConstruire, ", ")+" sont à construire (contrôles 4, 5 et 8, CT-6 §9 à §11) ; aucun verdict n'est rendu sur un dossier qui porte ces parties",
			"provisional binary: checks "+strings.Join(res.AConstruire, ", ")+" are still to be built (controls 4, 5 and 8, CT-6 §9 to §11); no verdict is given on a dossier carrying these parts")})
	}
	return res
}

// calcul : état partagé des étapes 4 à 6.
type calcul struct {
	o   Options
	res *Resultat
	anc *ancres.Ancres
	hdr *ancres.Entetes
	an  *dossier.Analyse
	dos *dossier.Dossier

	// Contrôle 4
	partie4 *dossier.Partie
	jeton   *horodatage.Resultat
	jetonPt *horodatage.Resultat
	k7      *commun.Verification
	// Contrôle 5
	partie5  *dossier.Partie
	preuve   *ots.Resultat
	preuvePt *ots.Resultat
	k9       *commun.Verification
	// Contrôle 8
	reg  *registre.Resultat
	reg8 bool
	k8   *commun.Verification
	// N-3
	n3 ancres.ResultatN3
	// Avertissements par vérification.
	avert []commun.Avertissement
}

func (c *calcul) pointPrerequis(id string, controle int) *commun.Verification {
	pt := c.an.Point
	var v commun.Verification
	switch {
	case !pt.K1:
		v = commun.Nouvelle(id, commun.NonExecute, commun.PrerequisEnEchec, commun.T("K-1 non réussie", "K-1 not passed"), controle)
	case !pt.K2:
		v = commun.Nouvelle(id, commun.NonExecute, commun.PrerequisEnEchec, commun.T("K-2 non réussie", "K-2 not passed"), controle)
	default:
		return nil
	}
	return &v
}

func ancreNulle(id string, controle int) *commun.Verification {
	v := commun.Nouvelle(id, commun.NonExecute, commun.PartieAbsente, commun.T("ancre nulle dans anchors", "null anchor in anchors"), controle)
	return &v
}

func resumeStatuts(vs []commun.Verification) string {
	var p []string
	for _, v := range vs {
		s := v.ID + " " + string(v.Statut)
		if v.Statut == commun.NonExecute {
			s += " (" + string(v.Raison) + ")"
		}
		p = append(p, s)
	}
	return strings.Join(p, " ; ")
}

func (c *calcul) controlesReserves() {
	an := c.an
	ev := an.Evenement
	// --- Contrôle 4 et K-7 ---
	c.partie4 = c.dos.Partie(dossier.PJeton)
	baseH := horodatage.Entree{Ancres: c.anc}
	if ev != nil {
		baseH.TsEvenement, baseH.TsDisponible = ev.Ts()
	}
	if c.partie4 != nil && c.partie4.Present {
		e := baseH
		e.Usage = horodatage.Cloture
		e.Jeton, e.Etat = c.partie4.Lecture.Octets, c.partie4.Lecture.Etat
		e.EmpreinteAttendue, e.EmpreinteDisponible = an.PeriodHash, an.P1
		r := horodatage.Verifier(e)
		c.jeton = &r
	}
	if pt := an.Point; pt != nil {
		if v := c.pointPrerequis("K-7", 4); v != nil {
			c.k7 = v
		} else if pt.JetonBase64 == "" {
			c.k7 = ancreNulle("K-7", 4)
		} else if b, err := cryptographie.Base64Canonique(pt.JetonBase64); err != nil || len(b) > entree.LimiteJeton {
			v := commun.Nouvelle("K-7", commun.Echoue, "", commun.T("jeton du point inexploitable (base64 non canonique ou plus de 64 Kio)", "checkpoint token unusable (non-canonical base64 or more than 64 KiB)"), 4)
			c.k7 = &v
		} else {
			e := baseH
			e.Usage = horodatage.Point
			e.Jeton, e.Etat = b, entree.Lu
			e.EmpreinteAttendue, e.EmpreinteDisponible = pt.CheckpointHash, true
			e.CheckpointTs = pt.CheckpointTs
			r := horodatage.Verifier(e)
			c.jetonPt = &r
			d := commun.T(resumeStatuts(r.Verifications), resumeStatuts(r.Verifications))
			if r.Statut == commun.Reussi && !r.Resume.Vide() {
				d = d.Joindre(" ; ", "; ", r.Resume)
			}
			v := commun.Nouvelle("K-7", r.Statut, r.Raison, d, 4)
			c.k7 = &v
			for _, a := range r.Avertissements {
				a.Verification = "K-7"
				c.avert = append(c.avert, a)
			}
		}
	}
	// --- Contrôle 5 et K-9 ---
	c.partie5 = c.dos.Partie(dossier.PPreuveOTS)
	baseO := ots.Entree{Entetes: c.hdr}
	if c.anc != nil {
		baseO.Ancre = c.anc.Bitcoin
	}
	if c.partie5 != nil && c.partie5.Present {
		e := baseO
		e.Usage = ots.Cloture
		e.Preuve, e.Etat = c.partie5.Lecture.Octets, c.partie5.Lecture.Etat
		e.EmpreinteAttendue, e.EmpreinteDisponible = an.PeriodHash, an.P1
		r := ots.Verifier(e)
		c.preuve = &r
	}
	if pt := an.Point; pt != nil {
		if v := c.pointPrerequis("K-9", 5); v != nil {
			c.k9 = v
		} else if pt.PreuveBase64 == "" {
			c.k9 = ancreNulle("K-9", 5)
		} else if b, err := cryptographie.Base64Canonique(pt.PreuveBase64); err != nil || len(b) > entree.LimitePreuveOTS {
			v := commun.Nouvelle("K-9", commun.Echoue, "", commun.T("preuve du point inexploitable (base64 non canonique ou plus de 256 Kio)", "checkpoint proof unusable (non-canonical base64 or more than 256 KiB)"), 5)
			c.k9 = &v
		} else {
			e := baseO
			e.Usage = ots.Point
			e.Preuve, e.Etat = b, entree.Lu
			e.EmpreinteAttendue, e.EmpreinteDisponible = pt.CheckpointHash, true
			r := ots.Verifier(e)
			c.preuvePt = &r
			d := commun.T(resumeStatuts(r.Verifications), resumeStatuts(r.Verifications))
			if r.Statut == commun.Reussi && !r.Resume.Vide() {
				d = d.Joindre(" ; ", "; ", r.Resume)
			}
			v := commun.Nouvelle("K-9", r.Statut, r.Raison, d, 5)
			c.k9 = &v
			for _, a := range r.Avertissements {
				a.Verification = "K-9"
				c.avert = append(c.avert, a)
			}
		}
	}
	// --- Contrôle 8, N-4 et K-8 ---
	er := registre.Entree{
		Registre:    partieRegistre(c.dos.Partie(dossier.PRegistre)),
		Certificat:  partieRegistre(c.dos.Partie(dossier.PCertificat)),
		Validateurs: partieRegistre(c.dos.Partie(dossier.PValidateurs)),
		Ancres:      c.anc,
	}
	if ev != nil {
		er.OrgID, er.JournalID = ev.V.Membre("org_id").S(), ev.V.Membre("journal_id").S()
	}
	if an.P1 {
		m := an.Manifeste
		er.Manifeste = registre.Manifeste{Valide: true, PeriodHash: an.PeriodHash, OrgID: m.Membre("org_id").S(), JournalID: m.Membre("journal_id").S(), Root: m.Membre("root").S(), RecorderKeyID: m.Membre("recorder_key_id").S()}
		er.Manifeste.PeriodStart, _ = m.Membre("period_start").Entier()
		er.Manifeste.PeriodEnd, _ = m.Membre("period_end").Entier()
		er.Manifeste.FirstSeq, _ = m.Membre("first_seq").Entier()
		er.Manifeste.LastSeq, _ = m.Membre("last_seq").Entier()
		er.Manifeste.Version, _ = m.Membre("version").Entier()
	}
	er.ClesExploitables = an.ClesExploitables
	for _, k := range an.ClesListe {
		er.Cles = append(er.Cles, ancres.CleDossier{KeyID: k.KeyID, ClePublique: k.Hex})
	}
	if p := c.dos.Partie(dossier.PPoints); p != nil && p.Present {
		er.PointDeclare = true
	}
	pt := an.Point
	avecReference := false
	if pt != nil && pt.K1 {
		er.Point = &registre.Point{K2: pt.K2, CheckpointHash: pt.CheckpointHash, KeyID: pt.KeyID}
		if r := pt.AncreRegistre; r != nil {
			ref := &registre.ReferencePoint{Contract: r.Membre("contract").S(), Fingerprint: r.Membre("fingerprint").S(), DocType: r.Membre("doc_type").S(), BlockHash: r.Membre("block_hash").S(), TransactionHash: r.Membre("transaction_hash").S()}
			ref.ChainID, _ = r.Membre("chain_id").Entier()
			ref.BlockNumber, _ = r.Membre("block_number").Entier()
			ref.LogIndex, _ = r.Membre("log_index").Entier()
			er.Point.Reference = ref
			avecReference = pt.K2
		}
	}
	c.reg8 = er.PartiesPresentes()
	if c.reg8 || avecReference {
		r := registre.Verifier(er)
		c.reg = &r
		for _, a := range r.Avertissements {
			c.avert = append(c.avert, a)
		}
	}
	if pt != nil {
		switch {
		case c.pointPrerequis("K-8", 8) != nil:
			c.k8 = c.pointPrerequis("K-8", 8)
		case pt.AncreRegistre == nil:
			c.k8 = ancreNulle("K-8", 8)
		case c.reg != nil && c.reg.K8 != nil:
			v := *c.reg.K8
			c.k8 = &v
		default:
			panic("le paquet registre n'a pas rendu K-8 pour une référence au registre")
		}
	}
	if c.jeton != nil {
		c.avert = append(c.avert, c.jeton.Avertissements...)
	}
	if c.preuve != nil {
		c.avert = append(c.avert, c.preuve.Avertissements...)
	}
	// --- N-3 ---
	if c.anc != nil && ev != nil {
		e := ancres.EntreeN3{OrgID: ev.V.Membre("org_id").S(), JournalID: ev.V.Membre("journal_id").S(), ClesExploitables: an.ClesExploitables}
		for _, k := range an.ClesListe {
			e.Cles = append(e.Cles, ancres.CleDossier{KeyID: k.KeyID, ClePublique: k.Hex})
		}
		for _, x := range []*dossier.Evt{an.Evenement, an.Precedent, an.Suivant} {
			if x != nil {
				e.Signataires = append(e.Signataires, x.Cle())
			}
		}
		for _, x := range an.Decisions {
			e.Signataires = append(e.Signataires, x.Cle())
		}
		if an.CleManifeste != "" {
			e.Signataires = append(e.Signataires, an.CleManifeste)
		}
		if pt != nil && pt.K1 {
			e.Signataires = append(e.Signataires, pt.KeyID)
		}
		c.n3 = c.anc.VerifierN3(e)
	}
}

func partieRegistre(p *dossier.Partie) registre.Partie {
	if p == nil {
		return registre.Partie{}
	}
	if !p.Present {
		return registre.Partie{RaisonAbsence: p.Raison}
	}
	return registre.Partie{Presente: true, Etat: p.Lecture.Etat, Octets: p.Lecture.Octets}
}

// raisonAbsence : raison d'EX-4.3 d'une partie réservée absente.
func raisonAbsence(p *dossier.Partie) commun.Raison {
	if p != nil && p.Raison == dossier.RaisonHorsPerimetreCT1 {
		return commun.HorsPerimetreVersion
	}
	return commun.PartieAbsente
}

// sansEffet : vérifications sans effet sur le statut de leur contrôle quand
// elles ne sont pas exécutées (EX-6.4, règle 2).
func sansEffet(id string) bool {
	switch id {
	case "T-11", "R-3", "R-10", "R-11", "N-3", "N-4":
		return true
	}
	return strings.HasPrefix(id, "K-") || strings.HasPrefix(id, "AT-")
}

func ordreFamille(id string) (int, int) {
	fam, num, _ := strings.Cut(id, "-")
	n, _ := strconv.Atoi(num)
	ordre := map[string]int{"D": 0, "E": 1, "C": 2, "M": 3, "P": 4, "A": 5, "K": 6, "AT": 7, "T": 8, "O": 9, "R": 10, "N": 11}
	return ordre[fam], n
}

// synthese : statuts des contrôles, verdict, faits, énoncé, borne, rapport.
func (c *calcul) synthese() {
	an := c.an
	res := c.res
	// Liste des vérifications dans l'ordre du rapport (EX-5.2).
	var verifs []commun.Verification
	for _, v := range an.Verifs {
		if v.ID == "AT-1" {
			// K-7, K-8, K-9 avant AT-1.
			verifs = append(verifs, c.ksReserves()...)
		}
		verifs = append(verifs, v)
		if v.ID == "K-6" && (an.Attestation == nil) {
			verifs = append(verifs, c.ksReserves()...)
		}
	}
	if an.Point != nil && an.Attestation != nil && !contient(verifs, "K-7") {
		// Cas défensif : l'attestation n'a pas produit AT-1.
		verifs = append(verifs, c.ksReserves()...)
	}
	if c.jeton != nil {
		verifs = append(verifs, c.jeton.Verifications...)
	}
	if c.preuve != nil {
		verifs = append(verifs, c.preuve.Verifications...)
	}
	if c.reg != nil {
		verifs = append(verifs, c.reg.Verifications...)
	}
	if c.n3.Figure {
		verifs = append(verifs, c.n3.Verification)
	}
	if c.reg != nil && c.reg.N4 != nil {
		verifs = append(verifs, *c.reg.N4)
	}
	res.Verifs = verifs
	parID := map[string]commun.Verification{}
	rang := map[string]int{}
	for i, v := range verifs {
		parID[v.ID] = v
		rang[v.ID] = i
		if v.Raison == commun.AConstruire {
			res.AConstruire = append(res.AConstruire, v.ID)
		}
	}
	// Avertissements (EX-6.15).
	var avert []commun.Avertissement
	avert = append(avert, c.avert...)
	if an.Attestation != nil {
		avert = append(avert, an.Attestation.Avertissements...)
	}
	sort.SliceStable(avert, func(i, j int) bool {
		ri, rj := rang[avert[i].Verification], rang[avert[j].Verification]
		if ri != rj {
			return ri < rj
		}
		fi, ni := ordreFamille(strings.TrimPrefix(avert[i].ID, "AV-"))
		fj, nj := ordreFamille(strings.TrimPrefix(avert[j].ID, "AV-"))
		if fi != fj {
			return fi < fj
		}
		return ni < nj
	})
	res.Avertissements = avert
	// Statuts des contrôles.
	var ctrls [9]commun.Resultat
	for n := 1; n <= 8; n++ {
		ctrls[n] = c.statutControle(n, verifs)
	}
	res.Controles = ctrls
	// Verdict.
	var echecs, bloquantes []string
	for _, v := range verifs {
		if strings.HasPrefix(v.ID, "AT-") {
			continue
		}
		if v.Statut == commun.Echoue {
			echecs = append(echecs, v.ID)
		}
		if v.Statut == commun.NonExecute && v.Raison == commun.PrerequisEnEchec {
			bloquantes = append(bloquantes, v.ID)
		}
	}
	var exigesNonReussis []int
	for _, n := range c.o.Exiger {
		if ctrls[n].Statut != commun.Reussi {
			exigesNonReussis = append(exigesNonReussis, n)
		}
	}
	switch {
	case len(echecs) > 0 || len(bloquantes) > 0:
		res.Verdict, res.Code = "invalide", 1
	case len(exigesNonReussis) > 0:
		res.Verdict, res.Code = "incomplet", 3
	default:
		res.Verdict, res.Code = "valide", 0
	}
	if len(res.AConstruire) > 0 {
		return
	}
	res.Rapport = c.construireRapport(verifs, parID, ctrls, echecs, bloquantes, exigesNonReussis, avert)
}

func contient(vs []commun.Verification, id string) bool {
	for _, v := range vs {
		if v.ID == id {
			return true
		}
	}
	return false
}

// ksReserves rend K-7, K-8 et K-9 (une seule fois).
func (c *calcul) ksReserves() []commun.Verification {
	if c.an.Point == nil || c.k7 == nil {
		return nil
	}
	out := []commun.Verification{*c.k7, *c.k8, *c.k9}
	c.k7 = nil
	return out
}

// statutControle applique EX-6.4 et EX-6.5, avec les règles propres des
// contrôles 4, 5 et 8 (EX-9.18, EX-10.12, EX-11.20).
func (c *calcul) statutControle(n int, verifs []commun.Verification) commun.Resultat {
	var siennes []commun.Verification
	for _, v := range verifs {
		for _, k := range v.Controles {
			if k == n {
				siennes = append(siennes, v)
			}
		}
	}
	// Règle 1 d'EX-6.4, commune à tous les contrôles (EX-9.18, EX-10.12 et
	// EX-11.20 la reprennent, K- et N-4 comprises, EX-5.8).
	for _, v := range siennes {
		if v.Statut == commun.Echoue && !strings.HasPrefix(v.ID, "AT-") {
			return commun.Resultat{Statut: commun.Echoue}
		}
	}
	switch n {
	case 4, 5, 8:
		var parties []*dossier.Partie
		var synth *commun.Resultat
		switch n {
		case 4:
			parties = []*dossier.Partie{c.partie4}
			if c.jeton != nil {
				synth = &commun.Resultat{Statut: c.jeton.Statut, Raison: c.jeton.Raison}
			}
		case 5:
			parties = []*dossier.Partie{c.partie5}
			if c.preuve != nil {
				synth = &commun.Resultat{Statut: c.preuve.Statut, Raison: c.preuve.Raison}
			}
		case 8:
			parties = []*dossier.Partie{c.dos.Partie(dossier.PRegistre), c.dos.Partie(dossier.PCertificat)}
			if c.reg8 && c.reg != nil {
				synth = &commun.Resultat{Statut: c.reg.Statut, Raison: c.reg.Raison}
			}
		}
		// Partie requise absente (EX-4.3) ; index inexploitable : parties
		// inconnues, prerequis_en_echec.
		var raisons []commun.Raison
		for _, p := range parties {
			switch {
			case p == nil:
				raisons = append(raisons, commun.PrerequisEnEchec)
			case !p.Present:
				raisons = append(raisons, raisonAbsence(p))
			}
		}
		if len(raisons) > 0 {
			return commun.Resultat{Statut: commun.NonExecute, Raison: commun.PremiereRaison(raisons...)}
		}
		if synth == nil {
			panic(fmt.Sprintf("contrôle %d : aucun résultat du paquet", n))
		}
		return *synth
	}
	var raisons []commun.Raison
	for _, v := range siennes {
		if v.Statut == commun.NonExecute && v.Raison != commun.PieceHorsDossier && !sansEffet(v.ID) {
			raisons = append(raisons, v.Raison)
		}
	}
	if len(raisons) > 0 {
		return commun.Resultat{Statut: commun.NonExecute, Raison: commun.PremiereRaison(raisons...)}
	}
	return commun.Resultat{Statut: commun.Reussi}
}
