package dossier

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/noorfinances-eng/noortrace/verificateur/commun"
	"github.com/noorfinances-eng/noortrace/verificateur/cryptographie"
	"github.com/noorfinances-eng/noortrace/verificateur/entree"
	"github.com/noorfinances-eng/noortrace/verificateur/jcs"
	"github.com/noorfinances-eng/noortrace/verificateur/jsonv"
	"github.com/noorfinances-eng/noortrace/verificateur/schema"
)

// Cle : une clé de cles.json.
type Cle struct {
	KeyID  string
	Hex    string
	Octets []byte
	Debut  time.Time
	// Fin : nil pour valid_to nul.
	Fin *time.Time
}

// Options de l'analyse : entrées à part (CT-6 §4.3).
type Options struct {
	// RepertoirePieces : --pieces, ou "".
	RepertoirePieces string
	// SecondManifeste : --second-manifeste lu et conforme, ou nil.
	SecondManifeste *jsonv.Valeur
}

// Analyse : résultat des vérifications de CT-1 et données utiles aux
// autres contrôles.
type Analyse struct {
	Dossier *Dossier
	// Verifs : D-1 à A-4, K-1 à K-6, AT-1 à AT-7, dans l'ordre du rapport.
	Verifs []commun.Verification
	// PartiesAbsentes : parties déclarées absentes (absent_parts).
	PartiesAbsentes []*Partie

	// Événement prouvé (nil s'il est inexploitable), voisins, décisions.
	Evenement *Evt
	Precedent *Evt
	Suivant   *Evt
	Decisions []*Evt
	// voisinsLus : voisins.json exploitable (EX-5.13), conforme ou non à
	// son schéma ; voisinsEnveloppe : enveloppe { version, previous, next }
	// conforme (C-1).
	voisinsLus       bool
	voisinsEnveloppe bool
	// precedentInvalide, suivantInvalide : previous ou next qui n'est ni un
	// objet ni null (membre absent compris) : un événement qui n'est pas un
	// objet, E-1 échoue pour lui et les relations qui le lisent ne sont pas
	// tenues (CT-1 §11.4, révision 0.5).
	precedentInvalide, suivantInvalide bool
	// precedentPresent, suivantPresent : le membre invalide est présent
	// (et non absent) : c'est alors un événement qui n'est pas un objet, E-1
	// échoue pour lui et E-2 à E-11 ne s'y exécutent pas ; un membre absent
	// n'est pas un événement (CT-1 §11.4, CT-6 EX-5.13, révision 0.5).
	precedentPresent, suivantPresent bool
	// decisionsInvalides : rangs des éléments de events qui ne sont pas des
	// objets (E-1 échoue pour eux).
	decisionsInvalides []int
	evenements         []*Evt
	// evenementSansForme : evenement.json est un objet JSON sans forme
	// canonique (E-2) ; Evenement vaut alors nil.
	evenementSansForme bool

	// Cles : clés de cles.json par key_id ; ClesExploitables : première
	// partie de E-8 réussie.
	Cles             map[string]Cle
	ClesListe        []Cle
	ClesExploitables bool

	// Manifeste : manifeste.json (nil s'il n'est pas un objet JSON).
	Manifeste *jsonv.Valeur
	// P1 : P-1 a réussi (manifeste conforme ; EX-5.4).
	P1 bool
	// PeriodHash : periodHash recalculé, valable si PeriodHashOK.
	PeriodHash   [32]byte
	PeriodHashOK bool
	// CleManifeste : manifeste.sig.recorder_key_id.
	CleManifeste string
	// M3 : M-3 a réussi.
	M3     bool
	chemin *jsonv.Valeur

	// Point : partie points-de-controle.json (nil si non déclarée présente).
	Point *Point
	// Attestation : partie attestation-perimetre.json (nil si non déclarée
	// présente).
	Attestation *Attestation

	pieces *Pieces
	statut map[string]commun.Verification
}

// Pieces rend le nombre de pièces lues à part, ou -1 sans --pieces.
func (a *Analyse) PiecesLues() int {
	if a.pieces == nil {
		return -1
	}
	return a.pieces.Lues
}

// Statut rend la vérification d'identifiant id (si elle figure).
func (a *Analyse) Statut(id string) (commun.Verification, bool) {
	v, ok := a.statut[id]
	return v, ok
}

func (a *Analyse) ajouter(v commun.Verification) {
	a.Verifs = append(a.Verifs, v)
	a.statut[v.ID] = v
}

func (a *Analyse) reussie(id string) bool {
	v, ok := a.statut[id]
	return ok && v.Statut == commun.Reussi
}

func prerequis(id string, fr, en string, controles ...int) commun.Verification {
	return commun.Nouvelle(id, commun.NonExecute, commun.PrerequisEnEchec, commun.T(fr, en), controles...)
}

// Analyser exécute les vérifications de CT-1 dans l'ordre de §11.4.
func Analyser(d *Dossier, opt Options) (*Analyse, *Defaut) {
	a := &Analyse{Dossier: d, Cles: map[string]Cle{}, statut: map[string]commun.Verification{}}
	if opt.RepertoirePieces != "" {
		a.pieces = &Pieces{Repertoire: opt.RepertoirePieces, lues: map[string]bool{}}
	}
	if !d.IndexConforme() {
		a.indexInexploitable()
		return a, nil
	}
	if def := d.LireParties(); def != nil {
		return nil, def
	}
	for _, p := range d.Parties {
		if !p.Present {
			a.PartiesAbsentes = append(a.PartiesAbsentes, p)
		}
	}
	a.preparer()
	a.d1()
	a.d2()
	if def := a.verificationsE(); def != nil {
		return nil, def
	}
	a.verificationsC()
	a.verificationsM()
	a.verificationsP(opt.SecondManifeste)
	a.verificationsA()
	if p := d.Partie(PPoints); p != nil && p.Present {
		a.verificationsK(p)
	}
	if p := d.Partie(PAttestation); p != nil && p.Present {
		a.verificationsAT(p)
	}
	return a, nil
}

// IDsCT1 : les vingt-huit vérifications de CT-1 qui figurent toujours.
var IDsCT1 = []string{"D-1", "D-2", "E-1", "E-2", "E-3", "E-4", "E-5", "E-6", "E-7", "E-8", "E-9", "E-10", "E-11", "C-1", "C-2", "C-3", "M-1", "M-2", "M-3", "P-1", "P-2", "P-3", "P-4", "P-5", "A-1", "A-2", "A-3", "A-4"}

// ControlesDe : contrôles servis par chaque vérification (CT-1 §11.4,
// CT-6 §5.1, §5.4, §5.5).
var ControlesDe = map[string][]int{
	"D-1": {}, "D-2": {},
	"E-1": {1}, "E-2": {1}, "E-3": {1}, "E-4": {1}, "E-5": {7}, "E-6": {1}, "E-7": {1}, "E-8": {6}, "E-9": {7}, "E-10": {6}, "E-11": {6},
	"C-1": {2}, "C-2": {2}, "C-3": {6},
	"M-1": {3}, "M-2": {3}, "M-3": {3},
	"P-1": {3}, "P-2": {3}, "P-3": {2, 3}, "P-4": {3}, "P-5": {3, 6},
	"A-1": {7}, "A-2": {7}, "A-3": {7}, "A-4": {7},
	"K-1": {3}, "K-2": {3}, "K-3": {6}, "K-4": {3}, "K-5": {3}, "K-6": {2}, "K-7": {4}, "K-8": {8}, "K-9": {5},
	"AT-1": {7}, "AT-2": {7}, "AT-3": {7}, "AT-4": {7}, "AT-5": {7}, "AT-6": {6}, "AT-7": {6},
	"N-3": {6}, "N-4": {8},
}

func (a *Analyse) indexInexploitable() {
	if err := a.Dossier.ErrCanonique; err != nil {
		// Index sans forme canonique : E-2 porte l'échec (CT-1 §11.4) ; D-1
		// et tout ce qui dépend de l'index ne sont pas exécutés.
		m := err.Error()
		if e, ok := err.(*jcs.Erreur); ok {
			m = e.Motif
		}
		for _, id := range IDsCT1 {
			if id == "E-2" {
				a.ajouter(commun.Nouvelle("E-2", commun.Echoue, "", commun.T("forme canonique non calculable : dossier.json ("+m+")", "canonical form not computable: dossier.json ("+m+")"), 1))
				continue
			}
			a.ajouter(prerequis(id, "dossier.json sans forme canonique (E-2) : index inexploitable, parties inconnues", "dossier.json without canonical form (E-2): unusable index, parts unknown", ControlesDe[id]...))
		}
		return
	}
	motif := commun.T("dossier.json dépasse 1 Mio", "dossier.json exceeds 1 MiB")
	if a.Dossier.ErrIndex != nil {
		motif = commun.T("dossier.json contraire au schéma dossier-v0 ("+a.Dossier.ErrIndex.Error()+")", "dossier.json does not follow the dossier-v0 schema ("+a.Dossier.ErrIndex.Error()+")")
	}
	a.ajouter(commun.Nouvelle("D-1", commun.Echoue, "", motif))
	for _, id := range IDsCT1[1:] {
		a.ajouter(prerequis(id, "index inexploitable (D-1) : parties inconnues", "unusable index (D-1): parts unknown", ControlesDe[id]...))
	}
}

// preparer lit les événements et les clés.
func (a *Analyse) preparer() {
	// Un evenement.json sans forme canonique est inexploitable : E-2 porte
	// l'échec, et les vérifications qui dépendent de l'événement prouvé ne
	// sont pas exécutées (CT-1 §11.4, cas (d) ; CT-6 EX-5.15).
	if p := a.Dossier.Partie(PEvenement); p.Exploitable() {
		a.Evenement = nouvelEvt(commun.T("evenement", "event"), p.Valeur)
		a.evenements = append(a.evenements, a.Evenement)
	} else if p.SansForme() {
		a.evenementSansForme = true
	}
	// Les événements de voisins.json et de approbations.json sont lus dans
	// une partie exploitable, conforme ou non au schéma de son enveloppe
	// (CT-1 §11.4, révision 0.5 ; CT-6 EX-5.13).
	if p := a.Dossier.Partie(PVoisins); p.Exploitable() {
		v := p.Valeur
		a.voisinsLus = true
		a.voisinsEnveloppe = enveloppeVoisins(v)
		switch x := v.Membre("previous"); {
		case x.EstObjet():
			a.Precedent = nouvelEvt(commun.T("voisin précédent", "previous neighbour"), x)
			a.evenements = append(a.evenements, a.Precedent)
		case !x.EstNul():
			a.precedentInvalide = true
			a.precedentPresent = x != nil
		}
		switch x := v.Membre("next"); {
		case x.EstObjet():
			a.Suivant = nouvelEvt(commun.T("voisin suivant", "next neighbour"), x)
			a.evenements = append(a.evenements, a.Suivant)
		case !x.EstNul():
			a.suivantInvalide = true
			a.suivantPresent = x != nil
		}
	}
	if p := a.Dossier.Partie(PApprobations); p.Exploitable() {
		if ev := p.Valeur.Membre("events"); ev.EstTableau() {
			for i, x := range ev.Elements {
				if !x.EstObjet() {
					a.decisionsInvalides = append(a.decisionsInvalides, i)
					continue
				}
				e := nouvelEvt(commun.T(fmt.Sprintf("approbation[%d]", i), fmt.Sprintf("approval[%d]", i)), x)
				a.Decisions = append(a.Decisions, e)
				a.evenements = append(a.evenements, e)
			}
		}
	}
	if p := a.Dossier.Partie(PManifeste); p.Exploitable() {
		a.Manifeste = p.Valeur
		if c, err := jcs.Canonique(p.Valeur); err == nil {
			a.PeriodHash = cryptographie.Sha256(cryptographie.PrefixeManifeste, c)
			a.PeriodHashOK = true
		}
	}
	if p := a.Dossier.Partie(PManifesteSig); p.Exploitable() {
		a.CleManifeste = p.Valeur.Membre("recorder_key_id").S()
	}
	a.lireCles()
}

// lireCles applique la première partie de E-8 : cles.json conforme à son
// schéma, org_id et journal_id égaux à ceux de l'événement, key_id et
// public_key uniques, valid_to ≥ valid_from.
func (a *Analyse) lireCles() (commun.Statut, commun.Texte) {
	p := a.Dossier.Partie(PCles)
	if p == nil || !p.Present || p.Lecture.Etat == entree.Absent {
		return commun.NonExecute, commun.T("cles.json absent du répertoire", "cles.json missing from the directory")
	}
	if p.SansForme() {
		// Cas (d) de CT-1 §11.4 : E-2 porte le défaut, E-8 n'est pas
		// exécutée.
		return commun.NonExecute, commun.T("cles.json sans forme canonique (E-2)", "cles.json without canonical form (E-2)")
	}
	if !p.Exploitable() {
		return commun.Echoue, commun.T("cles.json inexploitable (pas un objet JSON, ou limite de taille)", "cles.json unusable (not a JSON object, or size limit)")
	}
	v := p.Valeur
	if err := schema.Valider(schema.Dossier+"#/$defs/cles", v); err != nil {
		return commun.Echoue, commun.T("cles.json contraire à son schéma ("+err.Error()+")", "cles.json does not follow its schema ("+err.Error()+")")
	}
	ids, pubs := map[string]bool{}, map[string]bool{}
	var liste []Cle
	for _, k := range v.Membre("keys").Elements {
		kid, hx := k.Membre("key_id").S(), k.Membre("public_key").S()
		if ids[kid] || pubs[hx] {
			return commun.Echoue, commun.T("cles.json : key_id ou public_key en double ("+kid+")", "cles.json: duplicate key_id or public_key ("+kid+")")
		}
		ids[kid], pubs[hx] = true, true
		deb, okD := commun.LireHorodatage(k.Membre("valid_from").S())
		if !okD {
			return commun.Echoue, commun.T("cles.json : valid_from de "+kid+" n'est pas une date existante", "cles.json: valid_from of "+kid+" is not an existing date")
		}
		c := Cle{KeyID: kid, Hex: hx, Debut: deb}
		c.Octets, _ = cryptographie.LireHex(hx, 32)
		if f := k.Membre("valid_to"); f.EstChaine() {
			fin, okF := commun.LireHorodatage(f.Chaine)
			if !okF || fin.Before(deb) {
				return commun.Echoue, commun.T("cles.json : valid_to de "+kid+" illisible ou antérieur à valid_from", "cles.json: valid_to of "+kid+" unreadable or before valid_from")
			}
			c.Fin = &fin
		}
		liste = append(liste, c)
	}
	// La comparaison à l'événement vient après les règles qui ne lisent que
	// cles.json (schéma, dates, unicité, valid_to ≥ valid_from) : celles-ci
	// sont évaluées même quand evenement.json est inexploitable, et leur
	// échec l'emporte (CT-1 §11.4, « sauf s'il échoue sur ce qu'il lit des
	// autres parties » ; CT-6 EX-5.15, point 1).
	if a.Evenement == nil {
		return commun.NonExecute, commun.T("evenement.json inexploitable : org_id et journal_id non comparés", "evenement.json unusable: org_id and journal_id not compared")
	}
	if v.Membre("org_id").S() != a.Evenement.V.Membre("org_id").S() || v.Membre("journal_id").S() != a.Evenement.V.Membre("journal_id").S() {
		return commun.Echoue, commun.T("cles.json : org_id ou journal_id différent de celui de l'événement", "cles.json: org_id or journal_id differs from the event's")
	}
	a.ClesExploitables = true
	a.ClesListe = liste
	for _, c := range liste {
		a.Cles[c.KeyID] = c
	}
	return commun.Reussi, commun.Texte{}
}

// --- D-1, D-2 --------------------------------------------------------------

// d1 : D-1 sur un index conforme à son schéma (CT-1 §11.4, révision 0.5 ;
// CT-6 EX-5.14). La comparaison à l'événement exige evenement.json
// exploitable ; sinon D-1 est non_execute (prerequis_en_echec), jamais
// reussi.
func (a *Analyse) d1() {
	idx := a.Dossier.Index
	if a.Evenement == nil {
		a.ajouter(prerequis("D-1", "dossier.json conforme au schéma ; evenement.json inexploitable : event, org_id et journal_id non comparés", "dossier.json follows the schema; evenement.json unusable: event, org_id and journal_id not compared"))
		return
	}
	ev := a.Evenement.V
	s, okS := a.Evenement.Seq()
	is, _ := idx.Chemin("event", "seq").Entier()
	h, ih := ev.Membre("hash").S(), idx.Chemin("event", "hash").S()
	var fr, en []string
	if !okS || s != is || !ev.Membre("hash").EstChaine() || h != ih {
		fr = append(fr, fmt.Sprintf("event de l'index (seq %d, hash %s) différent de evenement.json (seq %d, hash %s)", is, ih, s, h))
		en = append(en, fmt.Sprintf("index event (seq %d, hash %s) differs from evenement.json (seq %d, hash %s)", is, ih, s, h))
	}
	for _, nom := range []string{"org_id", "journal_id"} {
		if v := ev.Membre(nom); !v.EstChaine() || v.Chaine != idx.Membre(nom).S() {
			fr = append(fr, nom+" de l'index "+idx.Membre(nom).S()+" différent de celui de evenement.json "+v.S())
			en = append(en, "index "+nom+" "+idx.Membre(nom).S()+" differs from that of evenement.json "+v.S())
		}
	}
	if len(fr) > 0 {
		a.ajouter(commun.Nouvelle("D-1", commun.Echoue, "", commun.T(strings.Join(fr, " ; "), strings.Join(en, "; "))))
		return
	}
	a.ajouter(commun.Nouvelle("D-1", commun.Reussi, "", commun.T("dossier.json conforme au schéma, event, org_id et journal_id égaux à ceux de evenement.json", "dossier.json follows the schema, event, org_id and journal_id equal those of evenement.json")))
}

func (a *Analyse) d2() {
	var ecartsFr, ecartsEn []string
	for _, p := range a.Dossier.Parties {
		chemin := filepath.Join(a.Dossier.Repertoire, p.Fichier)
		if !p.Present {
			// Aucun fichier ordinaire de ce nom, et une raison qui est une
			// chaîne non vide (CT-1 §3, §11.4, révision 0.5) ; une entrée
			// qui n'est pas un fichier ordinaire compte comme absente.
			if entree.EstOrdinaire(chemin) {
				ecartsFr = append(ecartsFr, p.Fichier+" déclaré absent mais présent dans le répertoire")
				ecartsEn = append(ecartsEn, p.Fichier+" declared absent but present in the directory")
			}
			if !commun.ChaineNonVide(p.Raison) {
				ecartsFr = append(ecartsFr, p.Fichier+" absent sans raison (raison vide ou faite de blancs)")
				ecartsEn = append(ecartsEn, p.Fichier+" absent without a reason (empty reason or made of white space)")
			}
			continue
		}
		if p.Lecture.Etat == entree.Absent {
			if errors.Is(p.Lecture.Err, entree.ErrNonOrdinaire) {
				// Lien symbolique, tube nommé… : jamais ouvert ni suivi, la
				// partie compte comme absente du répertoire.
				ecartsFr = append(ecartsFr, p.Fichier+" déclaré présent mais qui n'est pas un fichier ordinaire (lien symbolique, tube nommé…) : compté absent du répertoire")
				ecartsEn = append(ecartsEn, p.Fichier+" declared present but not a regular file (symbolic link, named pipe…): counted as missing from the directory")
				continue
			}
			ecartsFr = append(ecartsFr, p.Fichier+" déclaré présent mais absent du répertoire")
			ecartsEn = append(ecartsEn, p.Fichier+" declared present but missing from the directory")
			continue
		}
		if p.Lecture.Etat == entree.Illisible {
			ecartsFr = append(ecartsFr, p.Fichier+" illisible")
			ecartsEn = append(ecartsEn, p.Fichier+" unreadable")
			continue
		}
		s, connu := p.Sha256Calcule()
		if !connu {
			// Partie au-delà de sa limite : inexploitable, son échec est porté
			// par la vérification de la partie (EX-4.11) ; le SHA-256 n'est
			// pas calculé au-delà de la limite (EX-4.13).
			continue
		}
		if s != p.Sha256Declare {
			ecartsFr = append(ecartsFr, fmt.Sprintf("%s : SHA-256 %s, l'index déclare %s", p.Fichier, s, p.Sha256Declare))
			ecartsEn = append(ecartsEn, fmt.Sprintf("%s: SHA-256 %s, the index declares %s", p.Fichier, s, p.Sha256Declare))
		}
	}
	if len(ecartsFr) > 0 {
		a.ajouter(commun.Nouvelle("D-2", commun.Echoue, "", commun.T(strings.Join(ecartsFr, " ; "), strings.Join(ecartsEn, "; "))))
		return
	}
	a.ajouter(commun.Nouvelle("D-2", commun.Reussi, "", commun.Texte{}))
}

// --- E-1 à E-11 ------------------------------------------------------------

// etatPartieEvenement dit si evenement.json est absent du répertoire (D-2)
// ou inexploitable.
func (a *Analyse) partieInexploitable(nom string) (absente bool, inexploitable bool) {
	p := a.Dossier.Partie(nom)
	if p == nil || !p.Present {
		return false, false
	}
	if p.Lecture.Etat == entree.Absent {
		return true, false
	}
	return false, !p.Exploitable()
}

func (a *Analyse) verificationsE() *Defaut {
	evts := a.evenements
	absEv, inexEv := a.partieInexploitable(PEvenement)
	// E-1
	var res []resultatEvt
	for _, e := range evts {
		res = append(res, regleE1(e))
	}
	// previous, next ou élément de events qui n'est pas un objet : un
	// événement qui n'est pas un objet, E-1 échoue pour lui (CT-1 §11.4,
	// révision 0.5).
	evtsE1 := append([]*Evt{}, evts...)
	nonObjet := func(fr, en string) {
		evtsE1 = append(evtsE1, &Evt{Role: commun.T(fr, en)})
		res = append(res, ko("n'est pas un objet JSON", "is not a JSON object"))
	}
	if a.precedentPresent {
		nonObjet("voisin précédent", "previous neighbour")
	}
	if a.suivantPresent {
		nonObjet("voisin suivant", "next neighbour")
	}
	for _, i := range a.decisionsInvalides {
		nonObjet(fmt.Sprintf("approbation[%d]", i), fmt.Sprintf("approval[%d]", i))
	}
	v := agregerEvts("E-1", evtsE1, res, 1)
	switch {
	case a.evenementSansForme && v.Statut != commun.Echoue:
		v = prerequis("E-1", "evenement.json sans forme canonique (E-2)", "evenement.json without canonical form (E-2)", 1)
	case a.evenementSansForme:
	case inexEv:
		v = commun.Nouvelle("E-1", commun.Echoue, "", commun.T("evenement.json n'est pas un objet JSON exploitable", "evenement.json is not a usable JSON object"), 1)
	case absEv && v.Statut != commun.Echoue:
		v = prerequis("E-1", "evenement.json absent du répertoire (D-2)", "evenement.json missing from the directory (D-2)", 1)
	}
	if v.Statut == commun.Reussi {
		v.Detail = commun.Texte{}
	}
	a.ajouter(v)
	// E-2 : forme canonique de chaque partie JSON de CT-1, dont
	// points-de-controle.json (CT-1 §11.4, CT-6 EX-4.14). L'index est traité
	// à l'ouverture (indexInexploitable) ; attestation-perimetre.json relève
	// d'AT-1, sans effet sur le verdict (EX-5.11).
	var fautifs []string
	for _, nom := range []string{PEvenement, PVoisins, PChemin, PManifeste, PManifesteSig, PCles, PApprobations, PPoints} {
		if p := a.Dossier.Partie(nom); p.SansForme() {
			m := p.ErrCanonique.Error()
			if e, ok := p.ErrCanonique.(*jcs.Erreur); ok {
				m = e.Motif
			}
			fautifs = append(fautifs, p.Fichier+" ("+m+")")
		}
	}
	switch {
	case len(fautifs) > 0:
		s := strings.Join(fautifs, ", ")
		a.ajouter(commun.Nouvelle("E-2", commun.Echoue, "", commun.T("forme canonique non calculable : "+s, "canonical form not computable: "+s), 1))
	case a.Evenement == nil:
		a.ajouter(prerequis("E-2", "evenement.json inexploitable", "evenement.json unusable", 1))
	default:
		a.ajouter(commun.Nouvelle("E-2", commun.Reussi, "", commun.Texte{}, 1))
	}
	// E-3 à E-7
	simple := func(id string, regle func(*Evt) resultatEvt, controles ...int) {
		var r []resultatEvt
		for _, e := range evts {
			r = append(r, regle(e))
		}
		v := agregerEvts(id, evts, r, controles...)
		if a.Evenement == nil && v.Statut != commun.Echoue {
			v = prerequis(id, "evenement.json inexploitable", "evenement.json unusable", controles...)
		}
		if v.Statut == commun.Reussi && id != "E-7" && id != "E-8" {
			v.Detail = commun.Texte{}
		}
		a.ajouter(v)
	}
	simple("E-3", regleE3, 1)
	simple("E-4", regleE4, 1)
	simple("E-5", regleE5, 7)
	var r6 []resultatEvt
	for _, e := range evts {
		r, def := a.regleE6(e)
		if def != nil {
			return def
		}
		r6 = append(r6, r)
	}
	v6 := agregerEvts("E-6", evts, r6, 1)
	if a.Evenement == nil && v6.Statut != commun.Echoue {
		v6 = prerequis("E-6", "evenement.json inexploitable", "evenement.json unusable", 1)
	}
	if v6.Statut == commun.Reussi {
		v6.Detail = commun.Texte{}
	}
	a.ajouter(v6)
	simple("E-7", regleE7, 1)
	// E-8
	stCles, motifCles := a.lireClesStatut()
	switch {
	case stCles == commun.Echoue:
		a.ajouter(commun.Nouvelle("E-8", commun.Echoue, "", motifCles, 6))
	case stCles == commun.NonExecute:
		a.ajouter(prerequis("E-8", motifCles.Fr, motifCles.En, 6))
	default:
		var r []resultatEvt
		for _, e := range evts {
			r = append(r, a.regleE8(e))
		}
		a.ajouter(agregerEvts("E-8", evts, r, 6))
	}
	simple("E-9", regleE9, 7)
	simple("E-10", a.regleE10, 6)
	simple("E-11", a.regleE11, 6)
	a.nonObjetsNonExecutes()
	return nil
}

// nonObjetsNonExecutes : E-2 à E-11 ne s'exécutent pas sur un événement qui
// n'est pas un objet (voisin présent ou élément de events) ; faute d'échec
// sur un autre événement, elles sont rapportées non_execute,
// prerequis_en_echec, et non réussies (CT-1 §11.4, statut sur plusieurs
// événements ; CT-6 EX-5.13, révision 0.4).
func (a *Analyse) nonObjetsNonExecutes() {
	var roles []string
	if a.precedentPresent {
		roles = append(roles, "voisin précédent")
	}
	if a.suivantPresent {
		roles = append(roles, "voisin suivant")
	}
	for _, i := range a.decisionsInvalides {
		roles = append(roles, fmt.Sprintf("approbation[%d]", i))
	}
	if len(roles) == 0 {
		return
	}
	l := strings.Join(roles, ", ")
	for k, v := range a.Verifs {
		switch v.ID {
		case "E-2", "E-3", "E-4", "E-5", "E-6", "E-7", "E-8", "E-9", "E-10", "E-11":
		default:
			continue
		}
		if v.Statut != commun.Reussi {
			continue
		}
		n := prerequis(v.ID, "non exécutée sur un événement qui n'est pas un objet : "+l, "not run on an event that is not an object: "+l, v.Controles...)
		a.Verifs[k] = n
		a.statut[v.ID] = n
	}
}

// lireClesStatut rend le statut de la première partie de E-8 (calculée une
// fois par preparer).
func (a *Analyse) lireClesStatut() (commun.Statut, commun.Texte) {
	if a.ClesExploitables {
		return commun.Reussi, commun.Texte{}
	}
	// Recalcul sans effet de bord : lireCles n'a pas abouti.
	sauve := a.Cles
	st, t := a.lireCles()
	a.Cles = sauve
	a.ClesExploitables = false
	return st, t
}

// evtSeq rend, parmi l'événement prouvé et ses voisins, celui de seq donné.
func (a *Analyse) evtSeq(seq int64) *Evt {
	for _, e := range []*Evt{a.Evenement, a.Precedent, a.Suivant} {
		if e == nil {
			continue
		}
		if s, ok := e.Seq(); ok && s == seq {
			return e
		}
	}
	return nil
}

// --- C-1 à C-3 -------------------------------------------------------------

func enveloppeVoisins(v *jsonv.Valeur) bool {
	if !v.EstObjet() || v.Doublon || len(v.Noms()) != 3 {
		return false
	}
	ver, okV := v.Membre("version").Entier()
	if !okV || ver != 0 {
		return false
	}
	p, n := v.Membre("previous"), v.Membre("next")
	return p != nil && n != nil && (p.EstObjet() || p.EstNul()) && (n.EstObjet() || n.EstNul())
}

// verificationsC : C-1 porte voisins.json et son enveloppe ; C-2, C-3 (et
// P-3) s'exécutent sur une partie exploitable même contraire au schéma de
// son enveloppe, sur les valeurs lues (CT-1 §11.4, révision 0.5).
func (a *Analyse) verificationsC() {
	pv := a.Dossier.Partie(PVoisins)
	absV, _ := a.partieInexploitable(PVoisins)
	ev := a.Evenement
	// C-1
	switch {
	case absV:
		a.ajouter(prerequis("C-1", "voisins.json absent du répertoire (D-2)", "voisins.json missing from the directory (D-2)", 2))
	case pv.SansForme():
		a.ajouter(prerequis("C-1", "voisins.json sans forme canonique (E-2)", "voisins.json without canonical form (E-2)", 2))
	case !a.voisinsLus:
		a.ajouter(commun.Nouvelle("C-1", commun.Echoue, "", commun.T("voisins.json inexploitable (limite de taille, pas du JSON ou pas un objet)", "voisins.json unusable (size limit, not JSON or not an object)"), 2))
	case !a.voisinsEnveloppe:
		a.ajouter(commun.Nouvelle("C-1", commun.Echoue, "", commun.T("voisins.json : enveloppe { version, previous, next } non conforme", "voisins.json: non-conforming { version, previous, next } envelope"), 2))
	case ev == nil:
		a.ajouter(prerequis("C-1", "evenement.json inexploitable", "evenement.json unusable", 2))
	default:
		a.ajouter(a.c1())
	}
	// C-2
	switch {
	case !a.voisinsLus || ev == nil:
		a.ajouter(prerequis("C-2", "voisins.json ou evenement.json inexploitable", "voisins.json or evenement.json unusable", 2))
	default:
		a.ajouter(a.c2())
	}
	// C-3
	switch {
	case !a.voisinsLus || ev == nil:
		a.ajouter(prerequis("C-3", "voisins.json ou evenement.json inexploitable", "voisins.json or evenement.json unusable", 6))
	default:
		a.ajouter(a.c3())
	}
}

// voisinsNonObjets : écarts dus à un previous ou un next qui n'est ni un
// objet ni null : la relation qui le lit n'est pas tenue (CT-1 §11.4,
// révision 0.5).
func (a *Analyse) voisinsNonObjets() []string {
	var e []string
	if a.precedentInvalide {
		e = append(e, "voisin précédent qui n'est ni un objet ni null")
	}
	if a.suivantInvalide {
		e = append(e, "voisin suivant qui n'est ni un objet ni null")
	}
	return e
}

func (a *Analyse) c1() commun.Verification {
	ev := a.Evenement
	seq, _ := ev.Seq()
	ts, okTs := ev.Ts()
	var ecarts []string
	var parties []string
	if a.Precedent == nil {
		if seq != 1 {
			ecarts = append(ecarts, "previous nul alors que seq ≠ 1")
		}
		parties = append(parties, "previous null")
	} else {
		ps, _ := a.Precedent.Seq()
		parties = append(parties, fmt.Sprintf("previous seq %d", ps))
		if seq == 1 {
			ecarts = append(ecarts, "previous non nul alors que seq = 1")
		}
		if ps != seq-1 {
			ecarts = append(ecarts, fmt.Sprintf("previous.seq %d ≠ seq − 1", ps))
		}
		pts, okP := a.Precedent.Ts()
		if !okP || !okTs || pts.After(ts) {
			ecarts = append(ecarts, "ts du voisin précédent postérieur à celui de l'événement")
		}
		if a.Precedent.V.Membre("org_id").S() != ev.V.Membre("org_id").S() || a.Precedent.V.Membre("journal_id").S() != ev.V.Membre("journal_id").S() {
			ecarts = append(ecarts, "org_id ou journal_id du voisin précédent différent")
		}
	}
	if a.Suivant == nil {
		parties = append(parties, "next null")
	} else {
		ns, _ := a.Suivant.Seq()
		parties = append(parties, fmt.Sprintf("next seq %d", ns))
		if ns != seq+1 {
			ecarts = append(ecarts, fmt.Sprintf("next.seq %d ≠ seq + 1", ns))
		}
		nts, okN := a.Suivant.Ts()
		if !okN || !okTs || ts.After(nts) {
			ecarts = append(ecarts, "ts du voisin suivant antérieur à celui de l'événement")
		}
		if a.Suivant.V.Membre("org_id").S() != ev.V.Membre("org_id").S() || a.Suivant.V.Membre("journal_id").S() != ev.V.Membre("journal_id").S() {
			ecarts = append(ecarts, "org_id ou journal_id du voisin suivant différent")
		}
	}
	if len(ecarts) > 0 {
		s := strings.Join(ecarts, ", ")
		return commun.Nouvelle("C-1", commun.Echoue, "", commun.T(s, s), 2)
	}
	s := strings.Join(parties, ", ")
	return commun.Nouvelle("C-1", commun.Reussi, "", commun.T(s, s), 2)
}

var zero32 = "0x0000000000000000000000000000000000000000000000000000000000000000"

func (a *Analyse) c2() commun.Verification {
	ev := a.Evenement
	ph := ev.V.Membre("prev_hash").S()
	ecarts := a.voisinsNonObjets()
	// Règle d'origine (prev_hash nul si et seulement si seq = 1), appliquée
	// à chaque événement du dossier, voisins compris, et évaluée seulement
	// pour un seq entier : sinon elle n'est ni tenue ni violée, E-1 seule
	// porte le défaut (CT-1 §11.4 « Autres termes mal typés », §7.2 temps 1 ;
	// CT-6 EX-5.13).
	for _, e := range []*Evt{a.Precedent, ev, a.Suivant} {
		if e == nil {
			continue
		}
		s, okS := e.Seq()
		if !okS {
			continue
		}
		if (e.V.Membre("prev_hash").S() == zero32) != (s == 1) {
			ecarts = append(ecarts, e.Role.Fr+" : prev_hash nul si et seulement si seq = 1 : non respecté")
		}
	}
	nonExec := false
	if a.Precedent != nil {
		if !a.Precedent.HashOK() {
			nonExec = true
		} else if ph != a.Precedent.HashHex() {
			ecarts = append(ecarts, "prev_hash "+ph+" ≠ hash recalculé du voisin précédent "+a.Precedent.HashHex())
		}
	}
	if a.Suivant != nil {
		if !ev.HashOK() {
			nonExec = true
		} else if nph := a.Suivant.V.Membre("prev_hash").S(); nph != ev.HashHex() {
			ecarts = append(ecarts, "prev_hash du voisin suivant "+nph+" ≠ hash recalculé de l'événement "+ev.HashHex())
		}
	}
	if len(ecarts) > 0 {
		s := strings.Join(ecarts, " ; ")
		return commun.Nouvelle("C-2", commun.Echoue, "", commun.T(s, s), 2)
	}
	if nonExec {
		return prerequis("C-2", "hachage d'un événement non recalculable (E-2)", "hash of an event not recomputable (E-2)", 2)
	}
	return commun.Nouvelle("C-2", commun.Reussi, "", commun.T("chaînage avec les voisins fournis", "chaining with the neighbours given"), 2)
}

func cleAttendueApres(e *Evt) string {
	if e.EstRotation() {
		return e.NouvelleCle()
	}
	return e.Cle()
}

func (a *Analyse) c3() commun.Verification {
	ev := a.Evenement
	ecarts := a.voisinsNonObjets()
	if a.Precedent != nil && ev.Cle() != cleAttendueApres(a.Precedent) {
		ecarts = append(ecarts, "clé de l'événement "+ev.Cle()+" ≠ "+cleAttendueApres(a.Precedent))
	}
	if a.Suivant != nil && a.Suivant.Cle() != cleAttendueApres(ev) {
		ecarts = append(ecarts, "clé du voisin suivant "+a.Suivant.Cle()+" ≠ "+cleAttendueApres(ev))
	}
	if len(ecarts) > 0 {
		s := strings.Join(ecarts, " ; ")
		return commun.Nouvelle("C-3", commun.Echoue, "", commun.T(s, s), 6)
	}
	return commun.Nouvelle("C-3", commun.Reussi, "", commun.T("clé "+ev.Cle(), "key "+ev.Cle()), 6)
}

// --- M-1 à M-3 -------------------------------------------------------------

func (a *Analyse) verificationsM() {
	pc := a.Dossier.Partie(PChemin)
	absC, _ := a.partieInexploitable(PChemin)
	var ch *jsonv.Valeur
	if pc.Exploitable() {
		ch = pc.Valeur
		a.chemin = ch
	}
	conforme := ch != nil && schema.Valider(schema.Dossier+"#/$defs/chemin", ch) == nil
	ev := a.Evenement
	// M-1 (sur chemin.json exploitable, même contraire à son schéma : un
	// leaf_hash d'un autre genre ne tient pas la relation, CT-1 §11.4).
	switch {
	case ch == nil:
		a.ajouter(prerequis("M-1", "chemin.json inexploitable", "chemin.json unusable", 3))
	case ev == nil || !ev.HashOK():
		a.ajouter(prerequis("M-1", "hash de l'événement non recalculé (E-2)", "event hash not recomputed (E-2)", 3))
	default:
		f := cryptographie.FeuilleMerkle(ev.Hash[:])
		if cryptographie.Hex32(f) != ch.Membre("leaf_hash").S() {
			a.ajouter(commun.Nouvelle("M-1", commun.Echoue, "", commun.T("leaf_hash "+ch.Membre("leaf_hash").S()+" ≠ SHA-256(00 ‖ hash) "+cryptographie.Hex32(f), "leaf_hash "+ch.Membre("leaf_hash").S()+" ≠ SHA-256(00 ‖ hash) "+cryptographie.Hex32(f)), 3))
		} else {
			a.ajouter(commun.Nouvelle("M-1", commun.Reussi, "", commun.T("leaf_hash "+cryptographie.Hex32(f), "leaf_hash "+cryptographie.Hex32(f)), 3))
		}
	}
	// M-2
	switch {
	case absC:
		a.ajouter(prerequis("M-2", "chemin.json absent du répertoire (D-2)", "chemin.json missing from the directory (D-2)", 3))
	case pc.SansForme():
		a.ajouter(prerequis("M-2", "chemin.json sans forme canonique (E-2)", "chemin.json without canonical form (E-2)", 3))
	case !conforme:
		a.ajouter(commun.Nouvelle("M-2", commun.Echoue, "", commun.T("chemin.json inexploitable ou contraire à son schéma", "chemin.json unusable or not following its schema"), 3))
	default:
		lh, _ := cryptographie.LireHex(ch.Membre("leaf_hash").S(), 32)
		rt, _ := cryptographie.LireHex(ch.Membre("root").S(), 32)
		m, _ := ch.Membre("leaf_index").Entier()
		n, _ := ch.Membre("tree_size").Entier()
		var chemin [][]byte
		for _, h := range ch.Membre("path").Elements {
			b, _ := cryptographie.LireHex(h.S(), 32)
			chemin = append(chemin, b)
		}
		if cryptographie.VerifierInclusion(lh, uint64(m), uint64(n), chemin, rt) {
			a.ajouter(commun.Nouvelle("M-2", commun.Reussi, "", commun.T(fmt.Sprintf("chemin de %d nœud(s) mène à la racine (indice %d, taille %d)", len(chemin), m, n), fmt.Sprintf("path of %d node(s) leads to the root (index %d, size %d)", len(chemin), m, n)), 3))
		} else {
			a.ajouter(commun.Nouvelle("M-2", commun.Echoue, "", commun.T(fmt.Sprintf("le chemin de %d nœud(s) ne mène pas à la racine (indice %d, taille %d)", len(chemin), m, n), fmt.Sprintf("the path of %d node(s) does not lead to the root (index %d, size %d)", len(chemin), m, n)), 3))
		}
	}
	// M-3
	man := a.Manifeste
	switch {
	case ch == nil || man == nil || ev == nil:
		a.ajouter(prerequis("M-3", "chemin.json, manifeste.json ou evenement.json inexploitable", "chemin.json, manifeste.json or evenement.json unusable", 3))
	default:
		seq, _ := ev.Seq()
		fs, _ := man.Membre("first_seq").Entier()
		var ecarts []string
		if ch.Membre("root").S() != man.Membre("root").S() || !ch.Membre("root").EstChaine() {
			ecarts = append(ecarts, "chemin.root ≠ manifeste.root")
		}
		ts, okT := ch.Membre("tree_size").Entier()
		cn, okC := man.Membre("count").Entier()
		if !okT || !okC || ts != cn {
			ecarts = append(ecarts, "tree_size ≠ count")
		}
		li, okL := ch.Membre("leaf_index").Entier()
		if !okL || li != seq-fs {
			ecarts = append(ecarts, "leaf_index ≠ seq − first_seq")
		}
		if len(ecarts) > 0 {
			s := strings.Join(ecarts, ", ")
			a.ajouter(commun.Nouvelle("M-3", commun.Echoue, "", commun.T(s, s), 3))
		} else {
			a.M3 = true
			a.ajouter(commun.Nouvelle("M-3", commun.Reussi, "", commun.T("chemin cohérent avec le manifeste", "path consistent with the manifest"), 3))
		}
	}
}

// --- P-1 à P-5 -------------------------------------------------------------

func (a *Analyse) verificationsP(second *jsonv.Valeur) {
	man := a.Manifeste
	absM, _ := a.partieInexploitable(PManifeste)
	ev := a.Evenement
	// P-1
	switch {
	case absM:
		a.ajouter(prerequis("P-1", "manifeste.json absent du répertoire (D-2)", "manifeste.json missing from the directory (D-2)", 3))
	case a.Dossier.Partie(PManifeste).SansForme():
		a.ajouter(prerequis("P-1", "manifeste.json sans forme canonique (E-2)", "manifeste.json without canonical form (E-2)", 3))
	case man == nil:
		a.ajouter(commun.Nouvelle("P-1", commun.Echoue, "", commun.T("manifeste.json n'est pas un objet JSON exploitable", "manifeste.json is not a usable JSON object"), 3))
	default:
		var ecarts []string
		if err := schema.Valider(schema.Manifeste, man); err != nil {
			ecarts = append(ecarts, "contraire au schéma manifeste-v0 ("+err.Error()+")")
		} else {
			if _, okG := commun.LireHorodatage(man.Membre("generated_at").S()); !okG {
				ecarts = append(ecarts, "generated_at n'est pas une date existante")
			}
			ps, _ := man.Membre("period_start").Entier()
			pe, _ := man.Membre("period_end").Entier()
			fs, _ := man.Membre("first_seq").Entier()
			ls, _ := man.Membre("last_seq").Entier()
			cn, _ := man.Membre("count").Entier()
			if pe != ps+3600 {
				ecarts = append(ecarts, "period_end ≠ period_start + 3600")
			}
			if cn != ls-fs+1 {
				ecarts = append(ecarts, "count ≠ last_seq − first_seq + 1")
			}
			// org_id et journal_id non nuls (CT-1 §3, révision 0.5).
			if man.Membre("org_id").S() == zero32 || man.Membre("journal_id").S() == zero32 {
				ecarts = append(ecarts, "org_id ou journal_id nul (32 octets nuls)")
			}
		}
		if ev != nil && (man.Membre("org_id").S() != ev.V.Membre("org_id").S() || man.Membre("journal_id").S() != ev.V.Membre("journal_id").S()) {
			ecarts = append(ecarts, "org_id ou journal_id différent de celui de l'événement")
		}
		switch {
		case len(ecarts) > 0:
			s := strings.Join(ecarts, ", ")
			a.ajouter(commun.Nouvelle("P-1", commun.Echoue, "", commun.T(s, s), 3))
		case ev == nil:
			a.ajouter(prerequis("P-1", "evenement.json inexploitable", "evenement.json unusable", 3))
		case !a.PeriodHashOK:
			a.ajouter(prerequis("P-1", "forme canonique du manifeste non calculable (E-2)", "canonical form of the manifest not computable (E-2)", 3))
		default:
			a.P1 = true
			ps, _ := man.Membre("period_start").Entier()
			pe, _ := man.Membre("period_end").Entier()
			fs, _ := man.Membre("first_seq").Entier()
			ls, _ := man.Membre("last_seq").Entier()
			a.ajouter(commun.Nouvelle("P-1", commun.Reussi, "", commun.T(fmt.Sprintf("période [%d, %d), seq %d..%d", ps, pe, fs, ls), fmt.Sprintf("period [%d, %d), seq %d..%d", ps, pe, fs, ls)), 3))
		}
	}
	// P-2
	if man == nil || ev == nil {
		a.ajouter(prerequis("P-2", "manifeste.json ou evenement.json inexploitable", "manifeste.json or evenement.json unusable", 3))
	} else {
		seq, _ := ev.Seq()
		ts, okTs := ev.Ts()
		fs, okF := man.Membre("first_seq").Entier()
		ls, okL := man.Membre("last_seq").Entier()
		ps, okPs := man.Membre("period_start").Entier()
		pe, okPe := man.Membre("period_end").Entier()
		if okTs && okF && okL && okPs && okPe && fs <= seq && seq <= ls && !ts.Before(time.Unix(ps, 0)) && ts.Before(time.Unix(pe, 0)) {
			a.ajouter(commun.Nouvelle("P-2", commun.Reussi, "", commun.T("événement dans la période", "event within the period"), 3))
		} else {
			a.ajouter(commun.Nouvelle("P-2", commun.Echoue, "", commun.T("seq ou ts de l'événement hors de la période du manifeste", "seq or ts of the event outside the manifest period"), 3))
		}
	}
	// P-3
	if man == nil || !a.voisinsLus {
		a.ajouter(prerequis("P-3", "manifeste.json ou voisins.json inexploitable", "manifeste.json or voisins.json unusable", 2, 3))
	} else {
		fs, _ := man.Membre("first_seq").Entier()
		ls, _ := man.Membre("last_seq").Entier()
		ps, _ := man.Membre("period_start").Entier()
		pe, _ := man.Membre("period_end").Entier()
		debut, fin := time.Unix(ps, 0), time.Unix(pe, 0)
		ecarts := a.voisinsNonObjets()
		for _, v := range []*Evt{a.Precedent, a.Suivant} {
			if v == nil {
				continue
			}
			s, _ := v.Seq()
			t, okT := v.Ts()
			if !okT {
				ecarts = append(ecarts, v.Role.Fr+" : ts illisible")
				continue
			}
			switch {
			case fs <= s && s <= ls:
				if t.Before(debut) || !t.Before(fin) {
					ecarts = append(ecarts, v.Role.Fr+" de la période horodaté hors d'elle")
				}
			case s == fs-1 && t.Before(debut):
			case s == ls+1 && !t.Before(fin):
			default:
				ecarts = append(ecarts, v.Role.Fr+" hors de la période mais horodaté dans ses bornes ou non adjacent")
			}
		}
		if len(ecarts) > 0 {
			s := strings.Join(ecarts, ", ")
			a.ajouter(commun.Nouvelle("P-3", commun.Echoue, "", commun.T(s, s), 2, 3))
		} else {
			a.ajouter(commun.Nouvelle("P-3", commun.Reussi, "", commun.T("voisins cohérents avec la période", "neighbours consistent with the period"), 2, 3))
		}
	}
	// P-4
	if man == nil {
		a.ajouter(prerequis("P-4", "manifeste.json inexploitable", "manifeste.json unusable", 3))
	} else {
		cn, okC := man.Membre("count").Entier()
		root := man.Membre("root").S()
		if !okC || (root == zero32) != (cn == 0) || cn < 1 {
			a.ajouter(commun.Nouvelle("P-4", commun.Echoue, "", commun.T(fmt.Sprintf("count %d, racine %s : racine nulle si et seulement si count = 0, et count ≥ 1", cn, root), fmt.Sprintf("count %d, root %s: root null if and only if count = 0, and count ≥ 1", cn, root)), 3))
		} else {
			a.ajouter(commun.Nouvelle("P-4", commun.Reussi, "", commun.T(fmt.Sprintf("count %d, racine %s", cn, root), fmt.Sprintf("count %d, root %s", cn, root)), 3))
		}
	}
	// P-5
	a.ajouter(a.p5(second))
}

func (a *Analyse) p5(second *jsonv.Valeur) commun.Verification {
	ps := a.Dossier.Partie(PManifesteSig)
	absS, _ := a.partieInexploitable(PManifesteSig)
	if absS {
		return prerequis("P-5", "manifeste.sig absent du répertoire (D-2)", "manifeste.sig missing from the directory (D-2)", 3, 6)
	}
	if ps.SansForme() {
		return prerequis("P-5", "manifeste.sig sans forme canonique (E-2)", "manifeste.sig without canonical form (E-2)", 3, 6)
	}
	if !ps.Exploitable() || schema.Valider(schema.Dossier+"#/$defs/manifeste_sig", ps.Valeur) != nil {
		return commun.Nouvelle("P-5", commun.Echoue, "", commun.T("manifeste.sig inexploitable ou contraire à son schéma", "manifeste.sig unusable or not following its schema"), 3, 6)
	}
	if a.Manifeste == nil || !a.PeriodHashOK {
		return prerequis("P-5", "manifeste.json inexploitable ou sans forme canonique", "manifeste.json unusable or without canonical form", 3, 6)
	}
	sig := ps.Valeur
	ph := cryptographie.Hex32(a.PeriodHash)
	var ecarts []string
	if sig.Membre("period_hash").S() != ph {
		ecarts = append(ecarts, "periodHash recalculé "+ph+" ≠ period_hash "+sig.Membre("period_hash").S())
	}
	kid := sig.Membre("recorder_key_id").S()
	if a.Manifeste.Membre("recorder_key_id").S() != kid {
		ecarts = append(ecarts, "manifeste.recorder_key_id ≠ manifeste.sig.recorder_key_id")
	}
	cleOK := a.ClesExploitables
	if cleOK {
		c, trouvee := a.Cles[kid]
		if !trouvee {
			ecarts = append(ecarts, "clé "+kid+" absente de cles.json")
		} else {
			cm, _ := jcs.Canonique(a.Manifeste)
			s, _ := cryptographie.LireHex(sig.Membre("sig").S(), 64)
			if !cryptographie.VerifierEd25519(c.Octets, append(append([]byte{}, cryptographie.PrefixeSignatureManifeste...), cm...), s) {
				ecarts = append(ecarts, "signature du manifeste invalide sous "+kid)
			}
			g, okG := commun.LireHorodatage(a.Manifeste.Membre("generated_at").S())
			if !okG || g.Before(c.Debut) || (c.Fin != nil && g.After(*c.Fin)) {
				ecarts = append(ecarts, "generated_at hors de la validité de "+kid)
			}
		}
	}
	if second != nil {
		if e := a.continuite(second); e != "" {
			ecarts = append(ecarts, e)
		}
	}
	if len(ecarts) > 0 {
		s := strings.Join(ecarts, " ; ")
		return commun.Nouvelle("P-5", commun.Echoue, "", commun.T(s, s), 3, 6)
	}
	if !cleOK {
		return prerequis("P-5", "cles.json inexploitable (E-8)", "cles.json unusable (E-8)", 3, 6)
	}
	d := "periodHash " + ph + " signé par " + kid
	de := "periodHash " + ph + " signed by " + kid
	if second != nil {
		d += " ; continuité avec le second manifeste vérifiée"
		de += "; continuity with the second manifest checked"
	}
	return commun.Nouvelle("P-5", commun.Reussi, "", commun.T(d, de), 3, 6)
}

// continuite applique CT-1 §10.3 entre le manifeste et le second manifeste
// (EX-4.7) ; elle rend le motif d'un échec, ou "".
func (a *Analyse) continuite(second *jsonv.Valeur) string {
	m := a.Manifeste
	if second.Membre("org_id").S() != m.Membre("org_id").S() || second.Membre("journal_id").S() != m.Membre("journal_id").S() {
		return "second manifeste d'un autre journal"
	}
	cs, err := jcs.Canonique(second)
	if err != nil {
		return "second manifeste sans forme canonique"
	}
	phSecond := cryptographie.Sha256(cryptographie.PrefixeManifeste, cs)
	s1, _ := m.Membre("period_start").Entier()
	s2, _ := second.Membre("period_start").Entier()
	var p, q *jsonv.Valeur
	var phP [32]byte
	switch {
	case s2 < s1:
		p, q, phP = second, m, phSecond
	case s2 > s1:
		p, q, phP = m, second, a.PeriodHash
	default:
		return "second manifeste ni précédent ni suivant"
	}
	pe, _ := p.Membre("period_end").Entier()
	qs, _ := q.Membre("period_start").Entier()
	pl, _ := p.Membre("last_seq").Entier()
	qf, _ := q.Membre("first_seq").Entier()
	if qs != pe || qf != pl+1 || q.Membre("prev_period_hash").S() != cryptographie.Hex32(phP) {
		return "continuité de CT-1 §10.3 rompue avec le second manifeste"
	}
	return ""
}

// --- A-1 à A-4 -------------------------------------------------------------

// enveloppeApprobations valide approbations.json contre son schéma, sauf les
// événements de `events`, qui relèvent de E-1 (comme ceux de voisins.json
// relèvent de E-1 et non de C-1, CT-1 §11.4).
func enveloppeApprobations(v *jsonv.Valeur) bool {
	if !v.EstObjet() || v.Doublon {
		return false
	}
	base := schema.Dossier + "#/$defs/approbations/properties/"
	for _, nom := range v.Noms() {
		switch nom {
		case "version", "ticket", "request_hash", "approver_set":
			if schema.Valider(base+nom, v.Membre(nom)) != nil {
				return false
			}
		case "events":
			ev := v.Membre("events")
			if !ev.EstTableau() || len(ev.Elements) < 1 || len(ev.Elements) > 1024 {
				return false
			}
			for _, e := range ev.Elements {
				if !e.EstObjet() {
					return false
				}
			}
		default:
			return false
		}
	}
	for _, nom := range []string{"version", "ticket", "request_hash", "approver_set", "events"} {
		if !v.A(nom) {
			return false
		}
	}
	return true
}

// RaisonSansApprobation : raison d'absence exigée à l'identique de
// approbations.json quand approval est nul (CT-1 §11.1, révision 0.5 ; A-1).
const RaisonSansApprobation = "aucune approbation liée"

// verificationsA : A-1 à A-4 (CT-1 §11.4, révision 0.5 ; CT-6 EX-5.16,
// EX-5.18).
func (a *Analyse) verificationsA() {
	ev := a.Evenement
	pa := a.Dossier.Partie(PApprobations)
	if ev == nil {
		for _, id := range []string{"A-1", "A-2", "A-3", "A-4"} {
			a.ajouter(prerequis(id, "evenement.json inexploitable", "evenement.json unusable", 7))
		}
		return
	}
	ap := ev.V.Membre("approval")
	present := pa != nil && pa.Present
	raison := ""
	if pa != nil && !pa.Present {
		raison = pa.Raison
	}
	// approval nul : la partie doit être déclarée absente avec la raison
	// exacte « aucune approbation liée » ; A-2 à A-4 sont alors non
	// exécutées, partie absente. Partie présente, ou absente sous une autre
	// raison : A-1 en échec, A-2 à A-4 prerequis_en_echec.
	if ap.EstNul() {
		switch {
		case present:
			a.ajouter(commun.Nouvelle("A-1", commun.Echoue, "", commun.T("approbations.json déclaré présent alors que approval est nul", "approbations.json declared present while approval is null"), 7))
		case raison != RaisonSansApprobation:
			a.ajouter(commun.Nouvelle("A-1", commun.Echoue, "", commun.T("approval nul, mais approbations.json déclaré absent avec la raison « "+raison+" », et non « "+RaisonSansApprobation+" »", "null approval, but approbations.json declared absent with reason “"+raison+"”, not “"+RaisonSansApprobation+"”"), 7))
		default:
			a.ajouter(commun.Nouvelle("A-1", commun.Reussi, "", commun.T(RaisonSansApprobation, "no linked approval"), 7))
			for _, id := range []string{"A-2", "A-3", "A-4"} {
				a.ajouter(commun.Nouvelle(id, commun.NonExecute, commun.PartieAbsente, commun.T("approbations.json absent ("+raison+")", "approbations.json absent ("+raison+")"), 7))
			}
			return
		}
		for _, id := range []string{"A-2", "A-3", "A-4"} {
			a.ajouter(prerequis(id, "A-1 en échec : approval nul et approbations.json mal déclaré", "A-1 failed: null approval and approbations.json wrongly declared", 7))
		}
		return
	}
	if !ap.EstObjet() {
		// approval ni nul ni objet (E-1 porte le défaut de schéma) : les
		// relations qui lisent ses membres ne sont pas tenues (CT-1 §11.4,
		// révision 0.5).
		for _, id := range []string{"A-1", "A-2", "A-3", "A-4"} {
			a.ajouter(commun.Nouvelle(id, commun.Echoue, "", commun.T("approval n'est ni nul ni un objet", "approval is neither null nor an object"), 7))
		}
		return
	}
	// A-1
	a1 := func() commun.Verification {
		switch {
		case !present:
			return commun.Nouvelle("A-1", commun.Echoue, "", commun.T("approval non nul sans approbations.json", "non-null approval without approbations.json"), 7)
		case pa.Lecture.Etat == entree.Absent:
			return prerequis("A-1", "approbations.json absent du répertoire (D-2)", "approbations.json missing from the directory (D-2)", 7)
		case pa.SansForme():
			return prerequis("A-1", "approbations.json sans forme canonique (E-2)", "approbations.json without canonical form (E-2)", 7)
		case !pa.Exploitable():
			return commun.Nouvelle("A-1", commun.Echoue, "", commun.T("approbations.json inexploitable (limite de taille, pas du JSON ou pas un objet)", "approbations.json unusable (size limit, not JSON or not an object)"), 7)
		}
		var ecarts, ecartsEn []string
		if !enveloppeApprobations(pa.Valeur) {
			ecarts, ecartsEn = append(ecarts, "approbations.json contraire au schéma de son enveloppe"), append(ecartsEn, "approbations.json does not follow its envelope schema")
		}
		if t := pa.Valeur.Membre("ticket"); !t.EstChaine() || t.Chaine != ap.Membre("ticket").S() || !ap.Membre("ticket").EstChaine() {
			ecarts, ecartsEn = append(ecarts, "ticket différent de celui de approval"), append(ecartsEn, "ticket differs from that of approval")
		}
		if r := pa.Valeur.Membre("request_hash"); !r.EstChaine() || r.Chaine != ap.Membre("request_hash").S() || !ap.Membre("request_hash").EstChaine() {
			ecarts, ecartsEn = append(ecarts, "request_hash différent de celui de approval"), append(ecartsEn, "request_hash differs from that of approval")
		}
		if len(ecarts) > 0 {
			return commun.Nouvelle("A-1", commun.Echoue, "", commun.T("approbations.json : "+strings.Join(ecarts, " ; "), "approbations.json: "+strings.Join(ecartsEn, "; ")), 7)
		}
		t := ap.Membre("ticket").S()
		return commun.Nouvelle("A-1", commun.Reussi, "", commun.T("ticket "+t, "ticket "+t), 7)
	}()
	a.ajouter(a1)
	// A-2 et A-3 ne dépendent pas de A-1 (CT-6 EX-5.16) : elles s'exécutent
	// sur approbations.json exploitable, même contraire au schéma de son
	// enveloppe, et sont non exécutées (prerequis_en_echec) quand la partie
	// est déclarée absente, absente du répertoire ou inexploitable.
	if !present || !pa.Exploitable() {
		a.ajouter(prerequis("A-2", "approbations.json absent ou inexploitable", "approbations.json missing or unusable", 7))
		a.ajouter(prerequis("A-3", "approbations.json absent ou inexploitable", "approbations.json missing or unusable", 7))
	} else {
		a.ajouter(a.a2(ap, pa.Valeur))
		a.ajouter(a.a3(ap, pa.Valeur))
	}
	a.ajouter(a.a4(ap))
}

func (a *Analyse) a2(ap, approbations *jsonv.Valeur) commun.Verification {
	ev := a.Evenement
	seq, _ := ev.Seq()
	ts, _ := ev.Ts()
	estDecision := ev.Outil() == OutilDecision
	var ecarts []string
	if !approbations.Membre("events").EstTableau() {
		ecarts = append(ecarts, "events n'est pas un tableau")
	}
	for _, i := range a.decisionsInvalides {
		ecarts = append(ecarts, fmt.Sprintf("approbation[%d] n'est pas un objet", i))
	}
	trouve := false
	for _, d := range a.Decisions {
		if d.Outil() != OutilDecision {
			ecarts = append(ecarts, d.Role.Fr+" n'est pas une décision d'approbation")
		}
		if !jsonv.Egales(d.V.Membre("approval"), ap) {
			ecarts = append(ecarts, d.Role.Fr+" : approval différent de celui de l'événement prouvé")
		}
		A, errA := jcs.Canonique(objetA(d.V.Membre("approval"), d.V.Membre("org_id").S(), d.V.Membre("journal_id").S()))
		val, errV := jcs.Canonique(d.V.Chemin("execution", "arguments", "value"))
		if errA != nil || errV != nil || string(A) != string(val) {
			ecarts = append(ecarts, d.Role.Fr+" : arguments.value ≠ A")
		}
		if estDecision {
			if d.HashOK() && ev.HashOK() && d.Hash == ev.Hash {
				trouve = true
			}
		} else {
			ds, _ := d.Seq()
			at, okAt := commun.LireHorodatage(d.V.Chemin("approval", "at").S())
			if ds >= seq || !okAt || at.After(ts) {
				ecarts = append(ecarts, d.Role.Fr+" ne précède pas l'événement prouvé")
			}
		}
	}
	if estDecision && !trouve {
		if !ev.HashOK() {
			return prerequis("A-2", "hachage non recalculable (E-2)", "hash not recomputable (E-2)", 7)
		}
		ecarts = append(ecarts, "l'événement prouvé, une décision, ne figure pas dans events")
	}
	if len(ecarts) > 0 {
		s := strings.Join(ecarts, " ; ")
		return commun.Nouvelle("A-2", commun.Echoue, "", commun.T(s, s), 7)
	}
	n := len(a.Decisions)
	return commun.Nouvelle("A-2", commun.Reussi, "", commun.T(fmt.Sprintf("%d événement(s) de décision cohérent(s)", n), fmt.Sprintf("%d consistent decision event(s)", n)), 7)
}

func (a *Analyse) a3(ap, approbations *jsonv.Valeur) commun.Verification {
	jeu := approbations.Membre("approver_set")
	membres := map[string]bool{}
	for _, m := range jeu.Membre("members").Elements {
		membres[m.S()] = true
	}
	req, _ := jeu.Chemin("threshold", "required").Entier()
	taille, _ := jeu.Chemin("threshold", "size").Entier()
	var ecarts []string
	if !jsonv.Egales(ap.Membre("threshold"), jeu.Membre("threshold")) {
		ecarts = append(ecarts, "threshold de l'événement ≠ approver_set.threshold")
	}
	if req > taille || taille != int64(len(jeu.Membre("members").Elements)) {
		ecarts = append(ecarts, "required > size, ou size ≠ nombre de members")
	}
	adr := ap.Membre("approvers").Elements
	vus := map[string]bool{}
	for _, x := range adr {
		if vus[x.S()] {
			ecarts = append(ecarts, "approbateur en double "+x.S())
		}
		vus[x.S()] = true
		if !membres[x.S()] {
			ecarts = append(ecarts, "approbateur hors du jeu déclaré "+x.S())
		}
	}
	decision := ap.Membre("decision").S()
	if decision == "expire" {
		if len(ap.Membre("signatures").Elements) != 0 || len(adr) != 0 {
			ecarts = append(ecarts, "demande expirée qui porte des signatures")
		}
	} else if int64(len(vus)) < req {
		ecarts = append(ecarts, fmt.Sprintf("%d approbateur(s) pour un seuil de %d", len(vus), req))
	}
	if len(ecarts) > 0 {
		s := strings.Join(ecarts, " ; ")
		return commun.Nouvelle("A-3", commun.Echoue, "", commun.T(s, s), 7)
	}
	if decision == "expire" {
		return commun.Nouvelle("A-3", commun.Reussi, "", commun.T(fmt.Sprintf("demande expirée sans signature, seuil de %d/%d", req, taille), fmt.Sprintf("request expired without signature, threshold %d/%d", req, taille)), 7)
	}
	return commun.Nouvelle("A-3", commun.Reussi, "", commun.T(fmt.Sprintf("%d approbateur(s) distinct(s) sur un seuil de %d/%d", len(vus), req, taille), fmt.Sprintf("%d distinct approver(s) for a threshold of %d/%d", len(vus), req, taille)), 7)
}

func (a *Analyse) a4(ap *jsonv.Valeur) commun.Verification {
	rh := ap.Membre("request_hash").S()
	// voisins.json inexploitable : non exécutée, sans raison admise (CT-1
	// §11.4, révision 0.5 ; CT-6 EX-5.18).
	if !a.voisinsLus {
		return prerequis("A-4", "voisins.json inexploitable : événement de demande non recherché", "voisins.json unusable: request event not looked for", 7)
	}
	for _, v := range []*Evt{a.Precedent, a.Suivant} {
		if v == nil || !v.HashOK() || v.HashHex() != rh {
			continue
		}
		st := v.V.Chemin("execution", "status").S()
		if st != "retenue" {
			return commun.Nouvelle("A-4", commun.Echoue, "", commun.T("événement de demande "+rh+" ("+v.Role.Fr+") de status "+st+", et non retenue", "request event "+rh+" ("+v.Role.En+") with status "+st+", not retenue"), 7)
		}
		return commun.Nouvelle("A-4", commun.Reussi, "", commun.T("événement de demande "+rh+" ("+v.Role.Fr+"), status retenue", "request event "+rh+" ("+v.Role.En+"), status retenue"), 7)
	}
	return commun.Nouvelle("A-4", commun.NonExecute, commun.PieceHorsDossier, commun.T("événement de demande (request_hash "+rh+") absent du dossier : non vérifiable", "request event (request_hash "+rh+") not in the dossier: cannot be checked"), 7)
}
