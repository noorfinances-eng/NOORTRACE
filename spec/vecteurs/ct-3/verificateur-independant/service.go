// Machine à états du service d'approbation (CT-3 sections 7, 8 et 10) :
// tickets (états 7.3, entrées 7.4, transitions T1 à T21 de 7.5, minuteurs
// d'EX-7.7, délais 7.6), clé de rapprochement (EX-7.3), ré-émissions
// (EX-7.16 à EX-7.19), jeu d'approbateurs épinglé (8.1 à 8.4, seuil
// effectif d'EX-8.6), votes et décompte (EX-7.26 à EX-7.29), séparation des
// tâches et récusation (10.1), objections (10.2), remises (12.5, EX-7.28),
// acquittements et expirations du noyau (12.5, 12.6) et fenêtres (EX-5.4 à
// EX-5.6, EX-4.12).
//
// La machine est jouée sur les traces de l'annexe A.6 : une trace fournit,
// pour chaque evaluer, la sortie d'EVALUER (data.evaluation) ; le service
// n'évalue donc aucune règle ici (sections 4 à 6 : familles evaluation et
// acceptation).

package main

import (
	"fmt"
	"sort"
	"strings"
)

// Lecture est une lecture du jeu (EX-8.1) : objet jeu de ticket-v0.
type Lecture struct {
	ChainID  *int64
	Registre string // "" : null
	Set      string // "" : null
	Hauteur  *int64
	Bloc     string // "" : null
	Seuil    Seuil
	Membres  []string
	Statique bool
}

// meme compare deux jeux sur ce qui les distingue (EX-8.6 : « adresse du
// jeu, t, n ou membres »).
func (l *Lecture) meme(o *Lecture) bool {
	if l.Set != o.Set || l.Seuil != o.Seuil || len(l.Membres) != len(o.Membres) {
		return false
	}
	for i := range l.Membres {
		if l.Membres[i] != o.Membres[i] {
			return false
		}
	}
	return true
}

func (l *Lecture) membre(a string) bool {
	for _, m := range l.Membres {
		if m == a {
			return true
		}
	}
	return false
}

// LireJeu lit l'objet jeu de ticket-v0 ; les membres sont écrits en
// minuscules et triés (EX-8.1, point 6).
func LireJeu(v *Value) *Lecture {
	l := &Lecture{Registre: v.Get("registry").S(), Set: v.Get("set").S(), Bloc: v.Get("block_hash").S()}
	if n, ok := EntierJSON(v.Get("chain_id")); ok {
		l.ChainID = &n
	}
	if n, ok := EntierJSON(v.Get("height")); ok {
		l.Hauteur = &n
	}
	rq, _ := EntierJSON(v.Get("threshold").Get("required"))
	sz, _ := EntierJSON(v.Get("threshold").Get("size"))
	l.Seuil = Seuil{Required: rq, Size: sz}
	for _, m := range v.Get("members").Arr {
		l.Membres = append(l.Membres, strings.ToLower(m.Str))
	}
	sort.Strings(l.Membres)
	return l
}

// Vote est un vote accepté (EX-7.26).
type Vote struct {
	At          Instant
	Approbateur string
	Decision    string
	Signature   string // forme normalisée (EX-9.3)
	Motif       *Value // chaîne ou null
	Statut      string // courant, remplace, ecarte
	Cause       string
}

// Objection est un vote refuse accepté pendant une fenêtre de contestation
// (EX-10.7).
type Objection struct {
	Auteur string
	At     Instant
	Levee  bool
}

// Remise est la remise d'une décision au noyau (12.5).
type Remise struct {
	ID           string
	Ticket       string
	Decision     string
	RequestHash  string
	Seuil        Seuil
	Approbateurs []string
	Signatures   []string
	Motif        *Value
	Membres      []string
	Source       string
}

// ApprovalSansAt rend approval sans at ($defs/approval_sans_at).
func (r *Remise) ApprovalSansAt() *Value {
	return Objet("decision", Chaine(r.Decision), "ticket", Chaine(r.Ticket), "request_hash", Chaine(r.RequestHash),
		"threshold", seuilJSON(r.Seuil), "approvers", TableauChaines(r.Approbateurs),
		"signatures", TableauChaines(r.Signatures), "reason", Copier(r.Motif))
}

// Approval rend l'objet approval scellé, at compris (CT-1 §5.3).
func (r *Remise) Approval(at Instant) *Value {
	a := r.ApprovalSansAt()
	reason := a.Obj[len(a.Obj)-1]
	a.Obj = append(a.Obj[:len(a.Obj)-1], Member{Key: "at", Val: Chaine(at.String())}, reason)
	return a
}

// JSON rend $defs/remise.
func (r *Remise) JSON() *Value {
	return Objet("remise_id", Chaine(r.ID), "ticket", Chaine(r.Ticket), "approval", r.ApprovalSansAt(),
		"approver_set", Objet("threshold", seuilJSON(r.Seuil), "members", TableauChaines(r.Membres), "source", Chaine(r.Source)))
}

func seuilJSON(s Seuil) *Value {
	return Objet("required", Entier(s.Required), "size", Entier(s.Size))
}

// Scellement est ce que le noyau dit d'une décision scellée : decision,
// seq, hash, at et l'objet approval qu'il a scellé, gardé tel qu'il est
// reçu (12.5, 12.6).
type Scellement struct {
	Decision string
	Seq      int64
	Hash     string
	At       Instant
	Approval *Value
}

// Ticket est l'état d'un ticket (7.3).
type Ticket struct {
	ID         string
	Etat       string
	Cle        string
	CleLiberee bool
	Regle      string
	ContestMs  int64
	Ouverture  *Ouverture
	PV         string
	LaunchedBy string
	AdrDem     []string
	AutoAppr   string
	ReserveA   Instant

	Ouvert      bool   // ouvrir accepté (échéance fixée)
	RequestHash string // "" : inconnu ; inscrit par ouvrir, ou par T17 depuis reserve ou abandonne
	RequestSeq  int64
	RequestTs   Instant
	Echeance    Instant

	Jeu       *Lecture // jeu figé (8.2)
	Derniere  *Lecture // dernière confirmation du jeu figé (EX-8.8)
	EffReq    int64    // seuil effectif : le plus grand required figé (EX-8.6)
	Reassigne bool     // dernière lecture : jeu_non_attendu (EX-7.11)
	Recuses   map[string]bool
	Votes     []*Vote
	Objection []*Objection
	FinContes *Instant
	Calculee  string // décision calculée en verification
	EntreeVer Instant

	Remises   []*Remise
	Courante  *Remise
	Scelle    *Scellement
	FinRecon  *Instant
	Servi     bool // T21 : l'approbation a été servie
	Consomme  *[2]string
	Acquittes []string // données (JCS) des acquitter acceptés, pour EX-7.20
}

func (t *Ticket) actif() bool {
	if t.CleLiberee {
		return false
	}
	switch t.Etat {
	case "consomme", "clos", "abandonne":
		return false
	}
	return true
}

func (t *Ticket) nonDecide() bool {
	switch t.Etat {
	case "reserve", "ouvert", "seuil_atteint", "verification", "a_remettre":
		return true
	}
	return false
}

func (t *Ticket) decide() bool {
	return t.Etat == "approuve" || t.Etat == "refuse" || t.Etat == "expire"
}

func (t *Ticket) collecte() bool {
	return t.Etat == "ouvert" || t.Etat == "seuil_atteint" || t.Etat == "verification"
}

// Service est l'état du service d'approbation pour une trace.
type Service struct {
	OrgID, JournalID string
	PV               string
	Charges          map[string]bool
	E                int64
	Source           string // registre ou statique
	Epingle          string // adresse du jeu épinglé par la politique (EX-8.1), "" pour un jeu statique
	Statique         *Lecture
	AutoAppr         string
	Identites        []Identite
	MaxOuverts       int64
	Administrateurs  []string // contacts qui peuvent retirer (EX-7.15, 10.3)
	Repli            *Lecture
	Tickets          []*Ticket
	Compteur         int
	Fenetres         []*Fenetre

	pas            []*Remise // remises calculées pendant le pas
	Avertissements []string
}

// Resultat est le sort d'une entrée (A.6).
type Resultat struct {
	Accepte bool
	Raison  string
	Reponse *Value
}

func refus(raison string) Resultat { return Resultat{Accepte: false, Raison: raison} }

func (s *Service) ticket(id string) *Ticket {
	for _, t := range s.Tickets {
		if t.ID == id {
			return t
		}
	}
	return nil
}

func (s *Service) avertir(format string, args ...any) {
	s.Avertissements = append(s.Avertissements, fmt.Sprintf(format, args...))
}

// ----------------------------------------------------------- minuteurs

// Ordre des minuteurs à instant égal (EX-7.7) : échéance, fin de
// contestation, fin de réservation, fin de reconnaissance, escalade (sans
// effet sur l'état, non jouée ici), fin de fenêtre.
const (
	mEcheance = iota
	mContestation
	mReservation
	mReconnaissance
	mEscalade
	mFenetre
)

type minuteur struct {
	at    Instant
	ordre int
	t     *Ticket
	w     *Fenetre
}

func (m *minuteur) id() string {
	if m.t != nil {
		return m.t.ID
	}
	return m.w.Ticket
}

func (s *Service) prochainMinuteur(limite Instant) *minuteur {
	var best *minuteur
	prendre := func(m minuteur) {
		if m.at > limite {
			return
		}
		if best == nil || m.at < best.at || (m.at == best.at && (m.ordre < best.ordre || (m.ordre == best.ordre && m.id() < best.id()))) {
			mm := m
			best = &mm
		}
	}
	for _, t := range s.Tickets {
		// Échéance : ticket en collecte, ou a_remettre avec une remise
		// courante approuve ou refuse (T9, T13).
		if t.collecte() || (t.Etat == "a_remettre" && t.Courante != nil && t.Courante.Decision != "expire") {
			prendre(minuteur{at: t.Echeance, ordre: mEcheance, t: t})
		}
		if t.Etat == "seuil_atteint" && t.FinContes != nil {
			prendre(minuteur{at: *t.FinContes, ordre: mContestation, t: t})
		}
		if t.Etat == "reserve" {
			prendre(minuteur{at: t.ReserveA + Instant(s.E), ordre: mReservation, t: t})
		}
		if t.decide() && t.FinRecon != nil {
			prendre(minuteur{at: *t.FinRecon, ordre: mReconnaissance, t: t})
		}
	}
	for _, w := range s.Fenetres {
		prendre(minuteur{at: w.Fin, ordre: mFenetre, w: w})
	}
	return best
}

// declencher déclenche, avant une entrée d'instant at, les minuteurs échus
// (instant ≤ at), par instant croissant ; à instant égal dans l'ordre
// d'EX-7.7, puis par identifiant croissant.
func (s *Service) declencher(at Instant) {
	for i := 0; i < 100000; i++ {
		m := s.prochainMinuteur(at)
		if m == nil {
			return
		}
		t := m.t
		switch m.ordre {
		case mEcheance:
			if t.Etat == "a_remettre" { // T13
				s.remettre(t, s.remiseExpire(t, "decision non scellee avant l'echeance"))
			} else { // T9
				s.remettre(t, s.remiseExpire(t, s.raisonEcheance(t)))
			}
		case mContestation: // T7
			t.FinContes = nil
			s.verifier(t, "approuve", m.at)
		case mReservation: // T3
			t.Etat = "abandonne"
			t.CleLiberee = true
		case mReconnaissance: // T19
			t.Etat = "clos"
		case mFenetre: // EX-5.6 : à t = fin, la fenêtre est retirée
			for i, w := range s.Fenetres {
				if w == m.w {
					s.Fenetres = append(s.Fenetres[:i], s.Fenetres[i+1:]...)
					break
				}
			}
		}
	}
}

// raisonEcheance applique EX-7.11 à un ticket en collecte à l'échéance.
func (s *Service) raisonEcheance(t *Ticket) string {
	switch {
	case t.Jeu == nil:
		return "echeance atteinte, jeu d'approbateurs illisible"
	case t.Reassigne:
		return "echeance atteinte, jeu reassigne"
	case int64(len(s.eligibles(t))) < t.EffReq:
		return "echeance atteinte, seuil inatteignable"
	case len(t.objectionsOuvertes()) > 0:
		return "echeance atteinte, objection non levee"
	case t.Etat == "seuil_atteint":
		return "echeance atteinte pendant la fenetre de contestation"
	}
	return "echeance atteinte sans decision"
}

// --------------------------------------------------------- jeu et source

// sourceDe écrit la source d'EX-8.8 : jeu statique de la version pv, ou
// jeu lu (hauteur de gel, hauteur et bloc de confirmation, « repli »).
func sourceDe(pv string, jeu *Lecture, confirmation *Lecture, repli bool) string {
	if jeu.Statique {
		return "jeu statique de la politique " + pv
	}
	cid := int64(0)
	if jeu.ChainID != nil {
		cid = *jeu.ChainID
	}
	h1, h2 := int64(0), int64(0)
	if jeu.Hauteur != nil {
		h1 = *jeu.Hauteur
	}
	if confirmation.Hauteur != nil {
		h2 = *confirmation.Hauteur
	}
	src := fmt.Sprintf("CuratorSet c=%d r=%s s=%s h=%d..%d b=%s", cid, jeu.Registre, jeu.Set, h1, h2, confirmation.Bloc)
	if repli {
		src += " repli"
	}
	return src
}

// jeuNonFige rend le jeu qu'un ticket sans jeu figé déclare : jeu statique
// de la politique, sinon jeu de repli (EX-8.4, EX-8.8).
func (s *Service) jeuNonFige(pv string) (Seuil, []string, string, bool) {
	switch {
	case s.Statique != nil:
		return s.Statique.Seuil, s.Statique.Membres, sourceDe(pv, s.Statique, s.Statique, false), true
	case s.Repli != nil:
		return s.Repli.Seuil, s.Repli.Membres, sourceDe(pv, s.Repli, s.Repli, true), true
	}
	return Seuil{}, []string{}, "", false
}

// jeuReponseNouveau rend le membre approver_set d'une réponse nouveau
// (EX-12.6) : le jeu que le ticket déclarerait s'il n'était jamais figé.
func (s *Service) jeuReponseNouveau(pv string) *Value {
	seuil, membres, source, ok := s.jeuNonFige(pv)
	if !ok {
		s.avertir("réponse nouveau sans jeu de repli")
	}
	return Objet("threshold", seuilJSON(seuil), "members", TableauChaines(membres), "source", Chaine(source))
}

// remiseExpire construit la remise d'une décision expire (EX-7.11,
// EX-8.8) : jeu figé et dernière confirmation du ticket, ou jeu de repli
// pour un ticket jamais figé (EX-8.4).
func (s *Service) remiseExpire(t *Ticket, raison string) *Remise {
	r := &Remise{Ticket: t.ID, Decision: "expire", RequestHash: t.RequestHash, Approbateurs: []string{}, Signatures: []string{}, Motif: Chaine(raison)}
	if t.Jeu != nil {
		r.Seuil, r.Membres, r.Source = t.Jeu.Seuil, t.Jeu.Membres, sourceDe(t.PV, t.Jeu, t.Derniere, false)
		return r
	}
	var ok bool
	r.Seuil, r.Membres, r.Source, ok = s.jeuNonFige(t.PV)
	if !ok {
		s.avertir("%s : décision expire sans jeu de repli", t.ID)
	}
	return r
}

// remettre présente une remise : remise_id <ticket>/<n> (12.5), état
// a_remettre.
func (s *Service) remettre(t *Ticket, r *Remise) {
	r.ID = fmt.Sprintf("%s/%d", t.ID, len(t.Remises)+1)
	t.Remises = append(t.Remises, r)
	t.Courante = r
	t.Etat = "a_remettre"
	t.FinContes = nil
	t.Calculee = ""
	s.pas = append(s.pas, r)
}

// ------------------------------------------------- éligibles et décompte

func contient(l []string, a string) bool {
	for _, x := range l {
		if x == a {
			return true
		}
	}
	return false
}

// eligibles applique 10.1 : membres du jeu figé, moins les adresses du
// demandeur si self_approval vaut interdite, moins les récusés.
func (s *Service) eligibles(t *Ticket) []string {
	out := []string{}
	if t.Jeu == nil {
		return out
	}
	for _, m := range t.Jeu.Membres {
		if t.AutoAppr == "interdite" && contient(t.AdrDem, m) {
			continue
		}
		if t.Recuses[m] {
			continue
		}
		out = append(out, m)
	}
	return out
}

func (t *Ticket) objectionsOuvertes() []*Objection {
	var out []*Objection
	for _, o := range t.Objection {
		if !o.Levee {
			out = append(out, o)
		}
	}
	return out
}

func (t *Ticket) voteCourant(a string) *Vote {
	for _, v := range t.Votes {
		if v.Approbateur == a && v.Statut == "courant" {
			return v
		}
	}
	return nil
}

// recuseMembre : membre du jeu figé qui s'est récusé ; son vote refuse
// reste compté (EX-10.4).
func (t *Ticket) recuseMembre(a string) bool {
	return t.Recuses[a] && t.Jeu.membre(a)
}

// ecarterIneligibles écarte les votes courants des membres qui ne sont plus
// éligibles (EX-10.3, EX-8.6), sauf le vote refuse d'un membre récusé
// (EX-10.4).
func (s *Service) ecarterIneligibles(t *Ticket) {
	el := s.eligibles(t)
	for _, v := range t.Votes {
		if v.Statut != "courant" || contient(el, v.Approbateur) {
			continue
		}
		if v.Decision == "refuse" && t.recuseMembre(v.Approbateur) {
			continue
		}
		v.Statut = "ecarte"
		switch {
		case !t.Jeu.membre(v.Approbateur):
			v.Cause = "hors_jeu"
		case t.Recuses[v.Approbateur]:
			v.Cause = "recuse"
		default:
			v.Cause = "auto_approbation"
		}
	}
}

// comptes rend, dans l'ordre d'acceptation, les votes courants qui comptent
// pour dec (EX-7.27) : ceux des éligibles ; pour refuse, aussi ceux des
// membres récusés (EX-10.4).
func (s *Service) comptes(t *Ticket, dec string) []*Vote {
	el := s.eligibles(t)
	var out []*Vote
	for _, v := range t.Votes {
		if v.Statut != "courant" || v.Decision != dec {
			continue
		}
		if contient(el, v.Approbateur) || (dec == "refuse" && t.recuseMembre(v.Approbateur)) {
			out = append(out, v)
		}
	}
	return out
}

// decompte applique EX-7.27 à l'instant at, avec le seuil effectif.
func (s *Service) decompte(t *Ticket, at Instant) {
	if t.Jeu == nil {
		return
	}
	a := int64(len(s.comptes(t, "approuve")))
	r := int64(len(s.comptes(t, "refuse")))
	seuil := t.EffReq
	switch {
	case r >= seuil:
		s.verifier(t, "refuse", at)
	case a >= seuil && t.ContestMs == 0:
		s.verifier(t, "approuve", at)
	case a >= seuil && len(t.objectionsOuvertes()) == 0:
		if t.Etat == "seuil_atteint" || (t.Etat == "verification" && t.Calculee == "approuve") {
			return
		}
		t.Etat = "seuil_atteint"
		fin := at + Instant(t.ContestMs)
		t.FinContes = &fin
		t.Calculee = ""
	default:
		t.Etat = "ouvert"
		t.FinContes = nil
		t.Calculee = ""
	}
}

// verifier fait entrer un ticket en verification avec une décision ; un
// décompte qui rend la décision déjà calculée laisse l'état et son instant
// d'entrée inchangés (EX-7.27). Un jeu statique est confirmé aussitôt
// (EX-8.7 : T8 suit l'entrée en verification).
func (s *Service) verifier(t *Ticket, dec string, at Instant) {
	if t.Etat == "verification" && t.Calculee == dec {
		return
	}
	t.Etat = "verification"
	t.Calculee = dec
	t.EntreeVer = at
	t.FinContes = nil
	if t.Jeu != nil && t.Jeu.Statique {
		s.confirmer(t, t.Jeu)
	}
}

// confirmer applique T8 : remise construite (12.5, EX-7.28) avec exactement
// t = seuil effectif signatures, approval.threshold = seuil du jeu figé et
// confirmé ; source de 8.4.
func (s *Service) confirmer(t *Ticket, lecture *Lecture) {
	r := &Remise{Ticket: t.ID, Decision: t.Calculee, RequestHash: t.RequestHash, Seuil: t.Jeu.Seuil,
		Membres: t.Jeu.Membres, Approbateurs: []string{}, Signatures: []string{}, Motif: Nul()}
	for _, v := range s.comptes(t, t.Calculee) {
		if int64(len(r.Approbateurs)) >= t.EffReq {
			break
		}
		r.Approbateurs = append(r.Approbateurs, v.Approbateur)
		r.Signatures = append(r.Signatures, v.Signature)
		r.Motif = Copier(v.Motif)
	}
	if int64(len(r.Approbateurs)) != t.EffReq {
		s.avertir("%s : %d vote(s) %s pour un seuil effectif de %d", t.ID, len(r.Approbateurs), t.Calculee, t.EffReq)
	}
	r.Source = sourceDe(t.PV, t.Jeu, lecture, false)
	s.remettre(t, r)
}

// geler fige un jeu (8.2, EX-8.6) : le seuil effectif ne baisse jamais ;
// éligibles recalculés, décompte.
func (s *Service) geler(t *Ticket, l *Lecture, at Instant) {
	t.Jeu, t.Derniere = l, l
	if l.Seuil.Required > t.EffReq {
		t.EffReq = l.Seuil.Required
	}
	s.ecarterIneligibles(t)
	s.decompte(t, at)
}

// ---------------------------------------------------------------- entrées

// Traiter traite une entrée de 7.4 (forme $defs/entree) et rend son sort.
func (s *Service) Traiter(kind string, at Instant, d *Value) Resultat {
	s.pas = nil
	s.declencher(at)
	switch kind {
	case "charger":
		pv := d.Get("policy_version").S()
		if pv != s.PV {
			s.Fenetres = nil // EX-4.12 : toute nouvelle version ferme toutes les fenêtres
		}
		s.PV = pv
		s.Charges[pv] = true
		return Resultat{Accepte: true, Reponse: Objet("policy_version", Chaine(pv))}
	case "evaluer":
		return s.evaluer(at, d)
	case "ouvrir":
		return s.ouvrir(at, d)
	case "jeu_lu":
		s.jeuLu(at, d)
		return Resultat{Accepte: true}
	case "voter":
		return s.voter(at, d)
	case "recuser":
		return s.recuser(at, d)
	case "retirer":
		return s.retirer(at, d)
	case "horloge":
		return Resultat{Accepte: true}
	case "acquitter":
		return s.acquitter(at, d)
	case "consommer":
		return s.consommer(d)
	case "expiration":
		return s.expiration(d)
	}
	return refus("requete_invalide")
}

// cleRapprochement rend la clé d'EX-7.3.
func (s *Service) cleRapprochement(req *Value) (string, error) {
	args := req.Get("arguments")
	if args == nil {
		args = Objet()
	}
	jcs, err := CanoniqueIntegral(args)
	if err != nil {
		return "", err
	}
	dl := req.Get("delegation")
	parts := []*Value{Chaine(s.OrgID), Chaine(s.JournalID), Copier(req.Get("code").Get("policy_version")),
		Copier(req.Get("tool_announced")), Chaine(string(jcs)), Copier(dl.Get("launched_by")),
		Copier(dl.Get("on_behalf_of")), Copier(dl.Get("scope"))}
	c, err := CanoniqueIntegral(Tableau(parts...))
	return string(c), err
}

// reponseEvaluer rend $defs/reponse_evaluer : approver_set n'est non nul que
// pour ticket_state nouveau (EX-12.6).
func reponseEvaluer(rule *Value, decision string, ticket, etat *string, approval, jeu *Value) *Value {
	if approval == nil {
		approval = Nul()
	}
	if jeu == nil {
		jeu = Nul()
	}
	return Objet("rule", rule, "decision", Chaine(decision), "ticket", ChaineOuNul(ticket),
		"ticket_state", ChaineOuNul(etat), "approval", approval, "approver_set", jeu)
}

func (s *Service) evaluer(at Instant, d *Value) Resultat {
	req := d.Get("request")
	if s.Source == "registre" && s.Repli == nil {
		return refus("non_pret") // EX-8.3
	}
	if !s.Charges[req.Get("code").Get("policy_version").S()] {
		return refus("politique_inconnue")
	}
	cle, err := s.cleRapprochement(req)
	if err != nil {
		s.avertir("clé de rapprochement : %v", err)
		return refus("requete_invalide")
	}
	for _, t := range s.Tickets {
		if !t.actif() || t.Cle != cle {
			continue
		}
		// ré-émission reconnue (EX-7.6, table d'EX-7.16)
		id := t.ID
		etat := ""
		regle := Chaine(t.Regle)
		switch t.Etat {
		case "reserve":
			etat = "nouveau"
			return Resultat{Accepte: true, Reponse: reponseEvaluer(regle, "a_approuver", &id, &etat, nil, s.jeuReponseNouveau(t.PV))}
		case "approuve":
			if !t.Servi { // EX-7.17, T21 : une seule requête reçoit approuve
				t.Servi = true
				etat = "approuve"
				return Resultat{Accepte: true, Reponse: reponseEvaluer(regle, "autorise", &id, &etat, Copier(t.Scelle.Approval), nil)}
			}
			etat = "en_attente"
			return Resultat{Accepte: true, Reponse: reponseEvaluer(regle, "a_approuver", &id, &etat, nil, nil)}
		case "refuse", "expire":
			etat = t.Etat
			return Resultat{Accepte: true, Reponse: reponseEvaluer(regle, "refuse", &id, &etat, Copier(t.Scelle.Approval), nil)}
		default:
			etat = "en_attente"
			return Resultat{Accepte: true, Reponse: reponseEvaluer(regle, "a_approuver", &id, &etat, nil, nil)}
		}
	}
	ev := d.Get("evaluation")
	dec := ev.Get("decision").S()
	if dec != "a_approuver" {
		s.consommerFenetre(ev.Get("rule").S(), dec)
		return Resultat{Accepte: true, Reponse: reponseEvaluer(Copier(ev.Get("rule")), dec, nil, nil, nil, nil)}
	}
	lb := req.Get("delegation").Get("launched_by").S()
	n := int64(0)
	for _, t := range s.Tickets {
		if t.LaunchedBy == lb && t.nonDecide() {
			n++
		}
	}
	if n >= s.MaxOuverts {
		return refus("plafond_atteint") // EX-14.1
	}
	// T1
	s.Compteur++
	pv := req.Get("code").Get("policy_version").S()
	t := &Ticket{ID: fmt.Sprintf("apr-%04d", s.Compteur), Etat: "reserve", Cle: cle, Regle: ev.Get("rule").S(),
		Ouverture: LireOuverture(ev.Get("opening")), PV: pv, LaunchedBy: lb,
		AutoAppr: s.AutoAppr, ReserveA: at, Recuses: map[string]bool{}}
	if c, ok := EntierJSON(ev.Get("contest_ms")); ok {
		t.ContestMs = c
	}
	t.AdrDem = []string{}
	for _, id := range s.Identites {
		if id.LaunchedBy == lb { // EX-10.1 : octet pour octet
			t.AdrDem = id.Adresses
		}
	}
	s.Tickets = append(s.Tickets, t)
	id, etat := t.ID, "nouveau"
	return Resultat{Accepte: true, Reponse: reponseEvaluer(Chaine(t.Regle), "a_approuver", &id, &etat, nil, s.jeuReponseNouveau(pv))}
}

// consommerFenetre retire une unité de la fenêtre nommée par la marque
// « [fenetre <ticket> <fin>] » d'une sortie autorise (EX-5.5, EX-6.5) ; une
// fenêtre épuisée est retirée (EX-5.6).
func (s *Service) consommerFenetre(rule, dec string) {
	if dec != "autorise" {
		return
	}
	i := strings.LastIndex(rule, " [fenetre ")
	if i < 0 {
		return
	}
	champs := strings.Fields(strings.TrimSuffix(rule[i+len(" [fenetre "):], "]"))
	if len(champs) != 2 {
		return
	}
	for k, w := range s.Fenetres {
		if w.Ticket == champs[0] && w.Fin.String() == champs[1] && w.Restant >= 1 {
			w.Restant--
			if w.Restant == 0 {
				s.Fenetres = append(s.Fenetres[:k], s.Fenetres[k+1:]...)
			}
			return
		}
	}
}

func (s *Service) ouvrir(at Instant, d *Value) Resultat {
	t := s.ticket(d.Get("ticket").S())
	if t == nil {
		return refus("ticket_inconnu")
	}
	rh := d.Get("request_hash").S()
	rts, err := LireInstant(d.Get("request_ts").S())
	if err != nil {
		return refus("requete_invalide")
	}
	if t.RequestHash != "" {
		// 12.4 : ouvrir répété, sans effet, rend l'état courant ; un autre
		// request_hash est refusé.
		if rh != t.RequestHash {
			return refus("ticket_deja_ouvert")
		}
		return Resultat{Accepte: true, Reponse: s.reponseOuvrir(t)}
	}
	if t.Etat != "reserve" && t.Etat != "abandonne" {
		return refus("requete_invalide")
	}
	if !reHex32.MatchString(rh) || rts > at { // garde de T2 et T4
		return refus("requete_invalide")
	}
	seq, _ := EntierJSON(d.Get("request_seq"))
	t.Ouvert, t.RequestHash, t.RequestSeq, t.RequestTs = true, rh, seq, rts
	t.Echeance = rts + Instant(s.E)
	if t.Etat == "abandonne" { // T4
		s.remettre(t, s.remiseExpire(t, "reservation abandonnee avant l'ouverture"))
		return Resultat{Accepte: true, Reponse: s.reponseOuvrir(t)}
	}
	t.Etat = "ouvert" // T2
	if s.Statique != nil {
		s.geler(t, s.Statique, at) // EX-8.4 : un jeu statique est figé aussitôt
	}
	return Resultat{Accepte: true, Reponse: s.reponseOuvrir(t)}
}

func (s *Service) reponseOuvrir(t *Ticket) *Value {
	dl := Nul()
	if t.Ouvert {
		dl = Chaine(t.Echeance.String())
	}
	return Objet("ticket", Chaine(t.ID), "state", Chaine(t.Etat), "deadline", dl)
}

func (s *Service) jeuLu(at Instant, d *Value) {
	if s.Source == "statique" {
		return // un jeu statique ne se relit pas
	}
	var l *Lecture
	if d.Get("status").S() == "lu" {
		l = LireJeu(d.Get("jeu"))
	}
	// EX-8.1 (pas 2) : une lecture d'un autre jeu que le jeu épinglé est
	// illisible (jeu_non_attendu) ; seul le jeu épinglé devient le jeu de
	// repli (EX-8.3).
	lu := l != nil && l.Set == s.Epingle
	cause := d.Get("cause").S()
	if l != nil && !lu {
		cause = "jeu_non_attendu"
	}
	if lu {
		s.Repli = l
	}
	ids := []*Ticket{}
	for _, t := range s.Tickets {
		if t.collecte() {
			ids = append(ids, t)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].ID < ids[j].ID })
	for _, t := range ids {
		if !lu { // T5 : inscrite ; jeu_non_attendu marque le ticket
			if cause == "jeu_non_attendu" {
				t.Reassigne = true
			}
			continue
		}
		t.Reassigne = false
		switch {
		case t.Jeu == nil: // premier lu : gel
			s.geler(t, l, at)
		case !t.Jeu.meme(l): // EX-8.6 : nouveau gel
			if t.Etat == "seuil_atteint" { // fenêtre de contestation annulée
				t.Etat, t.FinContes = "ouvert", nil
			}
			s.geler(t, l, at)
		default: // lu égal : hauteur de confirmation (T8)
			t.Derniere = l
			if t.Etat == "verification" && at >= t.EntreeVer {
				s.confirmer(t, l)
			}
		}
	}
}

// gardeCollecte applique les quatre premières raisons d'EX-9.10.
func (s *Service) gardeCollecte(id string) (*Ticket, string) {
	t := s.ticket(id)
	switch {
	case t == nil:
		return nil, "ticket_inconnu"
	case t.Etat == "reserve":
		return t, "ticket_non_ouvert"
	case !t.collecte():
		return t, "ticket_clos_aux_votes"
	case t.Jeu == nil:
		return t, "jeu_non_fige"
	}
	return t, ""
}

func (s *Service) gardeEligible(t *Ticket, a string) string {
	if !t.Jeu.membre(a) {
		return "hors_jeu"
	}
	if t.AutoAppr == "interdite" && contient(t.AdrDem, a) {
		return "auto_approbation"
	}
	if t.Recuses[a] {
		return "recuse"
	}
	return ""
}

func (s *Service) voter(at Instant, d *Value) Resultat {
	t, raison := s.gardeCollecte(d.Get("ticket").S())
	if raison != "" {
		return refus(raison)
	}
	a := d.Get("approver").S()
	dec := d.Get("decision").S()
	sig, err := NormaliserSignature(d.Get("signature").S())
	if err != nil {
		return refus("signature_invalide")
	}
	adr, err := AdresseVote(ObjetA(dec, s.JournalID, s.OrgID, t.RequestHash, t.ID), sig)
	if err != nil || adr != a {
		return refus("signature_invalide")
	}
	if r := s.gardeEligible(t, a); r != "" {
		return refus(r)
	}
	motif := d.Get("reason")
	if motif == nil {
		motif = Nul()
	}
	if motif.Kind == KindString && PointsDeCode(motif.Str) > 1024 {
		return refus("motif_trop_long")
	}
	cour := t.voteCourant(a)
	if cour != nil && cour.Decision == dec { // EX-9.10 : même décision, quel que soit le motif
		return refus("vote_identique")
	}
	if dec == "approuve" { // EX-10.8 : levée par son auteur
		for _, o := range t.Objection {
			if o.Auteur == a && !o.Levee {
				o.Levee = true
			}
		}
	}
	if cour != nil {
		cour.Statut = "remplace"
	}
	if dec == "refuse" && t.ContestMs > 0 { // EX-10.7 : tout refus accepté, quel que soit l'état de collecte
		t.Objection = append(t.Objection, &Objection{Auteur: a, At: at})
	}
	t.Votes = append(t.Votes, &Vote{At: at, Approbateur: a, Decision: dec, Signature: sig.Encoder(), Motif: Copier(motif), Statut: "courant"})
	s.decompte(t, at)
	return Resultat{Accepte: true}
}

func (s *Service) recuser(at Instant, d *Value) Resultat {
	t, raison := s.gardeCollecte(d.Get("ticket").S())
	if raison != "" {
		return refus(raison)
	}
	a := d.Get("approver").S()
	if r := s.gardeEligible(t, a); r != "" {
		return refus(r)
	}
	t.Recuses[a] = true // EX-10.4 : vote approuve retiré, vote refuse compté
	s.ecarterIneligibles(t)
	s.decompte(t, at)
	return Resultat{Accepte: true}
}

func (s *Service) retirer(at Instant, d *Value) Resultat {
	t := s.ticket(d.Get("ticket").S())
	by := d.Get("by").S()
	switch {
	case t == nil:
		return refus("ticket_inconnu")
	case t.Etat == "reserve":
		return refus("ticket_non_ouvert")
	case !t.collecte():
		return refus("ticket_clos_aux_votes")
	case by != t.LaunchedBy && !contient(s.Administrateurs, by): // EX-7.15
		return refus("retrait_non_autorise")
	}
	t.Echeance = at // T10 : échéance avancée à at
	s.remettre(t, s.remiseExpire(t, "echeance avancee par retrait"))
	return Resultat{Accepte: true}
}

// donneesAcquitter rend la forme JCS des données d'un acquitter sans le
// ticket, pour reconnaître un acquitter répété à l'identique (EX-7.20).
func donneesAcquitter(d *Value) string {
	c := Objet()
	for _, m := range d.Obj {
		if m.Key != "ticket" {
			c.Obj = append(c.Obj, m)
		}
	}
	b, err := CanoniqueIntegral(c)
	if err != nil {
		return Compact(c)
	}
	return string(b)
}

// approvalCoherent : l'objet approval reçu est celui du ticket, de la
// décision et de l'instant annoncés (gardes de T11, T14, T17).
func approvalCoherent(t *Ticket, d *Value, dec string) bool {
	a := d.Get("approval")
	return a != nil && a.Kind == KindObject && a.Get("ticket").S() == t.ID && a.Get("decision").S() == dec &&
		a.Get("at").S() == d.Get("at").S() && a.Get("request_hash") != nil && a.Get("request_hash").Kind == KindString
}

func (s *Service) lireScellement(d *Value, dec string) (*Scellement, error) {
	at, err := LireInstant(d.Get("at").S())
	if err != nil {
		return nil, err
	}
	seq, _ := EntierJSON(d.Get("seq"))
	return &Scellement{Decision: dec, Seq: seq, Hash: d.Get("hash").S(), At: at, Approval: Copier(d.Get("approval"))}, nil
}

// sceller aligne le ticket sur une décision scellée par le noyau (T11, T14,
// T17) : l'objet approval est gardé tel qu'il est reçu.
func (s *Service) sceller(t *Ticket, sc *Scellement) {
	t.Scelle = sc
	fin := sc.At + Instant(s.E)
	t.FinRecon = &fin
	t.Courante, t.Calculee, t.FinContes = nil, "", nil
	if t.RequestHash == "" { // T17 depuis reserve ou abandonne
		t.RequestHash = sc.Approval.Get("request_hash").S()
	}
	t.Etat = sc.Decision
}

func (s *Service) acquitter(at Instant, d *Value) Resultat {
	t := s.ticket(d.Get("ticket").S())
	if t == nil {
		return refus("ticket_inconnu")
	}
	rid := d.Get("remise_id").S()
	var rem *Remise
	for _, r := range t.Remises {
		if r.ID == rid {
			rem = r
		}
	}
	res := d.Get("result").S()
	raison := d.Get("reason").S()
	scellement := res == "scelle" || raison == "ticket_deja_decide"
	if scellement {
		if _, err := LireInstant(d.Get("at").S()); err != nil || d.Get("approval") == nil || d.Get("approval").Kind != KindObject {
			return refus("requete_invalide")
		}
	}
	donnees := donneesAcquitter(d)
	ok := func() Resultat {
		t.Acquittes = append(t.Acquittes, donnees)
		return Resultat{Accepte: true, Reponse: Objet("ticket", Chaine(t.ID), "state", Chaine(t.Etat))}
	}
	// EX-7.20 : un acquitter identique à un acquitter déjà accepté est sans
	// effet et rend la même réponse.
	if contient(t.Acquittes, donnees) {
		return ok()
	}
	if t.Etat != "a_remettre" {
		if scellement && t.Scelle != nil {
			seq, _ := EntierJSON(d.Get("seq"))
			if t.Scelle.Seq == seq && t.Scelle.Hash == d.Get("hash").S() && EgalJSON(t.Scelle.Approval, d.Get("approval")) {
				return ok()
			}
			s.avertir("%s : scellement contraire à la décision déjà scellée", t.ID)
		}
		if !scellement && rem != nil {
			return ok() // remise qui n'est plus courante : sans effet
		}
		return refus("requete_invalide")
	}
	if rem == nil {
		return refus("requete_invalide")
	}
	switch {
	case res == "scelle": // T11
		dec := rem.Decision
		if d.Get("decision").S() != dec || !approvalCoherent(t, d, dec) || d.Get("approval").Get("request_hash").S() != rem.RequestHash {
			return refus("requete_invalide")
		}
		sc, _ := s.lireScellement(d, dec)
		s.sceller(t, sc)
		if dec == "approuve" {
			if h := d.Get("held"); h != nil && h.Kind == KindBool && h.Bool { // EX-11.5 : requête retenue relayée
				t.Servi = true
			}
			// EX-5.4 : fenêtre d'un ticket ouvrant, version en vigueur, pas déjà finie.
			if t.Ouverture != nil && t.Ouverture.Portee.PolicyVersion == s.PV && sc.At+Instant(t.Ouverture.DureeMs) > at {
				s.ouvrirFenetre(t, sc.At)
			}
		}
		return ok()
	case rem != t.Courante: // remise qui n'est plus courante : sans effet
		return ok()
	case res == "temporaire": // T12
		return ok()
	case res == "refuse" && raison == "ticket_deja_decide":
		dec := d.Get("decision").S()
		if !approvalCoherent(t, d, dec) {
			return refus("requete_invalide")
		}
		if d.Get("approval").Get("request_hash").S() == t.RequestHash { // T14
			sc, _ := s.lireScellement(d, dec)
			s.sceller(t, sc)
			return ok()
		}
		// T20 : décision d'une autre demande sous cet identifiant.
		s.avertir("%s : identifiant_en_collision", t.ID)
		t.Courante, t.Calculee = nil, ""
		t.Etat = "clos"
		return ok()
	case res == "refuse" && raison == "echeance_depassee": // T15
		return ok()
	case res == "refuse": // T16
		t.Courante, t.Calculee = nil, ""
		switch {
		case raison == "ticket_inconnu":
			t.Etat = "abandonne"
			t.CleLiberee = true
		case rem.Decision == "expire":
			// remise expire refusée : pas de nouvelle remise (EX-12.11)
		default:
			for _, v := range t.Votes {
				if v.Statut == "courant" && contient(rem.Approbateurs, v.Approbateur) {
					v.Statut, v.Cause = "ecarte", "remise_refusee"
				}
			}
			t.Etat = "ouvert"
			s.decompte(t, at)
		}
		return ok()
	}
	return refus("requete_invalide")
}

// ouvrirFenetre applique EX-5.4 : debut = approval.at, fin = debut +
// duration_ms, restant = max_calls ; une fenêtre de même portée est
// remplacée.
func (s *Service) ouvrirFenetre(t *Ticket, debut Instant) {
	w := &Fenetre{Portee: t.Ouverture.Portee, Debut: debut, Fin: debut + Instant(t.Ouverture.DureeMs), Restant: t.Ouverture.MaxAppels, Ticket: t.ID}
	for i, x := range s.Fenetres {
		if x.Portee.Egale(w.Portee) {
			s.Fenetres[i] = w
			return
		}
	}
	s.Fenetres = append(s.Fenetres, w)
}

func (s *Service) consommer(d *Value) Resultat {
	t := s.ticket(d.Get("ticket").S())
	if t == nil {
		return refus("ticket_inconnu")
	}
	rep := func() *Value { return Objet("ticket", Chaine(t.ID), "state", Chaine(t.Etat)) }
	seq := Compact(d.Get("seq"))
	h := d.Get("hash").S()
	switch t.Etat {
	case "approuve": // T18
		t.Etat = "consomme"
		t.Consomme = &[2]string{seq, h}
		return Resultat{Accepte: true, Reponse: rep()}
	case "consomme": // répété à l'identique : sans effet (EX-7.20)
		if t.Consomme != nil && t.Consomme[0] == seq && t.Consomme[1] == h {
			return Resultat{Accepte: true, Reponse: rep()}
		}
	}
	return refus("requete_invalide")
}

func (s *Service) expiration(d *Value) Resultat {
	t := s.ticket(d.Get("ticket").S())
	if t == nil {
		return refus("ticket_inconnu")
	}
	sc, err := s.lireScellement(d, "expire")
	if err != nil || sc.Approval == nil || sc.Approval.Kind != KindObject {
		return refus("requete_invalide")
	}
	rep := func() *Value { return Objet("ticket", Chaine(t.ID), "state", Chaine(t.Etat)) }
	if t.Scelle != nil && t.Scelle.Seq == sc.Seq && t.Scelle.Hash == sc.Hash && EgalJSON(t.Scelle.Approval, sc.Approval) {
		return Resultat{Accepte: true, Reponse: rep()} // répétée : sans effet (12.6, EX-7.20)
	}
	memeDemande := t.RequestHash == "" || sc.Approval.Get("request_hash").S() == t.RequestHash
	if !(t.nonDecide() || t.Etat == "abandonne") || !approvalCoherent(t, d, "expire") || !memeDemande {
		return refus("requete_invalide")
	}
	// T17 : alignement sur le noyau (EX-12.11) ; l'objet approval est celui
	// qu'il a scellé seul.
	s.sceller(t, sc)
	return Resultat{Accepte: true, Reponse: rep()}
}
