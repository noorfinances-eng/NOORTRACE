// Planificateur de la section 8 de CT-5 comme machine à états déterministe
// à horloge injectée (EX-8.13) : les réponses des prestataires, des
// calendriers et du registre lui arrivent en entrées (`$defs/evenement_entree`)
// et il rend des actions (`$defs/action_attendue`). RejouerTrace exécute une
// trace normative de CT-5 §8.10 et rend la liste d'actions et la file finale
// à confronter à `expected` et `queue_after` (EX-8.16).
//
// Règles portées : périodes et échéances (EX-4.2, EX-4.3, EX-8.4), échéances
// remplacées (EX-4.4), ancre des points au registre (EX-4.6, EX-9.3 à EX-9.5),
// ordre des ancres (EX-4.7), file et états (EX-8.3, EX-8.5), priorité et
// min_interval_ms (EX-8.7), relève (EX-8.8), attente de reprise (EX-8.9),
// registre (EX-8.10), OpenTimestamps (EX-8.11), redémarrage (EX-8.12),
// classement des réponses (EX-5.10 à EX-5.12).

package main

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

type echeance struct {
	state   string
	demande *string
}

type periode struct {
	orgID          string
	journalID      string
	periodStart    int64
	close          bool
	ordre          []int64
	echeances      map[int64]*echeance
	dernierAncre   int64
	dernierPoint   *Sujet // dernier point admis de la période ouverte (cadence, repli de clôture)
	dernierPointAt *int64
}

func (p *periode) set(k int64, e *echeance) {
	if _, ok := p.echeances[k]; !ok {
		p.ordre = append(p.ordre, k)
	}
	p.echeances[k] = e
}

func (p *periode) get(k int64) *echeance {
	e, ok := p.echeances[k]
	if !ok {
		panic(refus("", "échéance %d inconnue de la période %d", k, p.periodStart))
	}
	return e
}

type minuterie struct {
	at       int64
	seq      int64
	typ      string
	id       string
	k        int64  // indice d'échéance ; pour "cadence", instant d'admission du point qui l'a armée
	provider string // "" : aucun prestataire (null)
}

type prete struct {
	id       string
	provider string
	seq      int64
}

// etatInterne est l'état hors file d'une demande (EX-8.5 : la file est le
// seul état durable ; ceci se reconstruit au démarrage).
type etatInterne struct {
	enCours       map[string]int64 // clé "" : sans prestataire
	engages       map[string]bool
	epuises       map[string]bool
	reprises      map[string]int64
	k             map[string]int64
	premier408    map[string]bool
	tardives      int64
	alertes       map[string]bool
	attenteAt     *int64
	inclusionAt   *int64
	miseANiveauAt *int64
	differe       *int64
	renvois       int64
	premierEnvoi  *int64 // instant de la tentative de rang 1 d'un jeton, retenu dans ce processus (EX-3.5)
	// nonces des tentatives que le planificateur a vues sortir de la fenêtre
	// de 32 pendant le rejeu, par rang (8.5, règle 2, complément du 2026-11-16).
	noncesSortis map[int64]string
	// EX-9.5 (complément du 2026-11-16, l'ancre d'un point en reprise) : une
	// tentative de l'ancre « sortie de la fenêtre de 32 avant le dernier
	// démarrage, dont la file ne dit plus rien (EX-8.5, règle 7), a pu être
	// admise » ; de même une tentative sortie pendant la marche close sur un
	// autre code que ceux d'un échec sans admission, ou obtenue. Vrai : l'ancre
	// n'est plus « encore à envoyer » et n'est pas remplacée.
	peutEtreAdmise bool
}

// Ecriture relie une action ecrire_file (indice dans Actions) à la ligne
// de file qu'elle écrit (EX-8.5, règle 1 : la ligne envoyee porte le nonce
// de la tentative).
type Ecriture struct {
	Action int
	Ligne  string
}

// Planificateur est la machine à états de la section 8.
type Planificateur struct {
	cfg           *Config
	prestataires  map[string]*Prestataire
	roles         map[string]*Prestataire
	nT            int64
	aleatoire     Aleatoire
	demandes      map[string]*Demande
	interne       map[string]*etatInterne
	periodes      map[string]*periode
	ordrePeriodes []string
	timers        []*minuterie
	seq           int64
	Actions       []*Value
	Lignes        []string
	Ecritures     []Ecriture
	dernierEnvoi  map[string]int64
	pretes        []*prete
	relues        int64
	horloge       *int64
	demarre       bool
	admissions    map[string]int64 // instant d'admission de chaque point, par empreinte (EX-3.5, révision 0.6)
	// passe en cours (EX-8.10, complément du 2026-11-16) : « une passe est le
	// traitement d'une entrée : les minuteries échues jusqu'à son instant, puis
	// l'entrée elle-même » ; instantPasse est l'instant de l'entrée, rejeux le
	// nombre d'échéances rejouées par minuterie périodique et par demande.
	instantPasse int64
	rejeux       map[string]int
	// enregistrements relus d'acquisitions.ndjson portés par l'entrée
	// stockage_relu en cours de traitement, par request_id (EX-8.12,
	// complément du 2026-11-16) ; nil hors de cette entrée ou sans le membre.
	acquisRelues map[string]*Resultat
}

func sortePeriode(kind string) bool      { return len(kind) > 8 && kind[len(kind)-8:] == "_periode" }
func prefixe(kind, p string) bool        { return len(kind) >= len(p) && kind[:len(p)] == p }
func idDemande(kind, hash string) string { return kind + ":" + hash }

// NouveauPlanificateur construit le planificateur d'une configuration
// (document ancrage-v0 ou projection) ; refuse une configuration hors d'AN-1.
func NouveauPlanificateur(config *Value, aleatoire Aleatoire) (*Planificateur, error) {
	cfg := ProjeterConfiguration(config)
	p := &Planificateur{cfg: cfg, prestataires: map[string]*Prestataire{}, roles: map[string]*Prestataire{}, aleatoire: aleatoire, demandes: map[string]*Demande{}, interne: map[string]*etatInterne{}, periodes: map[string]*periode{}, Actions: []*Value{}, Lignes: []string{}, dernierEnvoi: map[string]int64{}, admissions: map[string]int64{}}
	for _, pr := range cfg.Providers {
		if pr.ID == "" || !dans(pr.Role, Roles) {
			return nil, refus("AN-1", "prestataire mal formé : %s (%s)", pr.ID, pr.Role)
		}
		if _, ok := p.prestataires[pr.ID]; ok {
			return nil, refus("AN-1", "prestataire %s en double", pr.ID)
		}
		p.prestataires[pr.ID] = pr
		if pr.Role == "principal" || pr.Role == "secours" {
			if _, ok := p.roles[pr.Role]; ok {
				return nil, refus("AN-1", "deux prestataires de rôle %s", pr.Role)
			}
			p.roles[pr.Role] = pr
		} else if _, ok := p.roles[pr.Role]; !ok {
			p.roles[pr.Role] = pr
		}
	}
	if p.roles["principal"] == nil {
		return nil, refus("AN-1", "aucun prestataire de rôle principal")
	}
	cT := cfg.CheckpointsIntervalS
	if cT <= 0 || cfg.CheckpointIntervalS <= 0 || 3600%cT != 0 || cT%cfg.CheckpointIntervalS != 0 {
		return nil, refus("AN-1", "interval_s %d : multiple de checkpoint_interval_s et diviseur de 3600 attendu", cT)
	}
	if cfg.ProviderRole != "aucun" && p.roles[cfg.ProviderRole] == nil {
		return nil, refus("AN-1", "provider_role %s sans prestataire de ce rôle", cfg.ProviderRole)
	}
	p.nT = 3600 / cT
	return p, nil
}

// --- état interne ---------------------------------------------------------

func (p *Planificateur) int(id string) *etatInterne {
	s, ok := p.interne[id]
	if !ok {
		s = &etatInterne{enCours: map[string]int64{}, engages: map[string]bool{}, epuises: map[string]bool{}, reprises: map[string]int64{}, k: map[string]int64{}, premier408: map[string]bool{}, alertes: map[string]bool{}, noncesSortis: map[int64]string{}}
		p.interne[id] = s
	}
	return s
}

func (p *Planificateur) actives() int64 {
	var n int64
	for _, d := range p.demandes {
		if !EtatsFinaux[d.State] {
			n++
		}
	}
	return n
}

// File rend la file dans l'ordre (created_at, id).
func (p *Planificateur) File() []*Demande {
	l := make([]*Demande, 0, len(p.demandes))
	for _, d := range p.demandes {
		l = append(l, d)
	}
	trierFile(l)
	return l
}

func (p *Planificateur) emettre(t int64, action string, requestID *string, detail *Value) {
	p.Actions = append(p.Actions, vObj("t", vStr(Iso(t)), "action", vStr(action), "request_id", vStrOuNul(requestID), "detail", detail))
}
func (p *Planificateur) ecrire(d *Demande, t int64, state string) {
	d.State = state
	// EX-8.5, règle 7 (révision 0.6) : la ligne porte au plus 32 tentatives et
	// toujours attempts_total, plus grand rang de la demande.
	gardees := Fenetre(d.Attempts)
	if len(gardees) < len(d.Attempts) {
		portees := map[int64]bool{}
		for _, a := range gardees {
			portees[a.N] = true
		}
		s := p.int(d.ID)
		for _, a := range d.Attempts {
			if !portees[a.N] && a.Nonce != nil {
				s.noncesSortis[a.N] = *a.Nonce
			}
			if !portees[a.N] && !sansAdmission(a) {
				s.peutEtreAdmise = true
			}
		}
	}
	d.Attempts = gardees
	total := d.Total()
	for _, a := range d.Attempts {
		if a.N > total {
			total = a.N
		}
	}
	d.AttemptsTotal = ptrI(total)
	p.emettre(t, "ecrire_file", &d.ID, vObj("state", vStr(state)))
	ligne := LigneFile(d)
	p.Lignes = append(p.Lignes, ligne)
	p.Ecritures = append(p.Ecritures, Ecriture{Action: len(p.Actions) - 1, Ligne: ligne})
}

// ajouterTentative ajoute la tentative de rang attempts_total + 1 (jamais de
// renumérotation, EX-8.5 règle 7, EX-8.12) et rend son rang.
func (p *Planificateur) ajouterTentative(d *Demande, provider *string, t int64, nonce *string, detail string) int64 {
	n := d.Total() + 1
	d.Attempts = append(d.Attempts, p.tentative(d, n, provider, t, nonce, detail))
	d.AttemptsTotal = ptrI(n)
	return n
}

// avecRang ajoute à une ligne du journal le rang et l'attempt_id de la
// tentative dont elle rend compte (EX-8.15, révision 0.6).
func avecRang(o *Value, d *Demande, n int64) *Value {
	o.Obj = append(o.Obj, Member{Key: "attempt", Val: vInt(n)}, Member{Key: "attempt_id", Val: vStr(IdentifiantCorrelation(d.Kind, d.Subject.Hash, n))})
	return o
}

func (p *Planificateur) programmer(d *Demande, t int64, at int64, reason string) {
	d.DueAt = ptrS(Iso(at))
	p.emettre(t, "programmer", &d.ID, vObj("next_at", vStr(Iso(at)), "reason", vStr(reason)))
}
func (p *Planificateur) timer(at int64, typ, id string, k int64, provider string) {
	p.timers = append(p.timers, &minuterie{at: at, seq: p.seq, typ: typ, id: id, k: k, provider: provider})
	p.seq++
}
func (p *Planificateur) journaliser(t int64, requestID *string, detail *Value) {
	p.emettre(t, "journaliser", requestID, detail)
}
func (p *Planificateur) alerter(t int64, requestID *string, code, severity string) {
	p.emettre(t, "alerter", requestID, vObj("code", vStr(code), "severity", vStr(severity)))
}

// --- périodes et échéances (EX-8.4, règle 1) ----------------------------

func cle(s *Sujet) string { return fmt.Sprintf("%s|%s|%d", s.OrgID, s.JournalID, s.PeriodStart) }

func (p *Planificateur) periode(sujet *Sujet, t int64, nouvelle, fermee bool) *periode {
	k := cle(sujet)
	if per, ok := p.periodes[k]; ok {
		return per
	}
	per := &periode{orgID: sujet.OrgID, journalID: sujet.JournalID, periodStart: sujet.PeriodStart, close: fermee, echeances: map[int64]*echeance{}}
	p.periodes[k] = per
	p.ordrePeriodes = append(p.ordrePeriodes, k)
	if fermee {
		return per
	}
	for i := int64(1); i < p.nT; i++ {
		at := p.D(per, i)
		if at <= t {
			per.set(i, &echeance{state: "ouverte"})
		} else {
			per.set(i, &echeance{state: "fermee"})
			if nouvelle {
				p.timer(at, "echeance", k, i, "")
			}
		}
	}
	return per
}

func (p *Planificateur) D(per *periode, k int64) int64 {
	return (per.periodStart + k*p.cfg.CheckpointsIntervalS) * 1000
}

// dernierContresigne : le plus grand tree_size des demandes jeton_point de la
// période dont le jeton est obtenu ou dont la demande n'est pas dans un état
// final ; une demande refusee, remplacee ou sans_objet ne compte pas (EX-4.3,
// EX-8.4 règle 1).
func (p *Planificateur) dernierContresigne(per *periode) int64 {
	var m int64
	c := fmt.Sprintf("%s|%s|%d", per.orgID, per.journalID, per.periodStart)
	for _, d := range p.demandes {
		if d.Kind != "jeton_point" || cle(d.Subject) != c || d.Subject.TreeSize == nil {
			continue
		}
		if (d.State == "obtenue" || !EtatsFinaux[d.State]) && *d.Subject.TreeSize > m {
			m = *d.Subject.TreeSize
		}
	}
	return m
}

// echeanceMediane : k_m = ⌈n_T / 2⌉ de l'option mi_periode (EX-6.1) ; 0 si n_T = 1.
func (p *Planificateur) echeanceMediane() int64 {
	if p.nT <= 1 {
		return 0
	}
	return (p.nT + 1) / 2
}
func (p *Planificateur) finPeriode(per *periode) int64 {
	return (per.periodStart + DureePeriode) * 1000
}

// --- horloge et minuteries ----------------------------------------------

// minuterieDePeriode : échéances et cadence des points, armées par période ou
// par journal ; les autres minuteries sont celles d'une demande.
func minuterieDePeriode(m *minuterie) bool { return m.typ == "echeance" || m.typ == "cadence" }

// trierTimers range les minuteries par échéance. EX-8.16 (complément du
// 2026-11-16) : « Deux minuteries de même échéance se déclenchent dans cet
// ordre : celles des périodes (échéances, cadence des points) d'abord, dans
// l'ordre où elles ont été armées ; puis celles des demandes, dans l'ordre de
// la file (created_at, puis id) et, pour une même demande, dans l'ordre où
// elles ont été armées » ; « l'ordre d'armement des minuteries de période vaut
// quel que soit leur journal ».
func (p *Planificateur) trierTimers() {
	sort.SliceStable(p.timers, func(i, j int) bool {
		a, b := p.timers[i], p.timers[j]
		if a.at != b.at {
			return a.at < b.at
		}
		pa, pb := minuterieDePeriode(a), minuterieDePeriode(b)
		if pa != pb {
			return pa
		}
		if !pa && a.id != b.id {
			da, db := p.demandes[a.id], p.demandes[b.id]
			if da != nil && db != nil && da.CreatedAt != db.CreatedAt {
				return da.CreatedAt < db.CreatedAt
			}
			return a.id < b.id
		}
		return a.seq < b.seq
	})
}

func (p *Planificateur) avancer(t int64) {
	for {
		p.trierTimers()
		if len(p.timers) == 0 || p.timers[0].at > t {
			return
		}
		m := p.timers[0]
		p.timers = p.timers[1:]
		p.declencher(m)
	}
}

func (p *Planificateur) declencher(m *minuterie) {
	t := m.at
	d := p.demandes[m.id]
	switch m.typ {
	case "echeance":
		per := p.periodes[m.id]
		if per == nil {
			return
		}
		e, ok := per.echeances[m.k]
		if !ok || e.state != "fermee" {
			return
		}
		e.state = "ouverte"
		p.emettre(t, "echeance", nil, vObj("k", vInt(m.k), "state", vStr("ouverte")))
		return
	case "attente_registre":
		if d == nil || d.State != "attente_registre" {
			return
		}
		if s := p.int(d.ID); s.attenteAt == nil || *s.attenteAt != t {
			return
		}
		// EX-8.10 : l'examen de l'attente du registre d'un jeton_periode est une
		// minuterie périodique, au plus quatre rejeux par passe.
		quatrieme := false
		if d.Kind == "jeton_periode" {
			p.rejeux["attente_registre|"+d.ID]++
			quatrieme = p.rejeux["attente_registre|"+d.ID] == 4
		}
		p.examinerAttenteRegistre(d, t, quatrieme)
	case "reprise":
		if d == nil || EtatsFinaux[d.State] {
			return
		}
		s := p.int(d.ID)
		if at, ok := s.reprises[m.provider]; !ok || at != t {
			return
		}
		delete(s.reprises, m.provider)
		if prefixe(d.Kind, "ancre_registre_") {
			// EX-8.10 (complément du 2026-11-16) : « À l'échéance, l'ancre est
			// renvoyée si la clé de chaîne n'a pas de transaction sans reçu ;
			// sinon elle attend (attente_nonce) et part au reçu de celle-ci
			// (EX-9.4). »
			p.attendOuEnvoie(d, t)
		} else if prefixe(d.Kind, "ots_") {
			p.soumettreOts(d, t)
		} else {
			p.pret(d, p.prestataires[m.provider])
		}
	case "releve":
		if d == nil || EtatsFinaux[d.State] {
			return
		}
		s := p.int(d.ID)
		secours := p.roles["secours"]
		if secours == nil || s.engages[secours.ID] || s.epuises[secours.ID] {
			return
		}
		p.relever(d, t, "delai")
	case "mise_a_niveau":
		if d == nil || d.State != "en_attente" {
			return
		}
		s := p.int(d.ID)
		if s.miseANiveauAt == nil || *s.miseANiveauAt != t {
			return
		}
		n := p.ajouterTentative(d, nil, t, nil, "mise a niveau demandee")
		s.enCours[""] = n
		p.ecrire(d, t, "en_attente") // EX-8.5, règle 1 : la ligne précède la requête
		p.emettre(t, "mettre_a_niveau_ots", &d.ID, vObj("attempt", vInt(n)))
	case "inclusion":
		if d == nil || d.State != "envoyee" {
			return
		}
		s := p.int(d.ID)
		if s.inclusionAt == nil || *s.inclusionAt != t {
			return
		}
		s.renvois++
		sev := "majeure"
		detail := "remplacement au meme nonce"
		if s.renvois == 1 {
			sev = "mineure"
			detail = "renvoi des memes octets"
		}
		// EX-8.10 (complément du 2026-11-16) : « au plus quatre sont rejouées
		// par minuterie et par demande [...] Au quatrième rejeu, la minuterie
		// est reposée à sa première échéance postérieure à l'instant de
		// l'entrée [...] pour le renvoi d'une ancre, elles sont comptées sur une
		// ligne anchor_retry écrite au quatrième rejeu, avant son envoi, si elles
		// sont au moins une (kind, mode renvoi, error_code recu_absent,
		// missed_deadlines, puis attempt et attempt_id de la tentative que ce
		// rejeu clôt) ».
		p.rejeux["inclusion|"+d.ID]++
		pas := p.cfg.InclusionAlertS * 1000
		prochain, manquees := p.reposer(t, pas, p.rejeux["inclusion|"+d.ID] == 4)
		p.alerter(t, &d.ID, "inclusion_late", sev)
		clos := int64(0)
		if len(d.Attempts) > 0 {
			clos = d.Attempts[len(d.Attempts)-1].N
		}
		p.cloreTentativeRegistre(d, t, "recu_absent", "")
		if manquees >= 1 {
			p.journaliser(t, &d.ID, avecRang(vObj("event", vStr("anchor_retry"), "kind", vStr(d.Kind), "mode", vStr("renvoi"), "error_code", vStr("recu_absent"), "missed_deadlines", vInt(manquees)), d, clos))
		}
		p.ajouterTentative(d, nil, t, nil, detail)
		// EX-8.10 (complément du 2026-11-16) : « une ancre renvoyée, comme toute
		// ancre envoyee, n'a pas de due_at ».
		d.DueAt = nil
		p.ecrire(d, t, "envoyee")
		p.emettre(t, "envoyer_registre", &d.ID, p.detailRegistre(d))
		s.inclusionAt = ptrI(prochain)
		p.timer(*s.inclusionAt, "inclusion", d.ID, 0, "")
	case "repli_cloture":
		// EX-8.4, règle 2 : « registry.squat_wait_s après la clôture, si
		// jeton_periode est encore attente_registre, une demande jeton_point
		// sans échéance est créée pour le point de clôture » ; EX-9.7
		// (complément du 2026-11-16) : « Le refus n'abandonne pas le repli de
		// clôture » : seul l'état du jeton de la période compte, quel que soit
		// celui de son ancre.
		if d == nil || d.State != "attente_registre" {
			return
		}
		p.repliCloture(d, t)
	case "cadence":
		// EX-8.15 : aucun point admis pendant 2 × c_K après le checkpoint_ts du dernier point admis (alerte point_manquant).
		per := p.periodes[m.id]
		if per == nil || per.close || per.dernierPointAt == nil || *per.dernierPointAt != m.k {
			return
		}
		p.journaliser(t, nil, vObj("event", vStr("point_manquant"), "last_checkpoint_ts", vStr(per.dernierPoint.DeclaredAt), "gap_s", vInt((t-m.k)/1000)))
		p.alerter(t, nil, "point_manquant", "majeure")
		return
	case "dispatch":
	default:
		panic(refus("", "minuterie inconnue %s", m.typ))
	}
	p.servir(t)
}

// --- entrées ----------------------------------------------------------------

// Recevoir traite une entrée (`$defs/evenement_entree`), minuteries échues comprises.
func (p *Planificateur) Recevoir(entree *Value) {
	if entree == nil || entree.Kind != KindObject {
		panic(refus("", "entrée : objet attendu"))
	}
	texte, ok := chaineDe(entree, "t")
	if !ok {
		panic(refus("", "entrée sans instant"))
	}
	t, err := Ms(texte)
	if err != nil {
		panic(refus("", "%s", err.Error()))
	}
	if p.horloge != nil && t < *p.horloge {
		panic(refus("", "horloge en recul : %s après %s", Iso(t), Iso(*p.horloge)))
	}
	typ, _ := chaineDe(entree, "type")
	if !p.demarre && typ != "demarrage" {
		panic(refus("", "première entrée : demarrage attendu"))
	}
	p.instantPasse = t
	p.rejeux = map[string]int{}
	data := entree.Get("data")
	// Schéma planificateur-ancrage-v0, complément du 2026-11-16 : « membre
	// facultatif acquisitions des entrées demarrage et stockage_relu
	// ($defs/acquisition_relue) » ; un élément hors de cette forme refuse
	// l'entrée.
	var acquisitions []*AcquisitionRelue
	avecAcquisitions := false
	if typ == "demarrage" || typ == "stockage_relu" {
		if a := champ(data, "acquisitions"); a != nil {
			l, err := AcquisitionsDe(a)
			if err != nil {
				panic(refus("", "%s.acquisitions : %s", typ, err.Error()))
			}
			if typ == "stockage_relu" && len(l) > 20000 {
				panic(refus("", "stockage_relu.acquisitions : au plus 20 000 éléments"))
			}
			acquisitions, avecAcquisitions = l, true
		}
	}
	p.avancer(t)
	switch typ {
	case "demarrage":
		p.demarrer(t, acquisitions, avecAcquisitions)
	case "point_produit":
		p.pointProduit(t, data)
	case "periode_close":
		p.periodeClose(t, data, nil)
	case "tic":
	case "reponse_rfc3161":
		p.reponseRfc3161(t, data)
	case "reponse_ots":
		p.reponseOts(t, data)
	case "inclusion_registre":
		p.inclusionRegistre(t, data)
	case "echec_registre":
		p.echecRegistre(t, data)
	case "stockage_relu":
		p.reconstruire(t, data, acquisitions)
	case "arret":
		p.journaliser(t, nil, vObj("event", vStr("anchoring_stopped"), "queue_entries", vInt(int64(len(p.demandes)))))
	default:
		panic(refus("", "type d'entrée inconnu : %q", typ))
	}
	for {
		p.servir(t)
		p.trierTimers()
		if len(p.timers) == 0 || p.timers[0].at > t {
			break
		}
		p.avancer(t)
	}
	p.horloge = &t
}

// Charger charge la file relue au démarrage (la dernière ligne d'un id fait foi).
func (p *Planificateur) Charger(demandes []*Demande) {
	for _, d := range demandes {
		p.demandes[d.ID] = d
		p.noterFenetreRelue(d)
	}
	p.relues = int64(len(p.demandes))
}

func (p *Planificateur) demarrer(t int64, acquisitions []*AcquisitionRelue, avecAcquisitions bool) {
	p.demarre = true
	p.journaliser(t, nil, vObj("event", vStr("anchoring_started"), "queue_entries", vInt(p.relues)))
	// EX-5.8 (complément du 2026-11-16) : « Au démarrage, une demande de jeton
	// obtenue de la file sans enregistrement obtenue promu de même token_sha256
	// dans acquisitions.ndjson est rouverte (a_reprendre) et alertée
	// (file_perdue). [...] la réouverture efface le résultat, écrit la demande
	// a_reprendre à l'instant du démarrage (due_at), lève l'alerte file_perdue
	// (critique) sur cette demande, et la reprise d'EX-8.12 la renvoie au rang
	// attempts_total + 1 ; ses échéances redeviennent celles d'une demande
	// active (EX-4.4 s'applique). [...] sans ce membre, la règle ne s'applique
	// pas. » La réouverture précède la relecture des échéances.
	if avecAcquisitions {
		promus := map[string]bool{}
		for _, a := range acquisitions {
			promus[a.RequestID+"|"+a.Result.SHA256] = true
		}
		for _, d := range p.File() {
			if !prefixe(d.Kind, "jeton_") || d.State != "obtenue" || d.Result == nil || promus[d.ID+"|"+d.Result.SHA256] {
				continue
			}
			d.Result = nil
			d.DueAt = ptrS(Iso(t))
			p.ecrire(d, t, "a_reprendre")
			p.alerter(t, &d.ID, "file_perdue", "critique")
		}
	}
	file := p.File()
	closes := map[string]bool{}
	for _, d := range file {
		if sortePeriode(d.Kind) {
			closes[cle(d.Subject)] = true
		}
	}
	for _, d := range file {
		p.periode(d.Subject, t, false, closes[cle(d.Subject)])
	}
	for _, d := range file {
		per := p.periode(d.Subject, t, false, false)
		// une demande refusee ne tient plus ses échéances (EX-4.3, EX-8.8)
		if d.Kind == "jeton_point" && d.State != "refusee" {
			etat := "ouverte"
			switch d.State {
			case "obtenue":
				etat = "satisfaite"
			case "remplacee":
				etat = "remplacee"
			case "sans_objet":
				etat = "sans_objet"
			}
			for _, k := range d.Deadlines {
				id := d.ID
				per.set(k, &echeance{state: etat, demande: &id})
			}
		}
		if d.Kind == "ancre_registre_point" && d.State != "refusee" && d.Subject.TreeSize != nil && *d.Subject.TreeSize > per.dernierAncre {
			per.dernierAncre = *d.Subject.TreeSize
		}
	}
	for _, k := range p.ordrePeriodes {
		per := p.periodes[k]
		if per.close {
			continue
		}
		for _, i := range per.ordre {
			if e := per.echeances[i]; e.state == "fermee" && p.D(per, i) > t {
				p.timer(p.D(per, i), "echeance", k, i, "")
			}
		}
	}
	// EX-8.12 et EX-4.4 (révision 0.10) : échéances des demandes de points relues
	p.remplacerRelues(t)
	// EX-8.12 : transitions de reprise
	for _, d := range file {
		if EtatsFinaux[d.State] {
			continue
		}
		s := p.int(d.ID)
		for _, a := range d.Attempts {
			if a.Provider != nil {
				s.engages[*a.Provider] = true
				if a.Outcome == "echec_permanente" {
					s.epuises[*a.Provider] = true
				}
			}
		}
		if prefixe(d.Kind, "ancre_registre_") {
			// EX-8.10 : l'alerte du refus définitif de l'ancre d'une période est
			// « levée une fois par ancre depuis le dernier démarrage ».
			delete(s.alertes, "prestataires_epuises")
			p.noterFenetreRelue(d)
			if d.State == "envoyee" {
				ligne := vObj("event", vStr("anchor_retry"), "kind", vStr(d.Kind), "mode", vStr("renvoi"))
				if len(d.Attempts) > 0 {
					// la tentative renvoyée telle quelle (EX-8.12) : la dernière de la ligne
					ligne = avecRang(ligne, d, d.Attempts[len(d.Attempts)-1].N)
				}
				p.journaliser(t, &d.ID, ligne)
				p.emettre(t, "envoyer_registre", &d.ID, p.detailRegistre(d))
				s.inclusionAt = ptrI(t + p.cfg.InclusionAlertS*1000)
				p.timer(*s.inclusionAt, "inclusion", d.ID, 0, "")
			} else if d.State == "a_envoyer" && p.cleOccupee(d) {
				// EX-8.12, ordre du démarrage, point 5 (complément du 2026-11-16) :
				// « une ancre a_envoyer attend le nonce à sa place (action
				// programmer de raison attente_nonce) si une ancre de sa clé de
				// chaîne est en vol (ligne envoyee), et ne produit sinon aucune
				// action dans la passe ».
				p.programmer(d, t, t, "attente_nonce")
			} else if d.State == "a_reprendre" {
				// EX-8.12 et EX-4.13 (complément du 2026-11-16) : « a_reprendre →
				// garde due_at (jeton, soumission OpenTimestamps ou ancre au
				// registre ; borné par EX-4.13 ; une échéance passée pendant l'arrêt
				// part au démarrage, jamais avant lui) ».
				at := p.borneDueAt(d, t, dueOuT(d, t))
				s.reprises[""] = at
				p.timer(at, "reprise", d.ID, 0, "")
			}
			continue
		}
		if prefixe(d.Kind, "ots_") {
			// EX-8.11 (complément du 2026-11-16, soumission aboutie au-delà de
			// l'âge d'abandon) : l'alerte ots_give_up est levée « une fois par
			// demande depuis le dernier démarrage ».
			delete(s.alertes, "ots_give_up")
			// EX-8.12 (complément du 2026-11-16) : « une ligne a_reprendre qui
			// porte encore une tentative en_cours [...] se reprend de même, comme
			// une soumission envoyee ».
			etat := d.State
			if etat == "a_reprendre" {
				for _, a := range d.Attempts {
					if a.Outcome == "en_cours" {
						etat = "envoyee"
					}
				}
			}
			switch etat {
			case "envoyee":
				// EX-8.12 (complément du 2026-11-16) : « sa tentative en cours est
				// close echec_transitoire, code redemarrage [...], la ligne est
				// réécrite a_reprendre et la soumission repart aussitôt (action
				// programmer de raison immediat), au rang attempts_total + 1, mais
				// avec le même nonce et le même engagement ».
				p.perdreTentatives(d, t)
				d.DueAt = ptrS(Iso(t))
				p.ecrire(d, t, "a_reprendre")
				p.programmer(d, t, t, "immediat")
				s.reprises[""] = t
				p.timer(t, "reprise", d.ID, 0, "")
			case "a_reprendre":
				at := p.borneDueAt(d, t, dueOuT(d, t))
				s.reprises[""] = at
				p.timer(at, "reprise", d.ID, 0, "")
			case "en_attente":
				at := dueOuT(d, t)
				s.miseANiveauAt = ptrI(at)
				p.programmer(d, t, at, "mise_a_niveau")
				p.timer(at, "mise_a_niveau", d.ID, 0, "")
			}
			// EX-8.9 : série de la soumission relue de la ligne.
			p.relireSerie(d)
			continue
		}
		// jetons
		switch d.State {
		case "envoyee":
			perdus := p.perdreTentatives(d, t)
			d.DueAt = ptrS(Iso(t))
			p.ecrire(d, t, "a_reprendre")
			p.programmer(d, t, t, "immediat")
			for _, prov := range perdus {
				s.reprises[prov] = t
				p.timer(t, "reprise", d.ID, 0, prov)
			}
		case "attente_registre":
			s.attenteAt = ptrI(t)
			p.programmer(d, t, t, "attente_registre")
			p.timer(t, "attente_registre", d.ID, 0, "")
		case "a_reprendre":
			at := p.borneDueAt(d, t, dueOuT(d, t))
			var dernier *Tentative
			for i := len(d.Attempts) - 1; i >= 0; i-- {
				if d.Attempts[i].Provider != nil {
					dernier = d.Attempts[i]
					break
				}
			}
			prov := ""
			if dernier != nil && !s.epuises[*dernier.Provider] {
				prov = *dernier.Provider
			} else if des := p.designe(d.Kind); des != nil {
				prov = des.ID
			}
			if prov != "" {
				s.reprises[prov] = at
				p.timer(at, "reprise", d.ID, 0, prov)
			}
		case "a_envoyer":
			p.pret(d, p.designe(d.Kind))
		}
		// EX-8.9 (révision 0.10) : k relu de la file, par prestataire.
		p.relireSerie(d)
		// EX-8.12 (révision 0.10) : la minuterie de relève d'EX-8.8, perdue avec
		// le processus, est reposée à premier envoi + fallback_after_s pour une
		// demande de jeton non finale qui admet la relève et dont le secours
		// n'est ni engagé ni épuisé ; échue, elle relève à l'instant du démarrage.
		if secours := p.roles["secours"]; p.releveAdmise(d) && len(d.Attempts) > 0 && !s.engages[secours.ID] && !s.epuises[secours.ID] {
			at := p.premierEnvoi(d) + p.delaiReleve(d)
			if at < t {
				at = t
			}
			p.timer(at, "releve", d.ID, 0, "")
		}
	}
}

// dueOuT rend max(due_at, t) : une reprise échue pendant l'arrêt part au
// démarrage, jamais avant lui (EX-8.12).
func dueOuT(d *Demande, t int64) int64 {
	if d.DueAt == nil {
		return t
	}
	v, err := Ms(*d.DueAt)
	if err != nil {
		panic(refus("", "%s", err.Error()))
	}
	if v < t {
		return t
	}
	return v
}

// borneDueAt applique EX-4.13 à la reprise d'une demande a_reprendre relue
// au démarrage : « Au démarrage, un due_at postérieur à l'instant courant plus
// retry.max_ms est ramené à cette borne. Complément du 2026-11-16 : la borne
// vise la seule attente de reprise d'une demande a_reprendre (EX-8.9 :
// nouvelle tentative d'un jeton RFC 3161, nouvelle soumission
// OpenTimestamps, renvoi d'une ancre au registre) [...] Quand elle
// s'applique, l'action programmer (raison backoff) porte la borne, puis la
// ligne de la demande est réécrite. » Une preuve en_attente n'y passe pas.
func (p *Planificateur) borneDueAt(d *Demande, t, at int64) int64 {
	borne := t + int64(p.cfg.Retry.MaxMs)
	if at <= borne {
		return at
	}
	p.programmer(d, t, borne, "backoff")
	p.ecrire(d, t, "a_reprendre")
	return borne
}

// relireSerie reprend, pour une demande de jeton relue au démarrage, le
// nombre k d'échecs transitoires consécutifs de chaque série (EX-8.9,
// révision 0.10) : sans tentative close par le redémarrage (error_code
// redemarrage), la demande garde ses échecs antérieurs dans k ; une telle
// tentative n'est pas un échec du prestataire et interrompt la série (l'échec
// suivant a k = 1). Un autre résultat (obtenue, echec_permanente) interrompt
// aussi la série. Les tentatives sorties de la fenêtre de 32 (EX-8.5, règle 7)
// ne sont plus lues : k est compté sur celles que la ligne porte.
//
// EX-8.9 (complément du 2026-11-16) : « une soumission OpenTimestamps n'a pas
// de prestataire, ses calendriers répondant ensemble (provider nul) : sa série
// est celle de ses soumissions en échec [...] ; la tentative d'une soumission
// close par le redémarrage (redemarrage, EX-8.12) l'interrompt comme celle d'un
// jeton, et, relue au démarrage, la série ne compte que les tentatives que la
// ligne porte » : sa série est rangée sous la clé "" (aucun prestataire).
func (p *Planificateur) relireSerie(d *Demande) {
	s := p.int(d.ID)
	ots := prefixe(d.Kind, "ots_")
	for _, a := range d.Attempts {
		cle := ""
		if a.Provider != nil {
			cle = *a.Provider
		} else if !ots {
			continue
		}
		if (a.Outcome == "echec_transitoire" || a.Outcome == "reponse_tardive") && (a.ErrorCode == nil || *a.ErrorCode != "redemarrage") {
			s.k[cle]++
		} else {
			s.k[cle] = 0
		}
	}
}

// remplacerRelues applique EX-4.4 aux demandes de points relues au démarrage
// (EX-8.12). Révision 0.10 : « Une demande jeton_point non finale dont toutes
// les échéances sont inférieures à une échéance satisfaite d'une autre
// demande de la période est close remplacee au démarrage, avec la ligne
// checkpoint_anchor_late (EX-4.4). » Complément du 2026-11-16 : « l'échéance
// n_T étant satisfaite par le jeton_periode (EX-8.4, règle 1), les demandes
// couvrantes sont les demandes de jeton obtenue relues de la période ; chacune
// s'applique comme à sa promotion, les jeton_point par plus petite échéance
// croissante (un repli de clôture, sans échéance, compte pour n_T ; à
// égalité, dans l'ordre de la file), puis le jeton_periode, et clôt les
// demandes non finales qui servent une échéance encore ouverte inférieure à
// sa plus grande échéance (n_T pour le jeton_periode et le repli).
// replaced_by nomme donc la première demande qui couvre [...] ; window_s est,
// comme en cours de marche, la borne (genTime + précision) de son jeton moins
// la plus petite échéance de la demande close, en secondes entières
// tronquées. » Le jeton de clôture obtenu clôt aussi un repli de clôture non
// final, comme à sa promotion (EX-4.2), avec la ligne anchor_replaced.
func (p *Planificateur) remplacerRelues(t int64) {
	severite := "majeure"
	if p.cfg.ProviderRole == "interne" {
		severite = "mineure"
	}
	file := p.File()
	for _, c := range p.ordrePeriodes {
		per := p.periodes[c]
		// demandes couvrantes de la période, dans l'ordre du texte
		type couvrante struct {
			d          *Demande
			kmin, kmax int64
		}
		var points []couvrante
		var cloture *Demande
		for _, d := range file {
			if cle(d.Subject) != c || d.State != "obtenue" {
				continue
			}
			switch d.Kind {
			case "jeton_point":
				kmin, kmax := p.nT, p.nT // repli de clôture : n_T
				if len(d.Deadlines) > 0 {
					kmin, kmax = d.Deadlines[0], d.Deadlines[0]
					for _, k := range d.Deadlines {
						kmin, kmax = min(kmin, k), max(kmax, k)
					}
				}
				points = append(points, couvrante{d, kmin, kmax})
			case "jeton_periode":
				cloture = d
			}
		}
		sort.SliceStable(points, func(i, j int) bool { return points[i].kmin < points[j].kmin })
		couvrantes := points
		if cloture != nil {
			couvrantes = append(couvrantes, couvrante{cloture, p.nT, p.nT})
		}
		for _, cv := range couvrantes {
			borne := t
			if r := cv.d.Result; r != nil {
				texte := r.ObtainedAt
				if r.Bound != nil {
					texte = *r.Bound
				}
				if v, err := Ms(texte); err == nil {
					borne = v
				}
			}
			for _, d := range file {
				if d == cv.d || d.Kind != "jeton_point" || EtatsFinaux[d.State] || cle(d.Subject) != c {
					continue
				}
				if len(d.Deadlines) == 0 {
					// repli de clôture non final : clos par le seul jeton de clôture (EX-4.2)
					if cv.d.Kind != "jeton_periode" {
						continue
					}
					d.ReplacedBy = ptrS(cv.d.ID)
					d.DueAt = nil
					p.emettre(t, "remplacer", &d.ID, vObj("replaced_by", vStr(cv.d.ID)))
					p.ecrire(d, t, "remplacee")
					p.journaliser(t, &d.ID, vObj("event", vStr("anchor_replaced"), "replaced_by", vStr(cv.d.ID)))
					continue
				}
				sert := false
				kmin := d.Deadlines[0]
				for _, k := range d.Deadlines {
					kmin = min(kmin, k)
					if e, ok := per.echeances[k]; ok && e.state == "ouverte" && k < cv.kmax {
						sert = true
					}
				}
				if !sert {
					continue
				}
				d.ReplacedBy = ptrS(cv.d.ID)
				d.DueAt = nil
				p.emettre(t, "remplacer", &d.ID, vObj("replaced_by", vStr(cv.d.ID)))
				p.ecrire(d, t, "remplacee")
				for _, k := range d.Deadlines {
					per.get(k).state = "remplacee"
					p.emettre(t, "echeance", &d.ID, vObj("k", vInt(k), "state", vStr("remplacee")))
				}
				p.journaliser(t, &d.ID, vObj("event", vStr("checkpoint_anchor_late"), "tree_size", vIntOuNul(d.Subject.TreeSize), "deadlines", vEntiers(d.Deadlines), "replaced_by", vStr(cv.d.ID), "window_s", vInt((borne-p.D(per, kmin))/1000)))
				p.alerter(t, &d.ID, "checkpoint_anchor_late", severite)
			}
		}
	}
}

func (p *Planificateur) perdreTentatives(d *Demande, t int64) []string {
	var perdus []string
	for _, a := range d.Attempts {
		if a.Outcome != "en_cours" {
			continue
		}
		a.Outcome = "echec_transitoire"
		a.ErrorCode = ptrS("redemarrage")
		a.NextAt = ptrS(Iso(t))
		a.Detail = "redemarrage : reponse non recue"
		prov := ""
		if a.Provider != nil {
			prov = *a.Provider
		}
		perdus = append(perdus, prov)
	}
	return perdus
}

// --- création des demandes --------------------------------------------------

func (p *Planificateur) tentative(d *Demande, n int64, provider *string, t int64, nonce *string, detail string) *Tentative {
	return &Tentative{N: n, Provider: provider, StartedAt: Iso(t), Nonce: nonce, CorrelationID: IdentifiantCorrelation(d.Kind, d.Subject.Hash, n), Outcome: "en_cours", Detail: detail}
}

func (p *Planificateur) creer(kind string, sujet *Sujet, deadlines []int64, t int64) *Demande {
	id := idDemande(kind, sujet.Hash)
	if existante, ok := p.demandes[id]; ok {
		p.journaliser(t, &id, vObj("event", vStr("anchor_duplicate_ignored"), "state", vStr(existante.State)))
		return nil
	}
	copieSujet := *sujet
	d := &Demande{Version: 0, ID: id, Kind: kind, Subject: &copieSujet, Deadlines: append([]int64{}, deadlines...), State: "a_envoyer", CreatedAt: Iso(t), Attempts: []*Tentative{}, AttemptsTotal: ptrI(0)}
	p.demandes[id] = d
	p.int(id)
	return d
}

// designe rend le prestataire désigné pour une sorte de jeton (EX-8.8).
func (p *Planificateur) designe(kind string) *Prestataire {
	if kind == "jeton_periode" {
		return p.roles["principal"]
	}
	if p.cfg.ProviderRole == "aucun" {
		return nil
	}
	return p.roles[p.cfg.ProviderRole]
}
func (p *Planificateur) releveAdmise(d *Demande) bool {
	return p.roles["secours"] != nil && (d.Kind == "jeton_periode" || (d.Kind == "jeton_point" && p.cfg.ProviderRole == "principal"))
}
func (p *Planificateur) delaiReleve(d *Demande) int64 {
	if d.Kind == "jeton_periode" {
		return p.cfg.ManifestFallbackAfterS * 1000
	}
	return p.cfg.CheckpointsFallbackAfterS * 1000
}
func (p *Planificateur) detailRegistre(d *Demande) *Value {
	s := d.Subject
	docType := DocTypePeriode
	if s.Kind == "point" {
		docType = DocTypePointDeControle
	}
	return vObj("fingerprint", vStr(EmpreinteAncre(s.OrgID, s.JournalID, s.Hash)), "doc_type", vStr(docType))
}

// cleOccupee dit si la clé de chaîne de l'ancre d est occupée. EX-9.4
// (complément du 2026-11-16) : « Pour ce verrou, la clé de chaîne d'une ancre
// est celle du journal de son sujet : deux ancres ont la même clé de chaîne
// quand leurs sujets ont le même org_id et le même journal_id, et un journal
// n'a jamais plus d'une ancre envoyee » ; la clé est occupée pour d quand une
// autre ancre de la file, de ce journal, est envoyee.
func (p *Planificateur) cleOccupee(d *Demande) bool {
	for _, x := range p.demandes {
		if x != d && prefixe(x.Kind, "ancre_registre_") && x.State == "envoyee" && x.Subject.OrgID == d.Subject.OrgID && x.Subject.JournalID == d.Subject.JournalID {
			return true
		}
	}
	return false
}

// cleDeChaine : clé de chaîne d'une ancre pour le verrou d'EX-9.4.
func cleDeChaine(d *Demande) string { return d.Subject.OrgID + "|" + d.Subject.JournalID }

// periodeBloquee : EX-9.4 (complément du 2026-11-16, l'ancre de la période
// après celles de ses points) : « L'ancre d'une période ne part pas tant
// qu'une ancre de point de la même période et du même journal n'a ni son
// reçu (obtenue) ni un autre état final (refusee, remplacee) ».
func (p *Planificateur) periodeBloquee(d *Demande) bool {
	if d.Kind != "ancre_registre_periode" {
		return false
	}
	for _, x := range p.demandes {
		if x.Kind == "ancre_registre_point" && !EtatsFinaux[x.State] && x.Subject.OrgID == d.Subject.OrgID && x.Subject.JournalID == d.Subject.JournalID && x.Subject.PeriodStart == d.Subject.PeriodStart {
			return true
		}
	}
	return false
}

// retenue : EX-9.4 (complément du 2026-11-16, une ancre de période qui
// attend retient sa clé) : « La clé d'une ancre est libre quand elle n'a
// aucune ancre en vol (envoyee) et qu'aucune ancre de période d'une période
// antérieure de la même clé (même org_id et journal_id, period_start plus
// petit) n'est dans un état non final ; sinon l'ancre est retenue » ;
// EX-9.4 (complément du 2026-11-16, l'ordre des ancres des points d'une
// période) : « L'ancre d'un point ne part pas tant que l'ancre d'un point
// antérieur de la même période et du même journal (checkpoint_ts plus petit,
// puis l'ordre de la file) n'a ni son reçu (obtenue) ni un autre état final
// (refusee, remplacee) : elle est retenue, comme derrière une ancre en vol ».
// L'ancre en vol est vue par cleOccupee, l'attente de ses points par
// l'ancre de la période par periodeBloquee.
func (p *Planificateur) retenue(d *Demande) bool {
	for _, x := range p.demandes {
		if x == d || EtatsFinaux[x.State] || x.Subject.OrgID != d.Subject.OrgID || x.Subject.JournalID != d.Subject.JournalID {
			continue
		}
		if x.Kind == "ancre_registre_periode" && x.Subject.PeriodStart < d.Subject.PeriodStart {
			return true
		}
		if d.Kind == "ancre_registre_point" && x.Kind == "ancre_registre_point" && x.Subject.PeriodStart == d.Subject.PeriodStart && PointAnterieur(x, d) {
			return true
		}
	}
	return false
}

// PointAnterieur : l'ancre de point b précède l'ancre de point a dans sa
// période (EX-9.4, complément du 2026-11-16) : checkpoint_ts plus petit, en
// instant, puis l'ordre de la file (8.5 : created_at, puis id).
func PointAnterieur(b, a *Demande) bool {
	tb, eb := Ms(b.Subject.DeclaredAt)
	ta, ea := Ms(a.Subject.DeclaredAt)
	if eb == nil && ea == nil && tb != ta {
		return tb < ta
	}
	if (eb != nil || ea != nil) && b.Subject.DeclaredAt != a.Subject.DeclaredAt {
		return b.Subject.DeclaredAt < a.Subject.DeclaredAt
	}
	cb, ebc := Ms(b.CreatedAt)
	ca, eac := Ms(a.CreatedAt)
	if ebc == nil && eac == nil && cb != ca {
		return cb < ca
	}
	if (ebc != nil || eac != nil) && b.CreatedAt != a.CreatedAt {
		return b.CreatedAt < a.CreatedAt
	}
	return b.ID < a.ID
}

// attend : l'ancre attend (attente_nonce) au lieu de partir : sa clé a une
// ancre en vol, c'est une ancre de période dont une ancre de point de la
// période n'est pas finale, ou elle est retenue (EX-9.4).
func (p *Planificateur) attend(d *Demande) bool {
	return p.cleOccupee(d) || p.periodeBloquee(d) || p.retenue(d)
}

// CodesSansAdmission : EX-9.5 (complément du 2026-11-16) : codes d'une
// tentative « qui dit qu'aucune transaction n'est partie et qu'aucun nonce
// n'est consommé, noeud_injoignable [...], nonce_incoherent [...],
// transaction_refusee [...], ou l'un des codes du composant d'ancrage de même
// sens (EX-8.10 : registre_absent, exception_client, reprise_impossible,
// lecture_nonce_incoherent, lecture_incoherente) ».
var CodesSansAdmission = map[string]bool{"noeud_injoignable": true, "nonce_incoherent": true, "transaction_refusee": true, "registre_absent": true, "exception_client": true, "reprise_impossible": true, "lecture_nonce_incoherent": true, "lecture_incoherente": true}

// sansAdmission : la tentative est close sur un code de CodesSansAdmission
// (une tentative obtenue, en cours ou de code nul a pu être admise).
func sansAdmission(a *Tentative) bool {
	return a.Outcome != "obtenue" && a.Outcome != "en_cours" && a.ErrorCode != nil && CodesSansAdmission[*a.ErrorCode]
}

// noterFenetreRelue : EX-9.5 (complément du 2026-11-16) : une tentative
// « sortie de la fenêtre de 32 avant le dernier démarrage, dont la file ne
// dit plus rien (EX-8.5, règle 7), a pu être admise » : relue, une ligne dont
// attempts_total dépasse le nombre de ses tentatives n'est pas encore à
// envoyer.
func (p *Planificateur) noterFenetreRelue(d *Demande) {
	if d.Kind == "ancre_registre_point" {
		p.int(d.ID).peutEtreAdmise = d.Total() > int64(len(d.Attempts))
	}
}

// encoreAEnvoyer : EX-9.5 (complément du 2026-11-16, l'ancre d'un point en
// reprise) : « Une ancre de point a_reprendre après un échec signalé
// (EX-8.10) est encore à envoyer, comme une ancre a_envoyer, quand aucune de
// ses tentatives n'a pu être admise par un nœud » ; « Une tentative close sur
// tout autre code [...] ou obtenue, ou une tentative sortie de la fenêtre de
// 32 avant le dernier démarrage [...] a pu être admise : l'ancre n'est pas
// remplacée et suit sa reprise ». Une a_reprendre sans tentative est encore à
// envoyer.
func (p *Planificateur) encoreAEnvoyer(d *Demande) bool {
	switch d.State {
	case "a_envoyer":
		return true
	case "a_reprendre":
		if p.int(d.ID).peutEtreAdmise {
			return false
		}
		for _, a := range d.Attempts {
			if !sansAdmission(a) {
				return false
			}
		}
		return true
	}
	return false
}

// attendOuEnvoie : EX-9.4 (complément du 2026-11-16) : « Une ancre part dès
// sa création quand sa clé est libre (admission du point, clôture, EX-8.4,
// règles 2 et 3), ou à l'échéance de sa reprise (EX-8.10) ; sinon elle
// attend (action programmer de raison attente_nonce) » ; « à sa création ou
// à l'échéance de sa reprise, l'ancre de la période attend alors comme
// derrière une ancre en vol (attente_nonce) ».
//
// EX-9.4 (complément du 2026-11-16) : une ancre retenue « attend (action
// programmer de raison attente_nonce, sans minuterie) à sa création, à
// l'échéance de sa reprise et quand la clé se libère ».
func (p *Planificateur) attendOuEnvoie(d *Demande, t int64) {
	if p.attend(d) {
		p.programmer(d, t, t, "attente_nonce")
	} else {
		p.envoyerRegistre(d, t)
	}
}

// avantDansLaCle : ordre des ancres d'une clé (EX-9.4, complément du
// 2026-11-16) : period_start croissant ; dans une période, les points par
// checkpoint_ts (subject.declared_at) croissant, puis la période. Faux à
// égalité : l'ordre de la file départage alors.
func avantDansLaCle(a, b *Demande) bool {
	if a.Subject.PeriodStart != b.Subject.PeriodStart {
		return a.Subject.PeriodStart < b.Subject.PeriodStart
	}
	pa, pb := sortePeriode(a.Kind), sortePeriode(b.Kind)
	if pa != pb {
		return !pa
	}
	if pa {
		return false
	}
	ta, ea := Ms(a.Subject.DeclaredAt)
	tb, eb := Ms(b.Subject.DeclaredAt)
	if ea != nil || eb != nil {
		return a.Subject.DeclaredAt < b.Subject.DeclaredAt
	}
	return ta < tb
}

// --- point admis (EX-8.4, règles 1 et 3 ; EX-9.3 à EX-9.5) ---------------

func (p *Planificateur) pointProduit(t int64, data *Value) {
	treeSize, _ := entierDe(data, "tree_size")
	ts := treeSize
	sujet := &Sujet{Kind: "point", OrgID: chaineOu(data, "", "org_id"), JournalID: chaineOu(data, "", "journal_id"), PeriodStart: entierOu(data, 0, "period_start"), Hash: chaineOu(data, "", "checkpoint_hash"), TreeSize: &ts, DeclaredAt: chaineOu(data, "", "checkpoint_ts")}
	per := p.periode(sujet, t, true, false)
	tsPoint, err := Ms(sujet.DeclaredAt)
	if err != nil {
		panic(refus("", "%s", err.Error()))
	}
	if _, ok := p.demandes[idDemande("ancre_registre_point", sujet.Hash)]; ok {
		p.journaliser(t, nil, vObj("event", vStr("anchor_duplicate_ignored"), "checkpoint_hash", vStr(sujet.Hash)))
		return
	}
	if _, ok := p.demandes[idDemande("jeton_point", sujet.Hash)]; ok {
		p.journaliser(t, nil, vObj("event", vStr("anchor_duplicate_ignored"), "checkpoint_hash", vStr(sujet.Hash)))
		return
	}
	// EX-3.5 (révision 0.6) : le point est admis à l'instant de cette entrée,
	// ou de sa relecture au démarrage (reconstruction d'EX-8.12).
	p.admissions[sujet.Hash] = t
	// cadence (EX-4.1, 8.9, révision 0.4 de CT-5) : dernier point admis de la période ouverte ; la
	// minuterie point_manquant est armée 2 × c_K après le checkpoint_ts déclaré du point, non après
	// son admission (un point reçu longtemps après sa production, saut d'horloge ou arrêt, lève
	// l'alerte dès sa relecture) ; le point de clôture (checkpoint_ts ≥ period_end) n'en arme aucune.
	if !per.close {
		copie := *sujet
		per.dernierPoint = &copie
		per.dernierPointAt = ptrI(tsPoint)
		if tsPoint < p.finPeriode(per) {
			p.timer(tsPoint+2*p.cfg.CheckpointIntervalS*1000, "cadence", cle(sujet), tsPoint, "")
		}
	}
	if p.actives() >= p.cfg.MaxPending {
		p.journaliser(t, nil, vObj("event", vStr("anchor_queue_full"), "tree_size", vInt(treeSize), "active", vInt(p.actives()), "max_pending", vInt(p.cfg.MaxPending)))
		p.alerter(t, nil, "file_pleine", "critique")
		return
	}
	// ancre au registre (EX-4.6, EX-9.3)
	regle := p.cfg.RegistryCheckpoints
	var ancre *Demande
	if regle != "aucun" && (regle == "tous" || treeSize > per.dernierAncre) {
		ancre = p.creer("ancre_registre_point", sujet, nil, t)
		p.ecrire(ancre, t, "a_envoyer")
		per.dernierAncre = treeSize
		// EX-9.5 : « les demandes ancre_registre_point encore a_envoyer d'une
		// même période ne sont pas toutes envoyées : seule celle du point admis
		// le plus récent part, les autres passent remplacee avec replaced_by » ;
		// complément du 2026-11-16 (l'ancre d'un point en reprise) : une ancre
		// a_reprendre dont aucune tentative n'a pu être admise par un nœud « est
		// encore à envoyer, comme une ancre a_envoyer [...]. À l'admission d'un
		// point plus récent de la même période et du même journal, elle passe
		// remplacee (replaced_by), et sa reprise n'a pas lieu ».
		for _, autre := range p.File() {
			if autre == ancre || autre.Kind != "ancre_registre_point" || cle(autre.Subject) != cle(sujet) || !p.encoreAEnvoyer(autre) {
				continue
			}
			delete(p.int(autre.ID).reprises, "")
			autre.ReplacedBy = ptrS(ancre.ID)
			autre.DueAt = nil
			p.emettre(t, "remplacer", &autre.ID, vObj("replaced_by", vStr(ancre.ID)))
			p.ecrire(autre, t, "remplacee")
			p.journaliser(t, &autre.ID, vObj("event", vStr("anchor_replaced"), "replaced_by", vStr(ancre.ID)))
		}
		p.attendOuEnvoie(ancre, t)
	} else {
		raison := "aucun_nouvel_evenement"
		if regle == "aucun" {
			raison = "ancre_des_points_desactivee"
		}
		p.journaliser(t, nil, vObj("event", vStr("checkpoint_not_anchored"), "reason", vStr(raison), "tree_size", vInt(treeSize)))
	}
	// échéances (EX-4.3, EX-8.4 règle 1)
	var choisies []int64
	for _, k := range per.ordre {
		if e := per.echeances[k]; e.state == "ouverte" && e.demande == nil && p.D(per, k) <= tsPoint {
			choisies = append(choisies, k)
		}
	}
	if len(choisies) > 0 {
		designe := p.designe("jeton_point")
		nouveau := treeSize > p.dernierContresigne(per) || p.cfg.CountersignIdle
		if nouveau && designe != nil {
			j := p.creer("jeton_point", sujet, choisies, t)
			for _, k := range choisies {
				per.get(k).demande = ptrS(j.ID)
				p.emettre(t, "echeance", &j.ID, vObj("k", vInt(k), "state", vStr("ouverte")))
			}
			if res := p.acquisRelues[j.ID]; res != nil {
				// EX-8.12 (complément du 2026-11-16) : demande recréée obtenue avec
				// le résultat de l'enregistrement relu, aucune tentative ni requête ;
				// ses échéances sont satisfaites.
				copie := *res
				j.Result = &copie
				p.ecrire(j, t, "obtenue")
				kmax := int64(0)
				for _, k := range choisies {
					per.get(k).state = "satisfaite"
					p.emettre(t, "echeance", &j.ID, vObj("k", vInt(k), "state", vStr("satisfaite")))
					kmax = max(kmax, k)
				}
				// EX-8.12 (complément du 2026-11-16) : « la demande recréée obtenue
				// s'applique ensuite comme à sa promotion (EX-4.4 ; EX-8.4, règle
				// 1) : les demandes de points non finales de la période qui servent
				// une échéance encore ouverte inférieure à sa plus grande échéance
				// [...] sont closes remplacee (replaced_by la demande recréée), avec
				// la ligne checkpoint_anchor_late (window_s : borne de son jeton
				// moins la plus petite échéance de la demande close) et l'alerte ».
				p.appliquerPromotion(j, t, per, kmax, borneDuResultat(j.Result, t))
			} else if ancre != nil && ancre.State != "obtenue" {
				p.ecrire(j, t, "attente_registre")
				s := p.int(j.ID)
				s.attenteAt = ptrI(t + p.cfg.SquatWaitS*1000)
				p.programmer(j, t, *s.attenteAt, "attente_registre")
				p.timer(*s.attenteAt, "attente_registre", j.ID, 0, "")
			} else {
				p.ecrire(j, t, "a_envoyer")
				p.pret(j, designe)
			}
		} else {
			for _, k := range choisies {
				per.get(k).state = "sans_objet"
				p.emettre(t, "echeance", nil, vObj("k", vInt(k), "state", vStr("sans_objet")))
			}
			raison := "aucun_nouvel_evenement"
			if nouveau {
				raison = "contresignature_desactivee"
			}
			p.journaliser(t, nil, vObj("event", vStr("deadline_sans_objet"), "reason", vStr(raison), "deadlines", vEntiers(choisies), "tree_size", vInt(treeSize)))
		}
	}
	// option mi_periode (EX-6.1) : le point sélectionné à k_m = ⌈n_T / 2⌉, contresigné ou non
	if km := p.echeanceMediane(); km > 0 && p.cfg.OtsEnabled && p.cfg.OtsCheckpoint == "mi_periode" {
		mi := false
		for _, k := range choisies {
			if k == km {
				mi = true
			}
		}
		if mi {
			if o := p.creer("ots_point", sujet, nil, t); o != nil {
				p.ecrire(o, t, "a_envoyer")
				p.soumettreOts(o, t)
			}
		}
	}
}

// --- clôture (EX-8.4, règle 2) -------------------------------------------------

// periodeClose crée les demandes de la clôture (EX-8.4, règle 2) ; seulement
// (non nil) restreint les sortes créées (reconstruction d'EX-8.12).
func (p *Planificateur) periodeClose(t int64, data *Value, seulement []string) {
	sujet := &Sujet{Kind: "periode", OrgID: chaineOu(data, "", "org_id"), JournalID: chaineOu(data, "", "journal_id"), PeriodStart: entierOu(data, 0, "period_start"), Hash: chaineOu(data, "", "period_hash"), DeclaredAt: chaineOu(data, "", "generated_at")}
	per := p.periode(sujet, t, false, true)
	per.close = true
	veut := func(kind string) bool { return seulement == nil || dans(kind, seulement) }
	var a, j, o *Demande
	if veut("ancre_registre_periode") {
		a = p.creer("ancre_registre_periode", sujet, nil, t)
	}
	if veut("jeton_periode") {
		j = p.creer("jeton_periode", sujet, nil, t)
	}
	if p.cfg.OtsEnabled && veut("ots_periode") {
		o = p.creer("ots_periode", sujet, nil, t)
	}
	if a != nil {
		p.ecrire(a, t, "a_envoyer")
	}
	jObtenue := false
	if j != nil {
		if res := p.acquisRelues[j.ID]; res != nil {
			// EX-8.12 (complément du 2026-11-16) : « Une demande recréée obtenue
			// porte le résultat de l'enregistrement [...], aucune tentative ; sa
			// ligne est écrite obtenue, ses échéances sont satisfaites (l'échéance
			// n_T pour le jeton_periode) ; aucune requête, aucune attente du
			// registre, aucun repli de clôture, aucune pièce stockée de nouveau,
			// aucune ligne checkpoint_countersigned ni period_timestamped ».
			copie := *res
			j.Result = &copie
			p.ecrire(j, t, "obtenue")
			p.emettre(t, "echeance", &j.ID, vObj("k", vInt(p.nT), "state", vStr("satisfaite")))
			jObtenue = true
			// EX-8.12 (complément du 2026-11-16) : elle s'applique comme à sa
			// promotion (EX-4.4), jusqu'à n_T, « et le jeton_periode clôt un
			// repli de clôture encore en cours ».
			p.appliquerPromotion(j, t, per, p.nT, borneDuResultat(j.Result, t))
		} else {
			p.ecrire(j, t, "attente_registre")
		}
	}
	if o != nil {
		p.ecrire(o, t, "a_envoyer")
	}
	if a != nil {
		// EX-8.4, règle 2 (complément du 2026-11-16) : « L'ancre part dès que
		// la clé de chaîne n'a plus de transaction sans reçu (EX-9.4) et [...]
		// que les ancres des points de la période, celle du point de clôture
		// comprise, ont leur reçu ou un autre état final ».
		p.attendOuEnvoie(a, t)
	}
	if j != nil && !jObtenue {
		s := p.int(j.ID)
		s.attenteAt = ptrI(t + p.cfg.InclusionAlertS*1000)
		p.programmer(j, t, *s.attenteAt, "attente_registre")
		p.timer(*s.attenteAt, "attente_registre", j.ID, 0, "")
		// EX-4.2, EX-8.4 règle 2 : repli sur le point de clôture si l'ancre de la période tarde
		p.timer(t+p.cfg.SquatWaitS*1000, "repli_cloture", j.ID, 0, "")
	}
	if o != nil {
		p.soumettreOts(o, t)
	}
}

// borneDuResultat rend la borne (genTime + précision) d'un résultat de
// jeton, à défaut son instant d'obtention, à défaut t.
func borneDuResultat(r *Resultat, t int64) int64 {
	if r == nil {
		return t
	}
	texte := r.ObtainedAt
	if r.Bound != nil {
		texte = *r.Bound
	}
	if v, err := Ms(texte); err == nil {
		return v
	}
	return t
}

// repliCloture (EX-4.2, EX-8.4 règle 2) : jeton_periode attend l'inclusion de
// l'ancre de la période depuis squat_wait_s ; le point de clôture, s'il engage
// un nouvel événement et n'a pas de demande de jeton, reçoit une demande
// jeton_point sans échéance auprès du prestataire des points.
func (p *Planificateur) repliCloture(dp *Demande, t int64) {
	per := p.periodes[cle(dp.Subject)]
	if per == nil || per.dernierPoint == nil {
		return
	}
	k := per.dernierPoint
	if _, ok := p.demandes[idDemande("jeton_point", k.Hash)]; ok {
		return
	}
	if k.TreeSize == nil || !(*k.TreeSize > p.dernierContresigne(per) || p.cfg.CountersignIdle) {
		return
	}
	designe := p.designe("jeton_point")
	if designe == nil {
		return
	}
	j := p.creer("jeton_point", k, nil, t)
	if j == nil {
		return
	}
	p.journaliser(t, &j.ID, vObj("event", vStr("checkpoint_closing_fallback"), "tree_size", vInt(*k.TreeSize), "period_request", vStr(dp.ID), "squat_wait_s", vInt(p.cfg.SquatWaitS)))
	ancre := p.demandes[idDemande("ancre_registre_point", k.Hash)]
	if ancre != nil && ancre.State != "obtenue" && ancre.State != "refusee" {
		p.ecrire(j, t, "attente_registre")
		s := p.int(j.ID)
		s.attenteAt = ptrI(t + p.cfg.SquatWaitS*1000)
		p.programmer(j, t, *s.attenteAt, "attente_registre")
		p.timer(*s.attenteAt, "attente_registre", j.ID, 0, "")
	} else {
		p.ecrire(j, t, "a_envoyer")
		p.pret(j, designe)
	}
}

// reconstruire (EX-8.12) : les objets durables sans ancre obtenue relus dans
// le stockage de l'enregistreur (entrée stockage_relu) sont confrontés à la
// file ; toute demande manquante d'une période close est recréée, et le
// dernier point de chaque période ouverte sans demande est traité comme admis.
func (p *Planificateur) reconstruire(t int64, data *Value, acquisitions []*AcquisitionRelue) {
	// EX-8.12 (complément du 2026-11-16) : « les enregistrements relus entrent
	// par le membre acquisitions de l'entrée stockage_relu [...] ; sans ce
	// membre, toute demande recréée l'est comme à la clôture ou à
	// l'admission » ; pour une même demande, le dernier enregistrement fait foi.
	p.acquisRelues = map[string]*Resultat{}
	for _, a := range acquisitions {
		p.acquisRelues[a.RequestID] = a.Result
	}
	defer func() { p.acquisRelues = nil }()
	avant := len(p.demandes)
	closes := map[string]bool{}
	for _, d := range p.demandes {
		if sortePeriode(d.Kind) {
			closes[cle(d.Subject)] = true
		}
	}
	var nPeriodes, nPoints int64
	if ps := data.Get("periods"); ps != nil && ps.Kind == KindArray {
		for _, m := range ps.Arr {
			c := fmt.Sprintf("%s|%s|%d", chaineOu(m, "", "org_id"), chaineOu(m, "", "journal_id"), entierOu(m, 0, "period_start"))
			closes[c] = true
			sortes := []string{"ancre_registre_periode", "jeton_periode"}
			if p.cfg.OtsEnabled {
				sortes = append(sortes, "ots_periode")
			}
			var manquantes []string
			for _, k := range sortes {
				if _, ok := p.demandes[idDemande(k, chaineOu(m, "", "period_hash"))]; !ok {
					manquantes = append(manquantes, k)
				}
			}
			if len(manquantes) == 0 {
				continue
			}
			nPeriodes++
			p.periodeClose(t, m, manquantes)
		}
	}
	derniers := map[string]*Value{}
	var ordre []string
	if ks := data.Get("checkpoints"); ks != nil && ks.Kind == KindArray {
		for _, k := range ks.Arr {
			c := fmt.Sprintf("%s|%s|%d", chaineOu(k, "", "org_id"), chaineOu(k, "", "journal_id"), entierOu(k, 0, "period_start"))
			if closes[c] {
				continue
			}
			prec, ok := derniers[c]
			if !ok {
				ordre = append(ordre, c)
				derniers[c] = k
				continue
			}
			a, _ := Ms(chaineOu(k, "", "checkpoint_ts"))
			b, _ := Ms(chaineOu(prec, "", "checkpoint_ts"))
			if a >= b {
				derniers[c] = k
			}
		}
	}
	for _, c := range ordre {
		k := derniers[c]
		h := chaineOu(k, "", "checkpoint_hash")
		existe := false
		for _, kind := range []string{"ancre_registre_point", "jeton_point", "ots_point"} {
			if _, ok := p.demandes[idDemande(kind, h)]; ok {
				existe = true
			}
		}
		if existe {
			continue
		}
		nPoints++
		p.pointProduit(t, k)
	}
	recreees := int64(len(p.demandes) - avant)
	p.journaliser(t, nil, vObj("event", vStr("anchoring_queue_rebuilt"), "recreated", vInt(recreees), "periods", vInt(nPeriodes), "checkpoints", vInt(nPoints)))
	if recreees > 0 {
		p.alerter(t, nil, "file_perdue", "critique")
	}
}

// rendreEcheances : une demande de point refusee rend la main à ses échéances
// encore ouvertes, que le point suivant sert (EX-4.3, EX-8.4 règle 1).
func (p *Planificateur) rendreEcheances(d *Demande) {
	per := p.periodes[cle(d.Subject)]
	if per == nil {
		return
	}
	for _, k := range d.Deadlines {
		if e, ok := per.echeances[k]; ok && e.state == "ouverte" && e.demande != nil && *e.demande == d.ID {
			e.demande = nil
		}
	}
}

// --- envois -----------------------------------------------------------------------

func (p *Planificateur) pret(d *Demande, prestataire *Prestataire) {
	if prestataire == nil {
		return
	}
	for _, x := range p.pretes {
		if x.id == d.ID && x.provider == prestataire.ID {
			return
		}
	}
	p.pretes = append(p.pretes, &prete{id: d.ID, provider: prestataire.ID, seq: p.seq})
	p.seq++
}

func rang(d *Demande) int {
	if d.Kind == "jeton_periode" {
		return 0
	}
	return 1
}

func (p *Planificateur) servir(t int64) {
	// 1. requêtes RFC 3161 prêtes (EX-8.7)
	sort.SliceStable(p.pretes, func(i, j int) bool {
		a := p.demandes[p.pretes[i].id]
		b := p.demandes[p.pretes[j].id]
		if rang(a) != rang(b) {
			return rang(a) < rang(b)
		}
		if a.Subject.PeriodStart != b.Subject.PeriodStart {
			return a.Subject.PeriodStart < b.Subject.PeriodStart
		}
		if a.Subject.DeclaredAt != b.Subject.DeclaredAt {
			return a.Subject.DeclaredAt < b.Subject.DeclaredAt
		}
		return p.pretes[i].seq < p.pretes[j].seq
	})
	for _, e := range append([]*prete{}, p.pretes...) {
		d := p.demandes[e.id]
		pr := p.prestataires[e.provider]
		if d == nil || EtatsFinaux[d.State] || pr == nil {
			p.retirerPrete(e)
			continue
		}
		dernier, ok := p.dernierEnvoi[pr.ID]
		if !ok || dernier+pr.MinIntervalMs <= t {
			p.retirerPrete(e)
			p.envoyerRfc3161(d, pr, t)
			continue
		}
		libre := dernier + pr.MinIntervalMs
		s := p.int(d.ID)
		if s.differe == nil || *s.differe != libre {
			s.differe = ptrI(libre)
			p.programmer(d, t, libre, "backoff")
			p.timer(libre, "dispatch", d.ID, 0, "")
		}
	}
	// 2. registre : une transaction par clé de chaîne (EX-9.4). Complément du
	// 2026-11-16 (EX-9.4, EX-8.10) : sont candidates les ancres a_envoyer et
	// les ancres a_reprendre dont due_at ≤ t sans reprise programmée (elles
	// attendent le nonce) ; « plusieurs clés libérées au même instant sont
	// servies dans l'ordre de la file de leur première ancre en attente ».
	// Deux journaux libres font donc partir chacun leur ancre.
	parCle := map[string][]*Demande{}
	var cles []string
	for _, d := range p.File() {
		if !prefixe(d.Kind, "ancre_registre_") || !p.ancreCandidate(d, t) {
			continue
		}
		c := cleDeChaine(d)
		if _, ok := parCle[c]; !ok {
			cles = append(cles, c)
		}
		parCle[c] = append(parCle[c], d)
	}
	for _, c := range cles {
		candidats := parCle[c]
		// EX-9.4 (complément du 2026-11-16, ordre des ancres d'une clé) :
		// « part au plus une ancre de la clé : la première, dans cet ordre,
		// des ancres qui attendent [...] — par period_start croissant
		// (EX-8.7) ; dans une même période, les ancres de ses points par
		// checkpoint_ts croissant, puis l'ancre de la période ; l'ordre de la
		// file (8.5 : created_at, puis id) ne départage que les égalités ».
		// p.File() rend déjà l'ordre de la file : le tri stable le garde.
		sort.SliceStable(candidats, func(i, j int) bool { return avantDansLaCle(candidats[i], candidats[j]) })
		premiere := candidats[0]
		// « Si cette première est une ancre de période qui attend encore le
		// reçu d'une ancre de point de sa période [...], rien ne part de la
		// clé : l'ancre du point part à l'échéance de sa reprise, celle de la
		// période à son reçu. »
		// EX-9.4 (complément du 2026-11-16) : une ancre retenue « n'est pas
		// candidate, pas plus que les candidates rangées après elle (elles sont
		// d'une période postérieure) » ; et pour l'ancre d'un point retenue par
		// celle d'un point antérieur : « à la libération de la clé, si la
		// première candidate est ainsi retenue, rien ne part ».
		if !p.attend(premiere) {
			p.envoyerRegistre(premiere, t)
		}
	}
	// 3. soumissions OpenTimestamps en attente d'envoi
	for _, d := range p.File() {
		if prefixe(d.Kind, "ots_") && d.State == "a_envoyer" {
			p.soumettreOts(d, t)
		}
	}
}

// ancreCandidate : ancre a_envoyer, ou a_reprendre échue sans reprise
// programmée (EX-8.10 : elle attend le reçu de l'ancre en vol de sa clé).
func (p *Planificateur) ancreCandidate(d *Demande, t int64) bool {
	switch d.State {
	case "a_envoyer":
		return true
	case "a_reprendre":
		if _, ok := p.int(d.ID).reprises[""]; ok || d.DueAt == nil {
			return false
		}
		v, err := Ms(*d.DueAt)
		return err == nil && v <= t
	}
	return false
}

func (p *Planificateur) retirerPrete(e *prete) {
	out := p.pretes[:0]
	for _, x := range p.pretes {
		if x != e {
			out = append(out, x)
		}
	}
	p.pretes = out
}

func (p *Planificateur) envoyerRfc3161(d *Demande, pr *Prestataire, t int64) {
	s := p.int(d.ID)
	n := d.Total() + 1
	nonce := p.aleatoire.NonceTsa(d.Subject, n)
	requete, err := ConstruireRequete(d.Subject.Hash, nonce, pr.PolicyOID, true)
	if err != nil {
		panic(err)
	}
	p.ajouterTentative(d, ptrS(pr.ID), t, ptrS(HexNonce(nonce)), "requete envoyee")
	if n == 1 {
		s.premierEnvoi = ptrI(t)
	}
	p.dernierEnvoi[pr.ID] = t
	d.DueAt = nil
	s.differe = nil
	p.ecrire(d, t, "envoyee") // EX-8.5, règle 1 : la ligne envoyee (nonce, tentative) précède l'envoi
	p.emettre(t, "envoyer_rfc3161", &d.ID, vObj("provider", vStr(pr.ID), "attempt", vInt(n), "digest", vStr(d.Subject.Hash), "nonce", vStr(HexNonce(nonce)), "policy_oid", vStrOuNul(pr.PolicyOID), "request_sha256", vStr(SHA256Hex(requete)), "request_size", vInt(int64(len(requete)))))
	s.enCours[pr.ID] = n
	s.engages[pr.ID] = true
	if n == 1 && p.releveAdmise(d) && pr.ID != p.roles["secours"].ID {
		p.timer(t+p.delaiReleve(d), "releve", d.ID, 0, "")
	}
}

func (p *Planificateur) envoyerRegistre(d *Demande, t int64) {
	s := p.int(d.ID)
	p.ajouterTentative(d, nil, t, nil, "transaction envoyee")
	d.DueAt = nil
	p.ecrire(d, t, "envoyee")
	p.emettre(t, "envoyer_registre", &d.ID, p.detailRegistre(d))
	s.inclusionAt = ptrI(t + p.cfg.InclusionAlertS*1000)
	p.timer(*s.inclusionAt, "inclusion", d.ID, 0, "")
}

func (p *Planificateur) soumettreOts(d *Demande, t int64) {
	s := p.int(d.ID)
	nonce := p.aleatoire.NonceOts(d.Subject)
	cals := p.cfg.Calendars
	n := p.ajouterTentative(d, nil, t, nil, fmt.Sprintf("soumission a %d calendriers", len(cals)))
	d.DueAt = nil
	p.ecrire(d, t, "envoyee")
	p.emettre(t, "soumettre_ots", &d.ID, vObj("digest", vStr(d.Subject.Hash), "nonce", vStr("0x"+hex.EncodeToString(nonce)), "calendars", vChaines(cals)))
	s.enCours[""] = n
}

func (p *Planificateur) relever(d *Demande, t int64, cause string) {
	secours := p.roles["secours"]
	p.emettre(t, "releve", &d.ID, vObj("provider", vStr(secours.ID)))
	ligne := vObj("event", vStr("anchor_fallback"), "to", vStr(secours.ID), "reason", vStr(cause))
	// EX-8.15 (révision 0.6) : la tentative dont l'issue déclenche la relève, la plus récente
	var derniere *Tentative
	for _, a := range d.Attempts {
		if derniere == nil || a.N > derniere.N {
			derniere = a
		}
	}
	if derniere != nil {
		ligne = avecRang(ligne, d, derniere.N)
	}
	p.journaliser(t, &d.ID, ligne)
	p.pret(d, secours)
}

// --- registre (EX-8.10, EX-9.6, EX-9.7) -----------------------------------------

func (p *Planificateur) jetonDuSujet(d *Demande) *Demande {
	kind := "jeton_periode"
	if d.Subject.Kind == "point" {
		kind = "jeton_point"
	}
	return p.demandes[idDemande(kind, d.Subject.Hash)]
}

// ignoree consigne un reçu ou un échec du registre qui ne s'applique pas.
// EX-8.10 (complément du 2026-11-16) : « un reçu (inclusion_registre) ou un
// échec signalé (echec_registre) ne s'applique qu'à une ancre dont une
// tentative est en cours (sa transaction) ; pour une ancre a_envoyer ou
// a_reprendre [...], ou close, il est ignoré et consigné
// anchor_duplicate_ignored avec son état » ; 8.5, règle 2 : « avec state
// (l'état de l'ancre) ou, pour une ancre inconnue, reason demande_inconnue ».
func (p *Planificateur) ignoree(t int64, data *Value, d *Demande) {
	if d == nil || !prefixe(d.Kind, "ancre_registre_") {
		p.journaliser(t, ptrChaine(data, "request_id"), vObj("event", vStr("anchor_duplicate_ignored"), "reason", vStr("demande_inconnue")))
		return
	}
	p.journaliser(t, &d.ID, vObj("event", vStr("anchor_duplicate_ignored"), "state", vStr(d.State)))
}

// ancreEnVol : la dernière tentative de l'ancre est en cours.
func ancreEnVol(d *Demande) bool {
	var der *Tentative
	for _, a := range d.Attempts {
		if der == nil || a.N > der.N {
			der = a
		}
	}
	return !EtatsFinaux[d.State] && der != nil && der.Outcome == "en_cours"
}

func (p *Planificateur) inclusionRegistre(t int64, data *Value) {
	d := p.demandes[chaineOu(data, "", "request_id")]
	if d == nil || !prefixe(d.Kind, "ancre_registre_") || !ancreEnVol(d) {
		p.ignoree(t, data, d)
		return
	}
	s := p.int(d.ID)
	att := d.Attempts[len(d.Attempts)-1]
	att.Outcome = "obtenue"
	att.Detail = fmt.Sprintf("ancre incluse au bloc %d", entierOu(data, 0, "block_number"))
	capture := chaineOu(data, "", "capture_sha256")
	d.Result = &Resultat{SHA256: capture, Size: TailleIndexCapture, ObtainedAt: Iso(t)}
	d.DueAt = nil
	s.inclusionAt = nil
	p.emettre(t, "stocker", &d.ID, vObj("sha256", vStr(capture), "size", vInt(TailleIndexCapture), "bound", vNull()))
	p.ecrire(d, t, "obtenue")
	// EX-8.10 (complément du 2026-11-16) : « au reçu, ce délai court depuis la
	// création de l'ancre (son admission), attente du nonce derrière une autre
	// ancre de la clé comprise, et non depuis son premier envoi ; l'alerte
	// n'est pas levée de nouveau au reçu quand un renvoi sans reçu l'a déjà
	// levée depuis le dernier démarrage ».
	creation, err := Ms(d.CreatedAt)
	if err != nil {
		panic(refus("", "%s", err.Error()))
	}
	if t-creation > p.cfg.InclusionAlertS*1000 && s.renvois == 0 {
		p.alerter(t, &d.ID, "inclusion_late", "mineure")
	}
	if j := p.jetonDuSujet(d); j != nil && j.State == "attente_registre" {
		p.pret(j, p.designe(j.Kind))
	}
}

func (p *Planificateur) echecRegistre(t int64, data *Value) {
	d := p.demandes[chaineOu(data, "", "request_id")]
	if d == nil || !prefixe(d.Kind, "ancre_registre_") || !ancreEnVol(d) {
		p.ignoree(t, data, d)
		return
	}
	s := p.int(d.ID)
	s.inclusionAt = nil
	code := chaineOu(data, "", "code")
	att := d.Attempts[len(d.Attempts)-1]
	if code == "empreinte_squattee" {
		att.Outcome = "echec_permanente"
		att.ErrorCode = ptrS(code)
		att.Detail = "empreinte deja ancree par un tiers"
		d.DueAt = nil
		p.ecrire(d, t, "refusee")
		p.alerter(t, &d.ID, "empreinte_squattee", "critique")
		p.journaliser(t, &d.ID, vObj("event", vStr("anchor_refused"), "error_code", vStr(code)))
		// EX-9.7 : sur l'ancre d'un point, « le point garde son jeton RFC 3161 »
		// (AN-36 : le jeton_point part après ce refus) ; sur l'ancre d'une
		// période (complément du 2026-11-16) : « Un refus n'est pas une
		// inclusion : jeton_periode reste attente_registre (EX-8.4, règle 2 ;
		// AN-36), aucune requête RFC 3161 sur periodHash ne part, et la période
		// reste signalée registry_pending ».
		if j := p.jetonDuSujet(d); j != nil && j.Kind == "jeton_point" && j.State == "attente_registre" {
			p.pret(j, p.designe(j.Kind))
		}
		return
	}
	// EX-8.10 (complément du 2026-11-16) : « tout autre échec que le registre
	// signale pour une ancre en vol [...] ne la renvoie pas aussitôt : la
	// tentative est close (echec_transitoire, ou echec_permanente pour un refus
	// définitif, code refus_*) ».
	definitif := strings.HasPrefix(code, "refus_")
	att.Outcome = "echec_transitoire"
	if definitif {
		att.Outcome = "echec_permanente"
	}
	att.ErrorCode = ptrS(code)
	att.Detail = "registre : " + code
	if definitif && d.Kind == "ancre_registre_point" {
		// « un refus définitif rend refusee l'ancre d'un point (alerte
		// prestataires_epuises majeure, ligne anchor_refused), dont le jeton
		// part alors sans elle (EX-9.7) ».
		att.NextAt = nil
		d.DueAt = nil
		p.ecrire(d, t, "refusee")
		p.alerter(t, &d.ID, "prestataires_epuises", "majeure")
		p.journaliser(t, &d.ID, vObj("event", vStr("anchor_refused"), "error_code", vStr(code)))
		if j := p.jetonDuSujet(d); j != nil && j.State == "attente_registre" {
			p.pret(j, p.designe(j.Kind))
		}
		return
	}
	// « sinon la ligne anchor_retry (mode reprise, error_code, rang et
	// attempt_id de la tentative close) est écrite et la demande passe
	// a_reprendre, due_at à l'attente d'EX-8.9 (k : tentatives en échec de la
	// demande, gigue comprise ; retry.max_ms pour le refus définitif d'une
	// ancre de période, jamais abandonnée, EX-4.5), action programmer de raison
	// backoff ». Les tentatives sorties de la fenêtre de 32, jamais obtenues
	// (l'ancre n'est pas finale), comptent parmi les échecs.
	var delai int64
	if definitif {
		delai = int64(p.cfg.Retry.MaxMs)
	} else {
		k := d.Total() - int64(len(d.Attempts))
		if k < 0 {
			k = 0
		}
		for _, a := range d.Attempts {
			if a.Outcome != "obtenue" {
				k++
			}
		}
		v, _ := CalculerAttente(nil, nil, k, true, p.cfg.Retry, p.aleatoire.Gigue())
		delai = int64(v)
	}
	next := t + delai
	att.NextAt = ptrS(Iso(next))
	p.journaliser(t, &d.ID, avecRang(vObj("event", vStr("anchor_retry"), "kind", vStr(d.Kind), "mode", vStr("reprise"), "error_code", vStr(code)), d, att.N))
	// EX-8.10 (complément du 2026-11-16) : « ce refus définitif de l'ancre
	// d'une période est un incident [...] ; la ligne anchor_retry est suivie
	// de l'alerte prestataires_epuises critique (8.9) [...], levée une fois
	// par ancre depuis le dernier démarrage, puis de l'écriture a_reprendre et
	// de l'action programmer ; un refus suivant de la même ancre ne la lève
	// pas de nouveau ». La marque est effacée à chaque démarrage (demarrer).
	if definitif && !s.alertes["prestataires_epuises"] {
		s.alertes["prestataires_epuises"] = true
		p.alerter(t, &d.ID, "prestataires_epuises", "critique")
	}
	d.DueAt = ptrS(Iso(next))
	p.ecrire(d, t, "a_reprendre")
	p.programmer(d, t, next, "backoff")
	s.reprises[""] = next
	p.timer(next, "reprise", d.ID, 0, "")
}

func (p *Planificateur) cloreTentativeRegistre(d *Demande, t int64, code, detail string) {
	if len(d.Attempts) == 0 {
		return
	}
	att := d.Attempts[len(d.Attempts)-1]
	if att.Outcome != "en_cours" {
		return
	}
	att.Outcome = "echec_transitoire"
	att.ErrorCode = ptrS(code)
	att.NextAt = ptrS(Iso(t))
	if detail == "" {
		detail = fmt.Sprintf("aucun recu en %d s", p.cfg.InclusionAlertS)
	}
	att.Detail = detail
}

// reposer rend la prochaine échéance d'une minuterie périodique de pas donné
// échue à t et le nombre d'échéances sautées : au quatrième rejeu d'une passe
// (EX-8.10), la première échéance postérieure à l'instant de l'entrée, les
// échéances intermédiaires n'étant jamais rejouées ; sinon t + pas.
func (p *Planificateur) reposer(t, pas int64, quatrieme bool) (int64, int64) {
	prochain := t + pas
	if !quatrieme || pas <= 0 || prochain > p.instantPasse {
		return prochain, 0
	}
	n := (p.instantPasse-t)/pas + 1
	return t + n*pas, n - 1
}

func (p *Planificateur) examinerAttenteRegistre(d *Demande, t int64, quatrieme bool) {
	s := p.int(d.ID)
	kind := "ancre_registre_periode"
	if d.Subject.Kind == "point" {
		kind = "ancre_registre_point"
	}
	ancre := p.demandes[idDemande(kind, d.Subject.Hash)]
	// EX-9.7 (complément du 2026-11-16) : l'ancre d'une période refusée ne
	// libère pas jeton_periode, qui attend son inclusion sans borne (« rien ne
	// lève ce signal tant que la période n'a pas de jeton ») ; l'ancre d'un
	// point refusée libère son jeton_point.
	if ancre == nil || ancre.State == "obtenue" || (ancre.State == "refusee" && d.Kind == "jeton_point") {
		p.pret(d, p.designe(d.Kind))
		return
	}
	creation, err := Ms(d.CreatedAt)
	if err != nil {
		panic(refus("", "%s", err.Error()))
	}
	if d.Kind == "jeton_point" {
		limite := creation + p.cfg.SquatWaitS*1000
		if t < limite {
			s.attenteAt = ptrI(limite)
			p.programmer(d, t, limite, "attente_registre")
			p.timer(limite, "attente_registre", d.ID, 0, "")
			return
		}
		p.journaliser(t, &d.ID, vObj("event", vStr("ordre_ancres_non_respecte"), "tree_size", vIntOuNul(d.Subject.TreeSize), "squat_wait_s", vInt(p.cfg.SquatWaitS)))
		p.pret(d, p.designe(d.Kind))
		return
	}
	age := (t - creation) / 1000
	if age >= p.cfg.InclusionAlertS {
		p.journaliser(t, &d.ID, vObj("event", vStr("registry_pending"), "age_s", vInt(age)))
		if !s.alertes["registry_pending"] {
			s.alertes["registry_pending"] = true
			p.alerter(t, &d.ID, "registry_pending", "majeure")
		}
	}
	if age >= p.cfg.AnchorPendingAlertS && !s.alertes["anchor_pending"] {
		s.alertes["anchor_pending"] = true
		p.journaliser(t, &d.ID, vObj("event", vStr("anchor_pending"), "age_s", vInt(age)))
		p.alerter(t, &d.ID, "anchor_pending", "majeure")
	}
	// EX-8.10 : au quatrième rejeu d'une passe, reposée à la première échéance
	// postérieure à l'instant de l'entrée ; les échéances sautées ne sont pas
	// consignées pour l'examen de l'attente du registre.
	prochain, _ := p.reposer(t, p.cfg.InclusionAlertS*1000, quatrieme)
	s.attenteAt = ptrI(prochain)
	p.programmer(d, t, *s.attenteAt, "attente_registre")
	p.timer(*s.attenteAt, "attente_registre", d.ID, 0, "")
}

// --- réponses RFC 3161 (EX-5.10 à EX-5.12, EX-8.6, EX-8.8, EX-8.9) -------------

type classement struct {
	issue          string
	code           *string
	piece          bool
	critique       bool
	avertissements []string
	bound          *int64
	detail         string
}

func (p *Planificateur) classer(d *Demande, att *Tentative, data *Value, t int64) *classement {
	f := p.cfg.Fraicheur
	res := &classement{issue: "echec_permanente", avertissements: []string{}}
	fin := func(issue, code, detail string) *classement {
		r := *res
		r.issue = issue
		r.code = ptrS(code)
		r.detail = detail
		return &r
	}
	piece := func(code, detail string) *classement {
		r := fin("echec_permanente", code, detail)
		r.piece = true
		return r
	}
	httpStatus := ptrEntier(data, "http_status")
	retryAfter := ptrEntier(data, "retry_after_s")
	switch chaineOu(data, "", "transport") {
	case "erreur_transport":
		return fin("echec_transitoire", "erreur_transport", "erreur de transport")
	case "delai":
		return fin("echec_transitoire", "delai", "delai de reponse depasse")
	case "reponse":
	default:
		return fin("echec_permanente", "reponse_illisible", "transport inconnu")
	}
	if httpStatus == nil || *httpStatus != 200 {
		st := int64(0)
		if httpStatus != nil {
			st = *httpStatus
		}
		issue := "echec_permanente"
		if httpTransitoires[st] {
			issue = "echec_transitoire"
		}
		detail := fmt.Sprintf("http %d", st)
		if retryAfter != nil {
			detail += fmt.Sprintf(" ; Retry-After %d s", *retryAfter)
		}
		return fin(issue, fmt.Sprintf("http_%d", st), detail)
	}
	// EX-5.10, étape 1 : Content-Type et taille, quand l'entrée les porte (EX-5.5)
	if ct := ptrChaine(data, "content_type"); ct != nil {
		base := strings.ToLower(strings.TrimSpace(strings.SplitN(*ct, ";", 2)[0]))
		if base != "application/timestamp-reply" && base != "application/timestamp-response" {
			return fin("echec_permanente", "type_contenu", fmt.Sprintf("Content-Type %s non admis", *ct))
		}
	}
	if taille := ptrEntier(data, "body_size"); taille != nil && *taille > 128*1024 {
		return fin("echec_permanente", "taille", fmt.Sprintf("corps de %d octets, au plus %d", *taille, 128*1024))
	}
	st := ptrEntier(data, "pki_status")
	if st == nil {
		return fin("echec_permanente", "reponse_illisible", "TimeStampResp illisible")
	}
	switch *st {
	case 2:
		// EX-5.10, étape 2 (complément du 2026-11-16) : « un PKIFailureInfo hors
		// des huit valeurs nommées (autre dans les traces) donne statut_2, comme
		// un status 2 sans PKIFailureInfo ».
		fi := ptrChaine(data, "failure_info")
		if fi == nil || !failureInfoNommee(*fi) {
			return fin("echec_permanente", "statut_2", "PKIStatus 2 (rejection)")
		}
		issue := "echec_permanente"
		if echecsTransitoires[*fi] {
			issue = "echec_transitoire"
		}
		return fin(issue, "echec_"+*fi, "PKIStatus 2 (rejection) ; "+*fi)
	case 3:
		return fin("echec_transitoire", "statut_3", "PKIStatus 3 (waiting)")
	case 4, 5:
		r := fin("echec_permanente", fmt.Sprintf("statut_%d", *st), fmt.Sprintf("PKIStatus %d (%s)", *st, NomsPKI[*st]))
		r.critique = true
		return r
	case 0, 1:
	default:
		return fin("echec_permanente", fmt.Sprintf("statut_%d", *st), fmt.Sprintf("PKIStatus %d inconnu", *st))
	}
	// EX-5.10, étape 2 (complément du 2026-11-16) : « une réponse de status 0
	// ou 1 sans TimeStampToken est reponse_illisible (permanente, détail
	// TimeStampToken absent), jamais promue ».
	if ptrChaine(data, "token_sha256") == nil {
		return fin("echec_permanente", "reponse_illisible", "TimeStampToken absent")
	}
	if im := ptrBool(data, "imprint_matches"); im == nil || !*im {
		return piece("empreinte_differente", "messageImprint different de l'empreinte demandee")
	}
	nonce := ptrChaine(data, "nonce_in_response")
	if nonce == nil {
		return piece("nonce_absent", "nonce absent du TSTInfo")
	}
	if att.Nonce == nil || *nonce != *att.Nonce {
		attendu := "null"
		if att.Nonce != nil {
			attendu = *att.Nonce
		}
		return piece("nonce_different", fmt.Sprintf("nonce %s different de %s", *nonce, attendu))
	}
	// EX-5.10, étape 5 : politique (résultat porté par l'entrée)
	if pc := ptrChaine(data, "policy_check"); pc != nil {
		switch *pc {
		case "politique_differente":
			return piece("politique_differente", "politique differente de la politique demandee")
		case "politique_refusee":
			return piece("politique_refusee", "politique hors de accepted_policies")
		}
	}
	passes := map[string]bool{}
	for _, c := range chainesDe(data, "checks_passed") {
		passes[c] = true
	}
	for i := 1; i <= 9; i++ {
		id := fmt.Sprintf("T-%d", i)
		if !passes[id] {
			return piece("verification_"+id, fmt.Sprintf("verification %s en echec", id))
		}
	}
	genTexte, ok := chaineDe(data, "gen_time")
	if !ok {
		panic(refus("", "reponse_rfc3161 : gen_time attendu pour un jeton accepté"))
	}
	genTime, err := Ms(genTexte)
	if err != nil {
		panic(refus("", "%s", err.Error()))
	}
	bound, dansLaPlage := borneDansLaPlage(genTime, nombreOu(data, 0, "accuracy_s"))
	if !dansLaPlage {
		// EX-5.10, étape 6 (complément du 2026-11-16) : « genTime plus la
		// précision hors de la plage d'un instant (±8,64 × 10^15 ms) est
		// verification_T-7 ».
		return piece("verification_T-7", "precision hors de la plage d'un instant (T-7)")
	}
	envoi, err := Ms(att.StartedAt)
	if err != nil {
		panic(refus("", "%s", err.Error()))
	}
	s := p.int(d.ID)
	if t-envoi > f.MaxResponseDelayS*1000 {
		if s.tardives+1 < 3 {
			r := fin("reponse_tardive", "reponse_tardive", fmt.Sprintf("reponse recue %d s apres l'envoi", (t-envoi)/1000))
			r.piece = true
			r.bound = &bound
			return r
		}
		res.avertissements = append(res.avertissements, "reponse_tardive")
	}
	if dlt := genTime - envoi; dlt > f.ClockToleranceS*1000 || -dlt > f.ClockToleranceS*1000 {
		res.avertissements = append(res.avertissements, "horloge_suspecte")
	}
	res.issue = "obtenue"
	res.code = nil
	res.bound = &bound
	res.detail = NomsPKI[*st] + " ; T-1 a T-9 reussies"
	if len(res.avertissements) > 0 {
		res.detail += " ; avertissement "
		for i, a := range res.avertissements {
			if i > 0 {
				res.detail += ", "
			}
			res.detail += a
		}
	}
	return res
}

// failureInfoNommee : l'une des huit valeurs de PKIFailureInfo que la RFC 3161
// nomme (§2.4.2).
func failureInfoNommee(fi string) bool {
	for _, nom := range NomsFailureInfo {
		if nom == fi {
			return true
		}
	}
	return false
}

// InstantMaxMs borne la valeur d'un instant (±8,64 × 10^15 ms, EX-5.10).
const InstantMaxMs = 8_640_000_000_000_000

// borneDansLaPlage rend genTime plus la précision, et si la somme tient dans la
// plage d'un instant.
func borneDansLaPlage(genTime int64, accuracyS float64) (int64, bool) {
	somme := float64(genTime) + accuracyS*1000
	if somme > InstantMaxMs || somme < -InstantMaxMs {
		return 0, false
	}
	return genTime + int64(accuracyS*1000), true
}

// borneDePiece rend la borne d'une pièce, jeton d'une réponse à une
// tentative qui n'est plus en cours. 8.5, règle 2 (complément du 2026-11-16) :
// « la borne d'une telle pièce (bound de l'action stocker) est genTime plus la
// précision quand le jeton passe les étapes 3 à 6 d'EX-5.10 pour la tentative
// qu'il désigne (avec le nonce de cette tentative, que le planificateur garde
// aussi quand il la voit sortir de la fenêtre de la règle 7), nulle sinon ».
func borneDePiece(data *Value, nonceTentative *string) *Value {
	g, ok := chaineDe(data, "gen_time")
	if !ok {
		return vNull()
	}
	if im := ptrBool(data, "imprint_matches"); im == nil || !*im {
		return vNull()
	}
	if n := ptrChaine(data, "nonce_in_response"); n == nil || nonceTentative == nil || *n != *nonceTentative {
		return vNull()
	}
	if pc := ptrChaine(data, "policy_check"); pc != nil && *pc != "conforme" {
		return vNull()
	}
	passes := map[string]bool{}
	for _, c := range chainesDe(data, "checks_passed") {
		passes[c] = true
	}
	for i := 1; i <= 9; i++ {
		if !passes[fmt.Sprintf("T-%d", i)] {
			return vNull()
		}
	}
	gm, err := Ms(g)
	if err != nil {
		return vNull()
	}
	b, dansLaPlage := borneDansLaPlage(gm, nombreOu(data, 0, "accuracy_s"))
	if !dansLaPlage {
		return vNull()
	}
	return vStr(Iso(b))
}

func (p *Planificateur) reponseRfc3161(t int64, data *Value) {
	requestID := ptrChaine(data, "request_id")
	var d *Demande
	if requestID != nil {
		d = p.demandes[*requestID]
	}
	attempt := ptrEntier(data, "attempt")
	var att *Tentative
	if d != nil && attempt != nil {
		for _, a := range d.Attempts {
			if a.N == *attempt {
				att = a
				break
			}
		}
	}
	pki := ptrEntier(data, "pki_status")
	tokenSHA := ptrChaine(data, "token_sha256")
	// EX-8.5, règle 2 (complément du 2026-11-16) : « Une réponse de status 2 à
	// 5 ne porte jamais de jeton » : seul un status 0 ou 1 avec token_sha256.
	jeton := pki != nil && (*pki == 0 || *pki == 1) && tokenSHA != nil
	tokenSize := ptrEntier(data, "token_size")
	// 8.5, règle 2 (complément du 2026-11-16) : « demande_inconnue quand la
	// file n'a aucune demande de cet id de la sorte attendue (rien n'est
	// gardé) » ; la ligne porte attempt (le rang de l'entrée), provider nul,
	// kept faux, et pas d'attempt_id.
	if d == nil || !prefixe(d.Kind, "jeton_") {
		p.journaliser(t, requestID, vObj("event", vStr("anchor_response_rejected"), "error_code", vStr("demande_inconnue"), "attempt", vIntOuNul(attempt), "provider", vNull(), "kept", vBool(false)))
		return
	}
	// EX-8.5, règle 7 (révision 0.6) : rang connu (1 à attempts_total) d'une
	// tentative que la ligne ne porte plus ; traitée comme une tentative close.
	horsFenetre := att == nil && attempt != nil && *attempt >= 1 && *attempt <= d.Total()
	if att == nil && !horsFenetre {
		// EX-8.5, règle 1 (complément du 2026-11-16) : « de même pour une
		// réponse RFC 3161 d'un rang que la demande n'a jamais ouvert (au-delà
		// d'attempts_total) : jeton gardé comme pièce (action stocker, borne
		// nulle), jamais promu, ligne anchor_response_rejected de code
		// tentative_inconnue ».
		if jeton {
			p.emettre(t, "stocker", &d.ID, vObj("sha256", vStr(*tokenSHA), "size", vIntOuNul(tokenSize), "bound", vNull()))
		}
		p.journaliser(t, &d.ID, vObj("event", vStr("anchor_response_rejected"), "error_code", vStr("tentative_inconnue"), "attempt", vIntOuNul(attempt), "attempt_id", vNull(), "provider", vNull(), "kept", vBool(jeton)))
		return
	}
	if EtatsFinaux[d.State] || horsFenetre || att.Outcome != "en_cours" {
		if jeton {
			var nonce *string
			if att != nil {
				nonce = att.Nonce
			} else if n, ok := p.int(d.ID).noncesSortis[*attempt]; ok {
				nonce = &n
			}
			p.emettre(t, "stocker", &d.ID, vObj("sha256", vStrOuNul(tokenSHA), "size", vIntOuNul(tokenSize), "bound", borneDePiece(data, nonce)))
		}
		code := "tentative_close"
		if EtatsFinaux[d.State] {
			code = "demande_close"
		}
		var fournisseur *string
		if att != nil {
			fournisseur = att.Provider
		}
		ligne := avecRang(vObj("event", vStr("anchor_response_rejected"), "error_code", vStr(code)), d, *attempt)
		ligne.Obj = append(ligne.Obj, Member{Key: "provider", Val: vStrOuNul(fournisseur)}, Member{Key: "kept", Val: vBool(jeton)})
		p.journaliser(t, &d.ID, ligne)
		return
	}
	s := p.int(d.ID)
	prID := ""
	if att.Provider != nil {
		prID = *att.Provider
	}
	pr := p.prestataires[prID]
	if pr == nil {
		panic(refus("", "tentative %s sans prestataire connu", att.CorrelationID))
	}
	r := p.classer(d, att, data, t)
	att.HTTPStatus = ptrEntier(data, "http_status")
	att.PKIStatus = pki
	att.FailureInfo = ptrChaine(data, "failure_info")
	// Valeur lue, plafonnée à la borne de $defs/tentative (604 800 s, EX-8.9).
	att.RetryAfterS = ptrEntier(data, "retry_after_s")
	if att.RetryAfterS != nil && *att.RetryAfterS > RetryAfterMaxS {
		att.RetryAfterS = ptrI(RetryAfterMaxS)
	}
	att.ErrorCode = r.code
	att.Detail = r.detail
	delete(s.enCours, pr.ID)
	// EX-8.9 (complément du 2026-11-16) : « une tentative obtenue ou en échec
	// permanent chez ce prestataire interrompt aussi la série, en cours de
	// marche comme à la relecture, et seule une echec_transitoire ou une
	// reponse_tardive la prolonge ».
	if r.issue == "obtenue" || r.issue == "echec_permanente" {
		s.k[pr.ID] = 0
	}
	if r.issue == "obtenue" {
		if tokenSHA == nil || tokenSize == nil {
			panic(refus("", "reponse_rfc3161 : token_sha256 et token_size attendus pour un jeton accepté"))
		}
		att.Outcome = "obtenue"
		s.tardives = 0
		d.Result = &Resultat{SHA256: *tokenSHA, Size: *tokenSize, Provider: ptrS(pr.ID), ObtainedAt: Iso(t), Bound: ptrS(Iso(*r.bound))}
		d.DueAt = nil
		p.emettre(t, "stocker", &d.ID, vObj("sha256", vStr(*tokenSHA), "size", vInt(*tokenSize), "bound", vStr(Iso(*r.bound))))
		p.ecrire(d, t, "obtenue")
		p.satisfaire(d, t, pr, r)
		return
	}
	if r.piece && jeton {
		var bound *Value = vNull()
		if r.bound != nil {
			bound = vStr(Iso(*r.bound))
		}
		p.emettre(t, "stocker", &d.ID, vObj("sha256", vStrOuNul(tokenSHA), "size", vIntOuNul(tokenSize), "bound", bound))
	}
	classe := "transitoire"
	if r.issue == "echec_permanente" {
		classe = "permanente"
	}
	att.Outcome = r.issue
	p.emettre(t, "rejeter_reponse", &d.ID, vObj("error_code", vStrOuNul(r.code), "class", vStr(classe)))
	rejet := avecRang(vObj("event", vStr("anchor_response_rejected"), "error_code", vStrOuNul(r.code)), d, att.N)
	rejet.Obj = append(rejet.Obj, Member{Key: "provider", Val: vStr(pr.ID)})
	p.journaliser(t, &d.ID, rejet)
	if r.critique {
		p.alerter(t, &d.ID, "revoque", "critique")
	}
	if classe == "transitoire" {
		if r.issue == "reponse_tardive" {
			s.tardives++
		}
		delai, raison := p.attenteReprise(d, pr.ID, data)
		next := t + delai
		att.NextAt = ptrS(Iso(next))
		s.reprises[pr.ID] = next
		if len(s.enCours) == 0 {
			d.DueAt = ptrS(Iso(next))
			p.ecrire(d, t, "a_reprendre")
		} else {
			p.ecrire(d, t, "envoyee")
		}
		p.programmer(d, t, next, raison)
		p.timer(next, "reprise", d.ID, 0, pr.ID)
		return
	}
	// permanente : relève ou refus (EX-5.12, EX-8.8)
	s.epuises[pr.ID] = true
	delete(s.reprises, pr.ID)
	secours := p.roles["secours"]
	if p.releveAdmise(d) && !s.engages[secours.ID] && !s.epuises[secours.ID] {
		if len(s.enCours) > 0 {
			p.ecrire(d, t, "envoyee")
		} else {
			p.ecrire(d, t, "a_envoyer")
		}
		p.relever(d, t, *r.code)
		return
	}
	if len(s.enCours) > 0 || len(s.reprises) > 0 {
		if len(s.enCours) > 0 {
			p.ecrire(d, t, "envoyee")
		} else {
			p.ecrire(d, t, "a_reprendre")
		}
		return
	}
	if d.Kind == "jeton_point" {
		d.DueAt = nil
		p.ecrire(d, t, "refusee")
		p.alerter(t, &d.ID, "prestataires_epuises", "majeure")
		p.journaliser(t, &d.ID, vObj("event", vStr("anchor_refused"), "error_code", vStrOuNul(r.code), "provider", vStr(pr.ID)))
		p.rendreEcheances(d)
		return
	}
	// jeton_periode : jamais abandonné (EX-4.5, EX-5.7)
	if !s.alertes["prestataires_epuises"] {
		s.alertes["prestataires_epuises"] = true
		p.alerter(t, &d.ID, "prestataires_epuises", "critique")
	}
	suivant := p.roles["principal"]
	if secours != nil && pr.ID == p.roles["principal"].ID {
		suivant = secours
	}
	next := t + int64(p.cfg.Retry.MaxMs)
	att.NextAt = ptrS(Iso(next))
	delete(s.epuises, suivant.ID)
	s.reprises[suivant.ID] = next
	d.DueAt = ptrS(Iso(next))
	p.ecrire(d, t, "a_reprendre")
	p.programmer(d, t, next, "backoff")
	p.timer(next, "reprise", d.ID, 0, suivant.ID)
}

// attenteReprise applique EX-8.9 à une demande ; prID vaut "" pour une
// soumission OpenTimestamps.
func (p *Planificateur) attenteReprise(d *Demande, prID string, data *Value) (int64, string) {
	s := p.int(d.ID)
	k := s.k[prID] + 1
	s.k[prID] = k
	httpStatus := ptrEntier(data, "http_status")
	retryAfter := ptrEntier(data, "retry_after_s")
	immediat := httpStatus != nil && *httpStatus == 408 && !s.premier408[prID]
	if immediat {
		s.premier408[prID] = true
	}
	avecRetryAfter := httpStatus != nil && (*httpStatus == 429 || *httpStatus == 503) && retryAfter != nil
	var gigue int64
	if !immediat && !avecRetryAfter {
		gigue = p.aleatoire.Gigue()
	}
	delai, raison := CalculerAttente(httpStatus, retryAfter, k, !immediat, p.cfg.Retry, gigue)
	return int64(delai), raison
}

// satisfaire : jeton promu, échéances satisfaites, journal, EX-4.4 sur les
// demandes antérieures de la période.
// instantAdmission rend l'instant d'admission du point d'une demande
// jeton_point (EX-3.5, révision 0.6) : celui de l'entrée qui l'a admis dans ce
// rejeu ; pour un point admis avant le démarrage, dont les demandes viennent de
// la file, la plus ancienne création de ses demandes (créées à l'admission).
func (p *Planificateur) instantAdmission(d *Demande) int64 {
	if v, ok := p.admissions[d.Subject.Hash]; ok {
		return v
	}
	m, err := Ms(d.CreatedAt)
	if err != nil {
		panic(refus("", "%s", err.Error()))
	}
	for _, kind := range []string{"ancre_registre_point", "jeton_point", "ots_point"} {
		if x := p.demandes[idDemande(kind, d.Subject.Hash)]; x != nil {
			if v, err := Ms(x.CreatedAt); err == nil && v < m {
				m = v
			}
		}
	}
	return m
}

// premierEnvoi rend l'instant du premier envoi d'un jeton (EX-3.5) : la
// tentative de rang 1 si la ligne la porte encore, sinon l'instant retenu dans
// ce rejeu, sinon la plus ancienne tentative portée.
func (p *Planificateur) premierEnvoi(d *Demande) int64 {
	for _, a := range d.Attempts {
		if a.N == 1 {
			v, err := Ms(a.StartedAt)
			if err != nil {
				panic(refus("", "%s", err.Error()))
			}
			return v
		}
	}
	if s := p.int(d.ID); s.premierEnvoi != nil {
		return *s.premierEnvoi
	}
	v, err := Ms(d.Attempts[0].StartedAt)
	if err != nil {
		panic(refus("", "%s", err.Error()))
	}
	return v
}

func (p *Planificateur) satisfaire(d *Demande, t int64, pr *Prestataire, r *classement) {
	per := p.periode(d.Subject, t, false, false)
	var kmax int64
	avert := func(o *Value) *Value {
		if len(r.avertissements) > 0 {
			o.Obj = append(o.Obj, Member{Key: "warnings", Val: vChaines(r.avertissements)})
		}
		return o
	}
	if d.Kind == "jeton_point" {
		for _, k := range d.Deadlines {
			per.get(k).state = "satisfaite"
			p.emettre(t, "echeance", &d.ID, vObj("k", vInt(k), "state", vStr("satisfaite")))
			if k > kmax {
				kmax = k
			}
		}
		// repli de la clôture (EX-4.2) : aucune échéance, délais comptés depuis la fin de la période
		repli := len(d.Deadlines) == 0
		reference := p.D(per, kmax)
		if repli {
			kmax = p.nT
			reference = p.finPeriode(per)
		}
		tsPoint, err := Ms(d.Subject.DeclaredAt)
		if err != nil {
			panic(refus("", "%s", err.Error()))
		}
		// EX-3.5 et 8.9 (révision 0.6) : cinq composantes de d_jeton,
		// différences successives des instants tronqués à la seconde depuis la
		// référence (point, admission, premier envoi, envoi de la tentative
		// promue, borne du jeton).
		var promue *Tentative
		for _, a := range d.Attempts {
			if a.Outcome == "obtenue" {
				promue = a
				break
			}
		}
		if promue == nil {
			panic(refus("", "jeton promu sans tentative obtenue"))
		}
		premier := p.premierEnvoi(d)
		admission := p.instantAdmission(d)
		envoiPromu, err := Ms(promue.StartedAt)
		if err != nil {
			panic(refus("", "%s", err.Error()))
		}
		s1, sA, s2, s3, s4 := (tsPoint-reference)/1000, (admission-reference)/1000, (premier-reference)/1000, (envoiPromu-reference)/1000, (*r.bound-reference)/1000
		ligne := vObj("event", vStr("checkpoint_countersigned"), "tree_size", vIntOuNul(d.Subject.TreeSize), "provider", vStr(pr.ID), "deadlines", vEntiers(d.Deadlines), "d_jeton_s", vInt(s4), "d_point_s", vInt(s1), "d_admission_s", vInt(sA-s1), "d_attente_s", vInt(s2-sA), "d_releve_s", vInt(s3-s2), "d_tsa_s", vInt(s4-s3))
		if repli {
			ligne.Obj = append(ligne.Obj, Member{Key: "closing_fallback", Val: vBool(true)})
		}
		p.journaliser(t, &d.ID, avert(ligne))
	} else {
		kmax = p.nT
		p.emettre(t, "echeance", &d.ID, vObj("k", vInt(p.nT), "state", vStr("satisfaite")))
		p.journaliser(t, &d.ID, avert(vObj("event", vStr("period_timestamped"), "provider", vStr(pr.ID), "d_jeton_s", vInt((*r.bound-p.finPeriode(per))/1000))))
	}
	for _, a := range r.avertissements {
		if a == "horloge_suspecte" {
			p.alerter(t, &d.ID, "horloge_suspecte", "mineure")
		}
	}
	// EX-5.11 : la troisième réponse tardive est promue avec une alerte
	for _, a := range r.avertissements {
		if a == "reponse_tardive" {
			p.alerter(t, &d.ID, "reponse_tardive_promue", "mineure")
		}
	}
	if d.Kind == "jeton_point" {
		// AN-2 : jeton antérieur au point déclaré, ou contresignature plus de c_T après lui
		tsPoint, _ := Ms(d.Subject.DeclaredAt)
		if *r.bound < tsPoint-p.cfg.Fraicheur.ClockToleranceS*1000 {
			p.alerter(t, &d.ID, "jeton_anterieur_au_point", "majeure")
		}
		if *r.bound-tsPoint > p.cfg.CheckpointsIntervalS*1000 {
			p.alerter(t, &d.ID, "contresignature_tardive", "mineure")
		}
	}
	p.appliquerPromotion(d, t, per, kmax, *r.bound)
}

// appliquerPromotion applique EX-4.4 après la promotion du jeton de d (ou sa
// recréation obtenue, EX-8.12) : les demandes non finales qui servent une
// échéance ouverte inférieure à kmax sont closes remplacee, une échéance
// ouverte sans demande passe remplacee, et le jeton de clôture rend sans objet
// un repli de clôture encore en cours (EX-4.2). borne est genTime plus la
// précision du jeton (window_s).
func (p *Planificateur) appliquerPromotion(d *Demande, t int64, per *periode, kmax, borne int64) {
	severite := "majeure"
	if p.cfg.ProviderRole == "interne" {
		severite = "mineure"
	}
	remplacees := map[string]bool{}
	for _, k := range per.ordre {
		e := per.echeances[k]
		if k >= kmax || e.state != "ouverte" {
			continue
		}
		var r2 *Demande
		if e.demande != nil {
			r2 = p.demandes[*e.demande]
		}
		if r2 != nil && !EtatsFinaux[r2.State] && !remplacees[r2.ID] {
			remplacees[r2.ID] = true
			r2.ReplacedBy = ptrS(d.ID)
			r2.DueAt = nil
			p.emettre(t, "remplacer", &r2.ID, vObj("replaced_by", vStr(d.ID)))
			p.ecrire(r2, t, "remplacee")
			kmin := r2.Deadlines[0]
			for _, k2 := range r2.Deadlines {
				per.get(k2).state = "remplacee"
				p.emettre(t, "echeance", &r2.ID, vObj("k", vInt(k2), "state", vStr("remplacee")))
				if k2 < kmin {
					kmin = k2
				}
			}
			p.journaliser(t, &r2.ID, vObj("event", vStr("checkpoint_anchor_late"), "tree_size", vIntOuNul(r2.Subject.TreeSize), "deadlines", vEntiers(r2.Deadlines), "replaced_by", vStr(d.ID), "window_s", vInt((borne-p.D(per, kmin))/1000)))
			p.alerter(t, &r2.ID, "checkpoint_anchor_late", severite)
		} else if r2 == nil || EtatsFinaux[r2.State] {
			e.state = "remplacee"
			var id *string
			if r2 != nil {
				id = &r2.ID
			}
			p.emettre(t, "echeance", id, vObj("k", vInt(k), "state", vStr("remplacee")))
		}
	}
	// le jeton de clôture rend sans objet un repli de clôture encore en cours (EX-4.2)
	if d.Kind == "jeton_periode" {
		for _, r2 := range p.File() {
			if r2.Kind != "jeton_point" || len(r2.Deadlines) != 0 || EtatsFinaux[r2.State] || cle(r2.Subject) != cle(d.Subject) {
				continue
			}
			r2.ReplacedBy = ptrS(d.ID)
			r2.DueAt = nil
			p.emettre(t, "remplacer", &r2.ID, vObj("replaced_by", vStr(d.ID)))
			p.ecrire(r2, t, "remplacee")
			p.journaliser(t, &r2.ID, vObj("event", vStr("anchor_replaced"), "replaced_by", vStr(d.ID)))
		}
	}
}

// --- réponses OpenTimestamps (EX-8.11) ------------------------------------------

func (p *Planificateur) reponseOts(t int64, data *Value) {
	requestID := ptrChaine(data, "request_id")
	var d *Demande
	if requestID != nil {
		d = p.demandes[*requestID]
	}
	preuve := ptrChaine(data, "proof_sha256")
	// EX-8.5, règle 2 (complément du 2026-11-16) : « Une réponse qui ne
	// s'applique pas est consignée anchor_response_rejected : demande_inconnue
	// quand la file n'a aucune demande de cet id de la sorte attendue (rien
	// n'est gardé), [...] tentative_close quand la tentative désignée n'est plus
	// en cours, demande_close quand la demande est dans un état final ; la
	// ligne porte attempt (pour une réponse des calendriers, la dernière
	// tentative de la demande, attempts_total, et nul pour une demande
	// inconnue), attempt_id (celui de ce rang quand la demande l'a ouvert, nul
	// sinon ; absent pour une demande inconnue), provider (nul pour les
	// calendriers) et kept (la réponse portait [...] une preuve) ».
	if d == nil || !prefixe(d.Kind, "ots_") {
		p.journaliser(t, requestID, vObj("event", vStr("anchor_response_rejected"), "error_code", vStr("demande_inconnue"), "attempt", vNull(), "provider", vNull(), "kept", vBool(false)))
		return
	}
	var att *Tentative
	for _, a := range d.Attempts {
		if att == nil || a.N > att.N {
			att = a
		}
	}
	if EtatsFinaux[d.State] || att == nil || att.Outcome != "en_cours" {
		code := "tentative_close"
		if EtatsFinaux[d.State] {
			code = "demande_close"
		}
		total := d.Total()
		var attemptID *Value = vNull()
		if total > 0 {
			attemptID = vStr(IdentifiantCorrelation(d.Kind, d.Subject.Hash, total))
		}
		p.journaliser(t, &d.ID, vObj("event", vStr("anchor_response_rejected"), "error_code", vStr(code), "attempt", vInt(total), "attempt_id", attemptID, "provider", vNull(), "kept", vBool(preuve != nil)))
		return
	}
	s := p.int(d.ID)
	delete(s.enCours, "")
	n := entierOu(data, 0, "calendars_answered")
	attestation := chaineOu(data, "", "attestation")
	stocker := func() {
		sha := chaineOu(data, "", "proof_sha256")
		size := entierOu(data, 0, "proof_size")
		d.Result = &Resultat{SHA256: sha, Size: size, ObtainedAt: Iso(t)}
		p.emettre(t, "stocker", &d.ID, vObj("sha256", vStr(sha), "size", vInt(size), "bound", vNull()))
	}
	if d.State == "envoyee" || d.State == "a_reprendre" {
		// EX-8.11 (complément du 2026-11-16) : « avec moins de min_responses
		// réponses valables, quelle que soit l'attestation [...], la tentative est
		// close echec_transitoire, code reponses_insuffisantes [...] : action
		// rejeter_reponse (error_code reponses_insuffisantes, classe
		// transitoire), ligne anchor_response_rejected (error_code, rang attempt
		// et attempt_id de la tentative, provider nul ; 8.9), puis la demande
		// passe a_reprendre, due_at à l'attente d'EX-8.9 (k : la série de la
		// soumission, gigue comprise), action programmer de raison backoff » ;
		// « une réponse sans preuve écrite (proof_sha256 nul) n'est jamais
		// promue. À la soumission, avec au moins min_responses réponses valables
		// et une attestation en_attente ou complete, la tentative est close de
		// même, code preuve_absente, détail <n> calendriers ; aucune preuve
		// ecrite (rejet, ligne et attente identiques ; la série d'EX-8.9 la
		// compte) ».
		code, detail := "", ""
		if attestation == "aucune" || n < p.cfg.MinResponses {
			code, detail = "reponses_insuffisantes", fmt.Sprintf("%d calendrier(s) ; moins de %d reponses valables", n, p.cfg.MinResponses)
		} else if preuve == nil {
			code, detail = "preuve_absente", fmt.Sprintf("%d calendriers ; aucune preuve ecrite", n)
		}
		if code != "" {
			att.Outcome = "echec_transitoire"
			att.ErrorCode = ptrS(code)
			att.Detail = detail
			p.emettre(t, "rejeter_reponse", &d.ID, vObj("error_code", vStr(code), "class", vStr("transitoire")))
			ligne := avecRang(vObj("event", vStr("anchor_response_rejected"), "error_code", vStr(code)), d, att.N)
			ligne.Obj = append(ligne.Obj, Member{Key: "provider", Val: vNull()})
			p.journaliser(t, &d.ID, ligne)
			delai, raison := p.attenteReprise(d, "", vObj())
			next := t + delai
			att.NextAt = ptrS(Iso(next))
			s.reprises[""] = next
			d.DueAt = ptrS(Iso(next))
			p.ecrire(d, t, "a_reprendre")
			p.programmer(d, t, next, raison)
			p.timer(next, "reprise", d.ID, 0, "")
			return
		}
		att.Outcome = "obtenue"
		s.k[""] = 0 // EX-8.9 : une soumission obtenue clôt la série
		if attestation == "complete" {
			att.Detail = fmt.Sprintf("%d calendriers ; attestation Bitcoin", n)
			stocker()
			d.DueAt = nil
			p.ecrire(d, t, "complete")
			p.journaliser(t, &d.ID, vObj("event", vStr("ots_complete"), "reexport", vBool(true)))
			return
		}
		att.Detail = fmt.Sprintf("%d calendriers ; attestation en attente", n)
		stocker()
		// EX-8.11 (complément du 2026-11-16, soumission aboutie au-delà de
		// l'âge d'abandon) : « Quand une soumission aboutit (passage en_attente,
		// preuve écrite) alors que l'âge de la demande (t − created_at) atteint
		// déjà upgrade.give_up_after_s [...], l'alerte ots_give_up est levée dès
		// ce passage, une fois par demande depuis le dernier démarrage (après
		// l'action stocker, avant l'écriture en_attente) [...] ; cette première
		// mise à niveau reste programmée à now + upgrade.first_after_s ».
		if creation, err := Ms(d.CreatedAt); err == nil && t-creation >= p.cfg.UpgradeGiveUpAfterS*1000 && !s.alertes["ots_give_up"] {
			s.alertes["ots_give_up"] = true
			p.alerter(t, &d.ID, "ots_give_up", "majeure")
		}
		next := t + p.cfg.UpgradeFirstAfterS*1000
		att.NextAt = ptrS(Iso(next))
		p.ecrire(d, t, "en_attente")
		s.miseANiveauAt = ptrI(next)
		p.programmer(d, t, next, "mise_a_niveau")
		p.timer(next, "mise_a_niveau", d.ID, 0, "")
		return
	}
	// en_attente : réponse à une mise à niveau. EX-8.11 (complément du
	// 2026-11-16) : « à la mise à niveau, une attestation Bitcoin sans preuve
	// laisse la preuve en_attente, tentative close echec_transitoire de code
	// en_attente, comme une réponse 404 ».
	if attestation == "complete" && preuve != nil {
		att.Outcome = "obtenue"
		att.Detail = "mise a niveau : attestation Bitcoin"
		stocker()
		d.DueAt = nil
		p.ecrire(d, t, "complete")
		p.journaliser(t, &d.ID, vObj("event", vStr("ots_complete"), "reexport", vBool(true)))
		return
	}
	att.Outcome = "echec_transitoire"
	att.ErrorCode = ptrS("en_attente")
	att.Detail = "mise a niveau : engagement en attente"
	intervalle := p.cfg.UpgradeIntervalS
	if intervalle < 60 {
		intervalle = 60
	}
	intervalle *= 1000
	// EX-8.11 (complément du 2026-11-16, origine de l'âge d'abandon) : « Cet
	// âge court depuis created_at de la demande, écrit à sa création, porté
	// par chaque ligne et jamais réécrit, au démarrage comme en marche
	// (EX-8.12) ».
	debut, err := Ms(d.CreatedAt)
	if err != nil {
		panic(refus("", "%s", err.Error()))
	}
	if t-debut >= p.cfg.UpgradeGiveUpAfterS*1000 {
		if !s.alertes["ots_give_up"] {
			s.alertes["ots_give_up"] = true
			p.alerter(t, &d.ID, "ots_give_up", "majeure")
		}
		intervalle = 86400 * 1000
	}
	next := t + intervalle
	att.NextAt = ptrS(Iso(next))
	p.ecrire(d, t, "en_attente")
	s.miseANiveauAt = ptrI(next)
	p.programmer(d, t, next, "mise_a_niveau")
	p.timer(next, "mise_a_niveau", d.ID, 0, "")
}

// --- rejeu d'une trace (EX-8.16) ------------------------------------------------------

// Rejeu est le résultat du rejeu d'une trace : les actions, la file finale,
// les lignes écrites dans la file et leur rattachement aux actions.
type Rejeu struct {
	Actions   []*Value
	File      []*Demande
	Lignes    []string
	Ecritures []Ecriture
}

// RejouerTrace rejoue une trace normative (racine du schéma
// planificateur-ancrage-v0) depuis une file de départ donnée (nil : celle de
// la trace) ; rend les actions et la file finale, ou l'erreur du planificateur.
func RejouerTrace(trace *Value, fileDepart []*Demande) (r *Rejeu, err error) {
	defer func() {
		if x := recover(); x != nil {
			if e, ok := x.(error); ok {
				err = e
				return
			}
			panic(x)
		}
	}()
	gigues := entiersDe(trace, "jitter_ms")
	p, err := NouveauPlanificateur(trace.Get("config"), &AleatoireVecteurs{Gigues: gigues})
	if err != nil {
		return nil, err
	}
	if fileDepart == nil {
		if qb := trace.Get("queue_before"); qb != nil && qb.Kind == KindArray {
			for _, v := range qb.Arr {
				d, err := DemandeDe(v)
				if err != nil {
					return nil, refus("", "queue_before : %s", err.Error())
				}
				fileDepart = append(fileDepart, d)
			}
		}
	}
	p.Charger(fileDepart)
	if in := trace.Get("inputs"); in != nil && in.Kind == KindArray {
		for _, e := range in.Arr {
			p.Recevoir(e)
		}
	}
	return &Rejeu{Actions: p.Actions, File: p.File(), Lignes: p.Lignes, Ecritures: p.Ecritures}, nil
}
