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
	soumisA       *int64
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
}

func sortePeriode(kind string) bool      { return len(kind) > 8 && kind[len(kind)-8:] == "_periode" }
func prefixe(kind, p string) bool        { return len(kind) >= len(p) && kind[:len(p)] == p }
func idDemande(kind, hash string) string { return kind + ":" + hash }

// NouveauPlanificateur construit le planificateur d'une configuration
// (document ancrage-v0 ou projection) ; refuse une configuration hors d'AN-1.
func NouveauPlanificateur(config *Value, aleatoire Aleatoire) (*Planificateur, error) {
	cfg := ProjeterConfiguration(config)
	p := &Planificateur{cfg: cfg, prestataires: map[string]*Prestataire{}, roles: map[string]*Prestataire{}, aleatoire: aleatoire, demandes: map[string]*Demande{}, interne: map[string]*etatInterne{}, periodes: map[string]*periode{}, Actions: []*Value{}, Lignes: []string{}, dernierEnvoi: map[string]int64{}}
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
		s = &etatInterne{enCours: map[string]int64{}, engages: map[string]bool{}, epuises: map[string]bool{}, reprises: map[string]int64{}, k: map[string]int64{}, premier408: map[string]bool{}, alertes: map[string]bool{}}
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
	p.emettre(t, "ecrire_file", &d.ID, vObj("state", vStr(state)))
	ligne := LigneFile(d)
	p.Lignes = append(p.Lignes, ligne)
	p.Ecritures = append(p.Ecritures, Ecriture{Action: len(p.Actions) - 1, Ligne: ligne})
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

func (p *Planificateur) trierTimers() {
	sort.SliceStable(p.timers, func(i, j int) bool {
		if p.timers[i].at != p.timers[j].at {
			return p.timers[i].at < p.timers[j].at
		}
		return p.timers[i].seq < p.timers[j].seq
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
		p.examinerAttenteRegistre(d, t)
	case "reprise":
		if d == nil || EtatsFinaux[d.State] {
			return
		}
		s := p.int(d.ID)
		if at, ok := s.reprises[m.provider]; !ok || at != t {
			return
		}
		delete(s.reprises, m.provider)
		if prefixe(d.Kind, "ots_") {
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
		n := int64(len(d.Attempts)) + 1
		d.Attempts = append(d.Attempts, p.tentative(d, n, nil, t, nil, "mise a niveau demandee"))
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
		p.alerter(t, &d.ID, "inclusion_late", sev)
		p.cloreTentativeRegistre(d, t, "recu_absent", "")
		n := int64(len(d.Attempts)) + 1
		d.Attempts = append(d.Attempts, p.tentative(d, n, nil, t, nil, detail))
		p.ecrire(d, t, "envoyee")
		p.emettre(t, "envoyer_registre", &d.ID, p.detailRegistre(d))
		s.inclusionAt = ptrI(t + p.cfg.InclusionAlertS*1000)
		p.timer(*s.inclusionAt, "inclusion", d.ID, 0, "")
	case "repli_cloture":
		if d == nil || d.State != "attente_registre" {
			return
		}
		ancre := p.demandes[idDemande("ancre_registre_periode", d.Subject.Hash)]
		if ancre == nil || ancre.State == "obtenue" || ancre.State == "refusee" {
			return
		}
		p.repliCloture(d, t)
	case "cadence":
		// EX-8.15 : aucun point admis pendant 2 × c_K (alerte point_manquant).
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
	p.avancer(t)
	data := entree.Get("data")
	switch typ {
	case "demarrage":
		p.demarrer(t)
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
		p.reconstruire(t, data)
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
	}
	p.relues = int64(len(p.demandes))
}

func (p *Planificateur) demarrer(t int64) {
	p.demarre = true
	p.journaliser(t, nil, vObj("event", vStr("anchoring_started"), "queue_entries", vInt(p.relues)))
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
			if d.State == "envoyee" {
				p.journaliser(t, &d.ID, vObj("event", vStr("anchor_retry"), "kind", vStr(d.Kind), "mode", vStr("renvoi")))
				p.emettre(t, "envoyer_registre", &d.ID, p.detailRegistre(d))
				s.inclusionAt = ptrI(t + p.cfg.InclusionAlertS*1000)
				p.timer(*s.inclusionAt, "inclusion", d.ID, 0, "")
			} else if d.State == "a_envoyer" {
				p.programmer(d, t, t, "attente_nonce")
			}
			continue
		}
		dueOuT := func() int64 {
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
		if prefixe(d.Kind, "ots_") {
			switch d.State {
			case "envoyee":
				p.perdreTentatives(d, t)
				d.DueAt = ptrS(Iso(t))
				p.ecrire(d, t, "a_reprendre")
				p.programmer(d, t, t, "immediat")
				s.reprises[""] = t
				p.timer(t, "reprise", d.ID, 0, "")
			case "a_reprendre":
				at := dueOuT()
				s.reprises[""] = at
				p.timer(at, "reprise", d.ID, 0, "")
			case "en_attente":
				at := dueOuT()
				debut := d.CreatedAt
				if len(d.Attempts) > 0 {
					debut = d.Attempts[0].StartedAt
				}
				v, err := Ms(debut)
				if err != nil {
					panic(refus("", "%s", err.Error()))
				}
				s.soumisA = ptrI(v)
				s.miseANiveauAt = ptrI(at)
				p.programmer(d, t, at, "mise_a_niveau")
				p.timer(at, "mise_a_niveau", d.ID, 0, "")
			}
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
			at := dueOuT()
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
	d := &Demande{Version: 0, ID: id, Kind: kind, Subject: &copieSujet, Deadlines: append([]int64{}, deadlines...), State: "a_envoyer", CreatedAt: Iso(t), Attempts: []*Tentative{}}
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
func (p *Planificateur) cleOccupee() bool {
	for _, d := range p.demandes {
		if prefixe(d.Kind, "ancre_registre_") && d.State == "envoyee" {
			return true
		}
	}
	return false
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
	// cadence (EX-8.15) : dernier point admis de la période ouverte, armé à 2 × c_K
	if !per.close {
		copie := *sujet
		per.dernierPoint = &copie
		per.dernierPointAt = ptrI(t)
		p.timer(t+2*p.cfg.CheckpointIntervalS*1000, "cadence", cle(sujet), t, "")
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
		for _, autre := range p.File() {
			if autre == ancre || autre.Kind != "ancre_registre_point" || autre.State != "a_envoyer" || cle(autre.Subject) != cle(sujet) {
				continue
			}
			autre.ReplacedBy = ptrS(ancre.ID)
			autre.DueAt = nil
			p.emettre(t, "remplacer", &autre.ID, vObj("replaced_by", vStr(ancre.ID)))
			p.ecrire(autre, t, "remplacee")
			p.journaliser(t, &autre.ID, vObj("event", vStr("anchor_replaced"), "replaced_by", vStr(ancre.ID)))
		}
		if p.cleOccupee() {
			p.programmer(ancre, t, t, "attente_nonce")
		} else {
			p.envoyerRegistre(ancre, t)
		}
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
			if ancre != nil && ancre.State != "obtenue" {
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
	if j != nil {
		p.ecrire(j, t, "attente_registre")
	}
	if o != nil {
		p.ecrire(o, t, "a_envoyer")
	}
	if a != nil {
		if p.cleOccupee() {
			p.programmer(a, t, t, "attente_nonce")
		} else {
			p.envoyerRegistre(a, t)
		}
	}
	if j != nil {
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
func (p *Planificateur) reconstruire(t int64, data *Value) {
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
	// 2. registre : une transaction par clé de chaîne (EX-9.4), la période d'abord (EX-8.7)
	if !p.cleOccupee() {
		var candidats []*Demande
		for _, d := range p.File() {
			if prefixe(d.Kind, "ancre_registre_") && d.State == "a_envoyer" {
				candidats = append(candidats, d)
			}
		}
		sort.SliceStable(candidats, func(i, j int) bool { return sortePeriode(candidats[i].Kind) && !sortePeriode(candidats[j].Kind) })
		if len(candidats) > 0 {
			p.envoyerRegistre(candidats[0], t)
		}
	}
	// 3. soumissions OpenTimestamps en attente d'envoi
	for _, d := range p.File() {
		if prefixe(d.Kind, "ots_") && d.State == "a_envoyer" {
			p.soumettreOts(d, t)
		}
	}
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
	n := int64(len(d.Attempts)) + 1
	nonce := p.aleatoire.NonceTsa(d.Subject, n)
	requete, err := ConstruireRequete(d.Subject.Hash, nonce, pr.PolicyOID, true)
	if err != nil {
		panic(err)
	}
	d.Attempts = append(d.Attempts, p.tentative(d, n, ptrS(pr.ID), t, ptrS(HexNonce(nonce)), "requete envoyee"))
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
	n := int64(len(d.Attempts)) + 1
	d.Attempts = append(d.Attempts, p.tentative(d, n, nil, t, nil, "transaction envoyee"))
	d.DueAt = nil
	p.ecrire(d, t, "envoyee")
	p.emettre(t, "envoyer_registre", &d.ID, p.detailRegistre(d))
	s.inclusionAt = ptrI(t + p.cfg.InclusionAlertS*1000)
	p.timer(*s.inclusionAt, "inclusion", d.ID, 0, "")
}

func (p *Planificateur) soumettreOts(d *Demande, t int64) {
	s := p.int(d.ID)
	n := int64(len(d.Attempts)) + 1
	nonce := p.aleatoire.NonceOts(d.Subject)
	cals := p.cfg.Calendars
	d.Attempts = append(d.Attempts, p.tentative(d, n, nil, t, nil, fmt.Sprintf("soumission a %d calendriers", len(cals))))
	d.DueAt = nil
	p.ecrire(d, t, "envoyee")
	p.emettre(t, "soumettre_ots", &d.ID, vObj("digest", vStr(d.Subject.Hash), "nonce", vStr("0x"+hex.EncodeToString(nonce)), "calendars", vChaines(cals)))
	s.enCours[""] = n
	if s.soumisA == nil {
		s.soumisA = ptrI(t)
	}
}

func (p *Planificateur) relever(d *Demande, t int64, cause string) {
	secours := p.roles["secours"]
	p.emettre(t, "releve", &d.ID, vObj("provider", vStr(secours.ID)))
	p.journaliser(t, &d.ID, vObj("event", vStr("anchor_fallback"), "to", vStr(secours.ID), "reason", vStr(cause)))
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

func (p *Planificateur) ignoree(t int64, data *Value, d *Demande) {
	raison := "demande_inconnue"
	if d != nil {
		raison = "etat " + d.State
	}
	p.journaliser(t, ptrChaine(data, "request_id"), vObj("event", vStr("anchor_duplicate_ignored"), "reason", vStr(raison)))
}

func (p *Planificateur) inclusionRegistre(t int64, data *Value) {
	d := p.demandes[chaineOu(data, "", "request_id")]
	if d == nil || !prefixe(d.Kind, "ancre_registre_") || EtatsFinaux[d.State] || d.State == "a_envoyer" {
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
	p.emettre(t, "stocker", &d.ID, vObj("sha256", vStr(capture), "size", vInt(TailleIndexCapture), "bound", vNull()))
	p.ecrire(d, t, "obtenue")
	envoi, err := Ms(d.Attempts[0].StartedAt)
	if err != nil {
		panic(refus("", "%s", err.Error()))
	}
	if t-envoi > p.cfg.InclusionAlertS*1000 && s.renvois == 0 {
		p.alerter(t, &d.ID, "inclusion_late", "mineure")
	}
	if j := p.jetonDuSujet(d); j != nil && j.State == "attente_registre" {
		p.pret(j, p.designe(j.Kind))
	}
}

func (p *Planificateur) echecRegistre(t int64, data *Value) {
	d := p.demandes[chaineOu(data, "", "request_id")]
	if d == nil || !prefixe(d.Kind, "ancre_registre_") || EtatsFinaux[d.State] {
		p.ignoree(t, data, d)
		return
	}
	code := chaineOu(data, "", "code")
	var att *Tentative
	if len(d.Attempts) > 0 {
		att = d.Attempts[len(d.Attempts)-1]
	}
	if code == "empreinte_squattee" {
		if att != nil {
			att.Outcome = "echec_permanente"
			att.ErrorCode = ptrS(code)
			att.Detail = "empreinte deja ancree par un tiers"
		}
		d.DueAt = nil
		p.ecrire(d, t, "refusee")
		p.alerter(t, &d.ID, "empreinte_squattee", "critique")
		p.journaliser(t, &d.ID, vObj("event", vStr("anchor_refused"), "error_code", vStr(code)))
		if j := p.jetonDuSujet(d); j != nil && j.State == "attente_registre" {
			p.pret(j, p.designe(j.Kind))
		}
		return
	}
	p.cloreTentativeRegistre(d, t, code, "registre : "+code)
	p.journaliser(t, &d.ID, vObj("event", vStr("anchor_retry"), "kind", vStr(d.Kind), "error_code", vStr(code)))
	n := int64(len(d.Attempts)) + 1
	d.Attempts = append(d.Attempts, p.tentative(d, n, nil, t, nil, "renvoi des memes octets"))
	p.ecrire(d, t, "envoyee")
	p.emettre(t, "envoyer_registre", &d.ID, p.detailRegistre(d))
	s := p.int(d.ID)
	s.inclusionAt = ptrI(t + p.cfg.InclusionAlertS*1000)
	p.timer(*s.inclusionAt, "inclusion", d.ID, 0, "")
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

func (p *Planificateur) examinerAttenteRegistre(d *Demande, t int64) {
	s := p.int(d.ID)
	kind := "ancre_registre_periode"
	if d.Subject.Kind == "point" {
		kind = "ancre_registre_point"
	}
	ancre := p.demandes[idDemande(kind, d.Subject.Hash)]
	if ancre == nil || ancre.State == "obtenue" || ancre.State == "refusee" {
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
	s.attenteAt = ptrI(t + p.cfg.InclusionAlertS*1000)
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
		fi := ptrChaine(data, "failure_info")
		if fi == nil {
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
	bound := genTime + int64(nombreOu(data, 0, "accuracy_s")*1000)
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
	jeton := pki != nil && *pki <= 1 && tokenSHA != nil
	if d == nil || att == nil || !prefixe(d.Kind, "jeton_") {
		p.journaliser(t, requestID, vObj("event", vStr("anchor_response_rejected"), "error_code", vStr("tentative_inconnue"), "attempt", vIntOuNul(attempt)))
		return
	}
	tokenSize := ptrEntier(data, "token_size")
	accuracyMs := int64(nombreOu(data, 0, "accuracy_s") * 1000)
	if EtatsFinaux[d.State] || att.Outcome != "en_cours" {
		if jeton {
			var bound *Value = vNull()
			if g, ok := chaineDe(data, "gen_time"); ok {
				gm, err := Ms(g)
				if err != nil {
					panic(refus("", "%s", err.Error()))
				}
				bound = vStr(Iso(gm + accuracyMs))
			}
			p.emettre(t, "stocker", &d.ID, vObj("sha256", vStrOuNul(tokenSHA), "size", vIntOuNul(tokenSize), "bound", bound))
		}
		code := "tentative_close"
		if EtatsFinaux[d.State] {
			code = "demande_close"
		}
		p.journaliser(t, &d.ID, vObj("event", vStr("anchor_response_rejected"), "error_code", vStr(code), "attempt", vInt(att.N), "provider", vStrOuNul(att.Provider), "kept", vBool(jeton)))
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
	att.RetryAfterS = ptrEntier(data, "retry_after_s")
	att.ErrorCode = r.code
	att.Detail = r.detail
	delete(s.enCours, pr.ID)
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
	p.journaliser(t, &d.ID, vObj("event", vStr("anchor_response_rejected"), "error_code", vStrOuNul(r.code), "attempt", vInt(att.N), "provider", vStr(pr.ID)))
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
		// EX-3.5 et 8.9 : quatre composantes de d_jeton, différences des
		// instants tronqués à la seconde depuis la référence (point, premier
		// envoi, envoi de la tentative promue, borne du jeton).
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
		premier, err := Ms(d.Attempts[0].StartedAt)
		if err != nil {
			panic(refus("", "%s", err.Error()))
		}
		envoiPromu, err := Ms(promue.StartedAt)
		if err != nil {
			panic(refus("", "%s", err.Error()))
		}
		s1, s2, s3, s4 := (tsPoint-reference)/1000, (premier-reference)/1000, (envoiPromu-reference)/1000, (*r.bound-reference)/1000
		ligne := vObj("event", vStr("checkpoint_countersigned"), "tree_size", vIntOuNul(d.Subject.TreeSize), "provider", vStr(pr.ID), "deadlines", vEntiers(d.Deadlines), "d_jeton_s", vInt(s4), "d_point_s", vInt(s1), "d_attente_s", vInt(s2-s1), "d_releve_s", vInt(s3-s2), "d_tsa_s", vInt(s4-s3))
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
			p.journaliser(t, &r2.ID, vObj("event", vStr("checkpoint_anchor_late"), "tree_size", vIntOuNul(r2.Subject.TreeSize), "deadlines", vEntiers(r2.Deadlines), "replaced_by", vStr(d.ID), "window_s", vInt((*r.bound-p.D(per, kmin))/1000)))
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
	if d == nil || !prefixe(d.Kind, "ots_") || EtatsFinaux[d.State] {
		code := "tentative_inconnue"
		if d != nil && EtatsFinaux[d.State] {
			code = "demande_close"
		}
		p.journaliser(t, requestID, vObj("event", vStr("anchor_response_rejected"), "error_code", vStr(code)))
		return
	}
	s := p.int(d.ID)
	var att *Tentative
	for i := len(d.Attempts) - 1; i >= 0; i-- {
		if d.Attempts[i].Outcome == "en_cours" {
			att = d.Attempts[i]
			break
		}
	}
	if att == nil {
		p.journaliser(t, &d.ID, vObj("event", vStr("anchor_response_rejected"), "error_code", vStr("tentative_inconnue")))
		return
	}
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
		if attestation == "aucune" || n < p.cfg.MinResponses {
			att.Outcome = "echec_transitoire"
			att.ErrorCode = ptrS("reponses_insuffisantes")
			att.Detail = fmt.Sprintf("%d calendrier(s) ; moins de %d reponses valables", n, p.cfg.MinResponses)
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
		next := t + p.cfg.UpgradeFirstAfterS*1000
		att.NextAt = ptrS(Iso(next))
		p.ecrire(d, t, "en_attente")
		s.miseANiveauAt = ptrI(next)
		p.programmer(d, t, next, "mise_a_niveau")
		p.timer(next, "mise_a_niveau", d.ID, 0, "")
		return
	}
	// en_attente : réponse à une mise à niveau
	if attestation == "complete" {
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
	debut := s.soumisA
	if debut == nil {
		v, err := Ms(d.CreatedAt)
		if err != nil {
			panic(refus("", "%s", err.Error()))
		}
		debut = &v
	}
	if t-*debut >= p.cfg.UpgradeGiveUpAfterS*1000 {
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
