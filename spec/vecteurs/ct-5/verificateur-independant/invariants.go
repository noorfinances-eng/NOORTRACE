// Invariants d'une trace de planification (CT-5 §8.11 : AN-32 à AN-41 et
// AN-43 ; §9.4 : AN-40, AN-48 ; §11.4 : AN-58), vérifiés sur les actions
// rejouées, les entrées de la trace, la file de départ et la file finale,
// indépendamment de l'égalité action par action d'AN-42. Chaque invariant
// rend la liste de ses écarts ; une liste vide est la valeur attendue.
//
// Les règles sont celles du texte : EX-8.3 (table des transitions), EX-8.4
// (échéances, ordre des ancres), EX-8.5 (écriture avant envoi, une demande
// par id, dernière ligne fait foi), EX-8.7 (priorité, min_interval_ms),
// EX-8.9 (attente de reprise), EX-8.10 (registre), EX-8.11 (OpenTimestamps),
// EX-8.12 (démarrage), EX-9.6, EX-9.7 et l'annexe A.2 (formes représentées).

package main

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

// Invariant est le résultat d'une vérification sur une trace.
type Invariant struct {
	Regle  string
	Objet  string
	Ecarts []string
}

// TransitionsEX83 est la table d'EX-8.3 : pour chaque état non final, les
// seuls états suivants admis ; envoyee → a_envoyer est la relève après une
// echec_permanente sans autre tentative en cours (EX-8.8). Un état final n'a
// aucune transition sortante, sauf obtenue → a_reprendre quand le jeton promu
// est constaté révoqué (EX-5.10, étape 10).
var TransitionsEX83 = map[string][]string{
	"a_envoyer":        {"envoyee", "remplacee"},
	"attente_registre": {"envoyee", "remplacee"},
	"envoyee":          {"obtenue", "en_attente", "a_reprendre", "envoyee", "a_envoyer", "refusee", "remplacee"},
	"a_reprendre":      {"envoyee", "remplacee"},
	"en_attente":       {"complete", "en_attente"},
	"obtenue":          {"a_reprendre"},
}

// EtatsInitiaux sont les premières lignes admises d'une demande (EX-8.5, règle 1).
var EtatsInitiaux = []string{"a_envoyer", "attente_registre"}

// TransitionAdmise dit si la table d'EX-8.3 admet prev → suivant ; prev vaut
// "" pour une demande qui n'a encore aucune ligne.
func TransitionAdmise(prev, suivant string) bool {
	if prev == "" {
		return dans(suivant, EtatsInitiaux)
	}
	return dans(suivant, TransitionsEX83[prev])
}

type actionLue struct {
	i      int
	t      int64
	action string
	id     string
	detail *Value
}

type entreeLue struct {
	t    int64
	typ  string
	data *Value
}

type analyseTrace struct {
	cfg       *Config
	nT        int64
	actions   []actionLue
	entrees   []entreeLue
	avant     map[string]*Demande
	finale    map[string]*Demande
	lignes    map[int]string
	gigues    []int64
	periodes  map[string]int64 // clé org|journal|period_start → period_start
	points    map[string][]int64
	admis     map[string][]int64 // points admis pendant la trace (point_produit), par période
	ecarts    map[string][]string
	ordreAN   []string
	objetsAN  map[string]string
	queueApre *Value
}

func (a *analyseTrace) ecart(regle, objet, format string, args ...any) {
	if _, ok := a.ecarts[regle]; !ok {
		a.ordreAN = append(a.ordreAN, regle)
		a.objetsAN[regle] = objet
	}
	a.ecarts[regle] = append(a.ecarts[regle], fmt.Sprintf(format, args...))
}

func (a *analyseTrace) declarer(regle, objet string) {
	if _, ok := a.ecarts[regle]; !ok {
		a.ordreAN = append(a.ordreAN, regle)
		a.objetsAN[regle] = objet
		a.ecarts[regle] = []string{}
	}
}

func kindDe(id string) string { return strings.SplitN(id, ":", 2)[0] }
func hashDe(id string) string {
	p := strings.SplitN(id, ":", 2)
	if len(p) < 2 {
		return ""
	}
	return p[1]
}

func (a *analyseTrace) D(periodStart, k int64) int64 {
	return (periodStart + k*a.cfg.CheckpointsIntervalS) * 1000
}

// VerifierInvariants vérifie les invariants de la section 8.11 sur une trace
// rejouée et rend un résultat par règle, dans l'ordre des règles.
func VerifierInvariants(trace *Value, rejeu *Rejeu) ([]Invariant, error) {
	a := &analyseTrace{cfg: ProjeterConfiguration(trace.Get("config")), avant: map[string]*Demande{}, finale: map[string]*Demande{}, lignes: map[int]string{}, periodes: map[string]int64{}, points: map[string][]int64{}, admis: map[string][]int64{}, ecarts: map[string][]string{}, objetsAN: map[string]string{}}
	if a.cfg.CheckpointsIntervalS <= 0 || 3600%a.cfg.CheckpointsIntervalS != 0 {
		return nil, refus("AN-1", "interval_s %d : diviseur de 3600 attendu", a.cfg.CheckpointsIntervalS)
	}
	a.nT = 3600 / a.cfg.CheckpointsIntervalS
	a.gigues = entiersDe(trace, "jitter_ms")
	a.queueApre = trace.Get("queue_after")
	for i, v := range rejeu.Actions {
		t, err := Ms(chaineOu(v, "", "t"))
		if err != nil {
			return nil, err
		}
		a.actions = append(a.actions, actionLue{i: i, t: t, action: chaineOu(v, "", "action"), id: chaineOu(v, "", "request_id"), detail: v.Get("detail")})
	}
	if in := trace.Get("inputs"); in != nil && in.Kind == KindArray {
		for _, e := range in.Arr {
			t, err := Ms(chaineOu(e, "", "t"))
			if err != nil {
				return nil, err
			}
			a.entrees = append(a.entrees, entreeLue{t: t, typ: chaineOu(e, "", "type"), data: e.Get("data")})
		}
	}
	if qb := trace.Get("queue_before"); qb != nil && qb.Kind == KindArray {
		for _, v := range qb.Arr {
			d, err := DemandeDe(v)
			if err != nil {
				return nil, refus("", "queue_before : %s", err.Error())
			}
			a.avant[d.ID] = d
			a.noterSujet(d.Subject)
		}
	}
	for _, d := range rejeu.File {
		a.finale[d.ID] = d
		a.noterSujet(d.Subject)
	}
	for _, e := range rejeu.Ecritures {
		a.lignes[e.Action] = e.Ligne
	}
	for _, e := range a.entrees {
		switch e.typ {
		case "point_produit":
			s := &Sujet{Kind: "point", OrgID: chaineOu(e.data, "", "org_id"), JournalID: chaineOu(e.data, "", "journal_id"), PeriodStart: entierOu(e.data, 0, "period_start"), DeclaredAt: chaineOu(e.data, "", "checkpoint_ts")}
			a.noterSujet(s)
			if ts, err := Ms(s.DeclaredAt); err == nil {
				a.admis[cle(s)] = append(a.admis[cle(s)], ts)
			}
		case "periode_close":
			s := &Sujet{Kind: "periode", OrgID: chaineOu(e.data, "", "org_id"), JournalID: chaineOu(e.data, "", "journal_id"), PeriodStart: entierOu(e.data, 0, "period_start")}
			a.noterSujet(s)
		}
	}
	a.an32()
	a.an33()
	a.an34()
	a.an35()
	a.an36()
	a.an37()
	a.an39()
	a.an40()
	a.an41()
	a.an43()
	a.formesRepresentees(chaineOu(trace, "", "id"))
	var out []Invariant
	for _, r := range a.ordreAN {
		out = append(out, Invariant{Regle: r, Objet: a.objetsAN[r], Ecarts: a.ecarts[r]})
	}
	return out, nil
}

func (a *analyseTrace) noterSujet(s *Sujet) {
	k := cle(s)
	a.periodes[k] = s.PeriodStart
	if s.Kind == "point" && s.DeclaredAt != "" {
		if ts, err := Ms(s.DeclaredAt); err == nil {
			deja := false
			for _, x := range a.points[k] {
				if x == ts {
					deja = true
				}
			}
			if !deja {
				a.points[k] = append(a.points[k], ts)
			}
		}
	}
}

// etatsSuccessifs rejoue les ecrire_file et rend, pour chaque action, l'état
// de la demande avant cette action (la file de départ compte).
func (a *analyseTrace) etatsSuccessifs() []map[string]string {
	courant := map[string]string{}
	for id, d := range a.avant {
		courant[id] = d.State
	}
	out := make([]map[string]string, len(a.actions))
	for i, x := range a.actions {
		copie := map[string]string{}
		for k, v := range courant {
			copie[k] = v
		}
		out[i] = copie
		if x.action == "ecrire_file" {
			courant[x.id] = chaineOu(x.detail, "", "state")
		}
	}
	return out
}

// AN-32 : toute requête est précédée, au même instant et dans l'ordre des
// actions, d'une ligne envoyee de la demande ; pour une requête RFC 3161 la
// ligne porte le nonce et le rang de la tentative (EX-8.5, règle 1 ; EX-8.16 :
// l'ordre d'expected est normatif). Une mise à niveau OpenTimestamps est
// précédée de sa ligne en_attente.
func (a *analyseTrace) an32() {
	a.declarer("AN-32", "ligne envoyee portant le nonce écrite avant chaque requête (EX-8.5, règle 1)")
	etats := a.etatsSuccessifs()
	for _, x := range a.actions {
		if x.action == "mettre_a_niveau_ots" {
			ok := false
			for _, y := range a.actions {
				if y.i < x.i && y.t == x.t && y.id == x.id && y.action == "ecrire_file" && chaineOu(y.detail, "", "state") == "en_attente" {
					ok = true
				}
			}
			if !ok {
				a.ecart("AN-32", "", "%s mettre_a_niveau_ots %s : aucune ligne en_attente écrite avant la requête", Iso(x.t), x.id)
			}
			continue
		}
		switch x.action {
		case "envoyer_rfc3161", "envoyer_registre", "soumettre_ots":
		default:
			continue
		}
		nonce := chaineOu(x.detail, "", "nonce")
		attempt := entierOu(x.detail, 0, "attempt")
		trouve := false
		for _, y := range a.actions {
			if y.i >= x.i || y.t != x.t || y.id != x.id || y.action != "ecrire_file" || chaineOu(y.detail, "", "state") != "envoyee" {
				continue
			}
			if x.action != "envoyer_rfc3161" {
				trouve = true
				break
			}
			ligne := a.lignes[y.i]
			if strings.Contains(ligne, fmt.Sprintf(`"nonce":"%s"`, nonce)) && strings.Contains(ligne, fmt.Sprintf(`"n":%d`, attempt)) {
				trouve = true
				break
			}
		}
		if !trouve && x.action != "envoyer_rfc3161" && etats[x.i][x.id] == "envoyee" {
			trouve = true // renvoi d'une ancre déjà envoyee (EX-8.12, CT-4 §8.6)
		}
		if !trouve {
			a.ecart("AN-32", "", "%s %s %s : aucune ligne envoyee (avec le nonce %s) écrite avant la requête", Iso(x.t), x.action, x.id, nonce)
		}
	}
}

// AN-33 : une seule demande par id dans la file finale, état égal à la
// dernière ligne écrite ; un demarrage ne produit que les transitions
// d'EX-8.12 (envoyee → a_reprendre).
func (a *analyseTrace) an33() {
	a.declarer("AN-33", "une demande par id, dernière ligne fait foi, transitions du demarrage (EX-8.5, EX-8.12)")
	dernier := map[string]string{}
	for id, d := range a.avant {
		dernier[id] = d.State
	}
	for _, x := range a.actions {
		if x.action == "ecrire_file" {
			dernier[x.id] = chaineOu(x.detail, "", "state")
		}
	}
	if a.queueApre != nil && a.queueApre.Kind == KindArray {
		vus := map[string]bool{}
		for _, v := range a.queueApre.Arr {
			id := chaineOu(v, "", "id")
			if vus[id] {
				a.ecart("AN-33", "", "queue_after : id %s en double", id)
			}
			vus[id] = true
			if st := chaineOu(v, "", "state"); st != dernier[id] {
				a.ecart("AN-33", "", "queue_after : %s dans l'état %s, dernière ligne écrite %s", id, st, dernier[id])
			}
		}
		for id := range dernier {
			if !vus[id] {
				a.ecart("AN-33", "", "queue_after : demande %s absente", id)
			}
		}
	}
	for _, e := range a.entrees {
		if e.typ != "demarrage" {
			continue
		}
		a.demarrageEX812(e.t)
	}
}

// demarrageEX812 vérifie qu'un demarrage produit, à son instant, les seules
// transitions d'EX-8.12 : une demande envoyee (jeton ou preuve) passe
// a_reprendre puis repart aussitôt ; une ancre envoyee est renvoyée sans
// changer d'état ; attente_registre interroge l'inclusion ; a_reprendre garde
// due_at ; en_attente reprogramme la mise à niveau à max(due_at, now) ;
// aucune demande n'atteint un état final autre que remplacee (EX-4.4) sans
// réponse.
func (a *analyseTrace) demarrageEX812(t int64) {
	premiereEcriture := map[string]string{}
	actionsA := map[string]map[string]bool{}
	for _, x := range a.actions {
		if x.t != t {
			continue
		}
		if actionsA[x.id] == nil {
			actionsA[x.id] = map[string]bool{}
		}
		nom := x.action
		if x.action == "programmer" {
			nom += ":" + chaineOu(x.detail, "", "reason")
		}
		actionsA[x.id][nom] = true
		if x.action == "ecrire_file" {
			st := chaineOu(x.detail, "", "state")
			if _, ok := premiereEcriture[x.id]; !ok {
				premiereEcriture[x.id] = st
			}
			if EtatsFinaux[st] && st != "remplacee" {
				a.ecart("AN-33", "", "%s demarrage : %s écrite %s sans réponse reçue", Iso(t), x.id, st)
			}
		}
	}
	var ids []string
	for id := range a.avant {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		d := a.avant[id]
		if EtatsFinaux[d.State] {
			continue
		}
		faites := actionsA[id]
		switch {
		case prefixe(d.Kind, "ancre_registre_") && d.State == "envoyee":
			if !faites["envoyer_registre"] {
				a.ecart("AN-33", "", "%s demarrage : ancre %s envoyee sans renvoi (CT-4 §8.6)", Iso(t), id)
			}
			if _, ok := premiereEcriture[id]; ok {
				a.ecart("AN-33", "", "%s demarrage : ancre %s envoyee réécrite (%s) au lieu d'un renvoi", Iso(t), id, premiereEcriture[id])
			}
		case d.State == "envoyee":
			if premiereEcriture[id] != "a_reprendre" {
				a.ecart("AN-33", "", "%s demarrage : %s envoyee ne passe pas a_reprendre (EX-8.12)", Iso(t), id)
			}
		case d.State == "attente_registre":
			if !faites["programmer:attente_registre"] && !faites["envoyer_rfc3161"] {
				a.ecart("AN-33", "", "%s demarrage : %s attente_registre sans interrogation de l'inclusion", Iso(t), id)
			}
		case d.State == "en_attente":
			if !faites["programmer:mise_a_niveau"] {
				a.ecart("AN-33", "", "%s demarrage : %s en_attente sans reprogrammation de la mise à niveau", Iso(t), id)
				continue
			}
			for _, x := range a.actions {
				if x.t == t && x.id == id && x.action == "programmer" && chaineOu(x.detail, "", "reason") == "mise_a_niveau" {
					attendu := t
					if d.DueAt != nil {
						if v, err := Ms(*d.DueAt); err == nil && v > t {
							attendu = v
						}
					}
					if next, err := Ms(chaineOu(x.detail, "", "next_at")); err == nil && next != attendu {
						a.ecart("AN-33", "", "%s demarrage : %s mise à niveau reprogrammée à %s, attendu max(due_at, now) = %s", Iso(t), id, Iso(next), Iso(attendu))
					}
				}
			}
		case d.State == "a_reprendre":
			if st, ok := premiereEcriture[id]; ok && st != "envoyee" && st != "remplacee" {
				a.ecart("AN-33", "", "%s demarrage : %s a_reprendre écrite %s", Iso(t), id, st)
			}
		}
	}
}

// AN-34 : transitions conformes à la table d'EX-8.3 ; aucun jeton_periode
// dans un état final autre qu'obtenue.
func (a *analyseTrace) an34() {
	a.declarer("AN-34", "transitions d'état de la table d'EX-8.3 ; jeton_periode jamais abandonné")
	etats := a.etatsSuccessifs()
	for _, x := range a.actions {
		if x.action != "ecrire_file" {
			continue
		}
		prev, suivant := etats[x.i][x.id], chaineOu(x.detail, "", "state")
		if !TransitionAdmise(prev, suivant) {
			if prev == "" {
				prev = "(aucune ligne)"
			}
			a.ecart("AN-34", "", "%s %s : transition %s → %s absente de la table d'EX-8.3", Iso(x.t), x.id, prev, suivant)
		}
	}
	for _, d := range a.finale {
		if d.Kind == "jeton_periode" && EtatsFinaux[d.State] && d.State != "obtenue" {
			a.ecart("AN-34", "", "%s dans l'état final %s (EX-4.5, EX-5.7)", d.ID, d.State)
		}
	}
}

// AN-35 : échéances D_k = period_start + k × c_T ; un point n'est demandé
// qu'une fois ; chaque k d'une demande est satisfait par le premier point de
// checkpoint_ts ≥ D_k (EX-4.2, EX-4.3, EX-8.4).
func (a *analyseTrace) an35() {
	a.declarer("AN-35", "échéances D_k et sélection du premier point de checkpoint_ts ≥ D_k (EX-4.2, EX-4.3)")
	for _, x := range a.actions {
		if x.action != "echeance" || chaineOu(x.detail, "", "state") != "ouverte" {
			continue
		}
		k := entierOu(x.detail, 0, "k")
		if k < 1 || k > a.nT {
			a.ecart("AN-35", "", "%s échéance k = %d hors de [1, %d]", Iso(x.t), k, a.nT)
			continue
		}
		if x.id == "" {
			ok := false
			for _, ps := range a.periodes {
				if a.D(ps, k) == x.t {
					ok = true
				}
			}
			if !ok {
				a.ecart("AN-35", "", "%s échéance %d ouverte à un instant qui n'est D_%d d'aucune période connue", Iso(x.t), k, k)
			}
			continue
		}
		d := a.finale[x.id]
		if d == nil {
			a.ecart("AN-35", "", "%s échéance %d ouverte pour une demande inconnue %s", Iso(x.t), k, x.id)
			continue
		}
		if ts, err := Ms(d.Subject.DeclaredAt); err == nil && ts < a.D(d.Subject.PeriodStart, k) {
			a.ecart("AN-35", "", "%s : échéance %d sélectionne un point de checkpoint_ts %s antérieur à D_%d", x.id, k, d.Subject.DeclaredAt, k)
		}
	}
	// Une demande refusee ne compte pas comme contresignée : ses échéances sont
	// rendues et servies par le point admis ensuite (EX-4.3, EX-8.4 règle 1).
	refuses := map[string]bool{}
	for _, d := range a.finale {
		if d.Kind == "jeton_point" && d.State == "refusee" {
			if ts, err := Ms(d.Subject.DeclaredAt); err == nil {
				refuses[fmt.Sprintf("%s#%d", cle(d.Subject), ts)] = true
			}
		}
	}
	servies := map[string]string{}
	var ids []string
	for id := range a.finale {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		d := a.finale[id]
		if d.Kind != "jeton_point" || d.State == "refusee" {
			continue
		}
		ts, err := Ms(d.Subject.DeclaredAt)
		if err != nil {
			a.ecart("AN-35", "", "%s : declared_at illisible", d.ID)
			continue
		}
		k0 := cle(d.Subject)
		for _, k := range d.Deadlines {
			if k < 1 || k >= a.nT {
				a.ecart("AN-35", "", "%s : échéance %d hors de [1, n_T − 1 = %d]", d.ID, k, a.nT-1)
			}
			if ts < a.D(d.Subject.PeriodStart, k) {
				a.ecart("AN-35", "", "%s : checkpoint_ts %s antérieur à D_%d", d.ID, d.Subject.DeclaredAt, k)
			}
			// Seuls les points admis pendant la trace comptent : une échéance close
			// sans_objet avant un redémarrage n'est pas dans la file et est rouverte
			// au démarrage (EX-8.12), puis servie par le point admis ensuite.
			for _, autre := range a.admis[k0] {
				if autre < ts && autre >= a.D(d.Subject.PeriodStart, k) && !refuses[fmt.Sprintf("%s#%d", k0, autre)] {
					a.ecart("AN-35", "", "%s : un point antérieur (%s) satisfait déjà checkpoint_ts ≥ D_%d", d.ID, Iso(autre), k)
				}
			}
			c := fmt.Sprintf("%s#%d", k0, k)
			if prec, ok := servies[c]; ok {
				a.ecart("AN-35", "", "échéance %d de la période %d servie par deux demandes (%s, %s)", k, d.Subject.PeriodStart, prec, d.ID)
			}
			servies[c] = d.ID
		}
	}
}

func (a *analyseTrace) premiereEntree(typ, id string, avant int64, filtre func(*Value) bool) *entreeLue {
	for i := range a.entrees {
		e := &a.entrees[i]
		if e.typ == typ && chaineOu(e.data, "", "request_id") == id && e.t <= avant && (filtre == nil || filtre(e.data)) {
			return e
		}
	}
	return nil
}

// AN-36 : jeton_periode envoyé après l'inclusion de l'ancre de la période ;
// jeton_point envoyé après l'inclusion de l'ancre du point, ou au plus
// squat_wait_s après l'admission avec ordre_ancres_non_respecte (EX-8.4,
// EX-9.6, EX-9.7).
func (a *analyseTrace) an36() {
	a.declarer("AN-36", "ordre des ancres : inclusion au registre avant la requête RFC 3161 (EX-8.4, EX-9.6)")
	premiers := map[string]bool{}
	for _, x := range a.actions {
		if x.action != "envoyer_rfc3161" || premiers[x.id] {
			continue
		}
		premiers[x.id] = true
		if entierOu(x.detail, 0, "attempt") != 1 {
			continue // relance après redémarrage : la première tentative est dans la file de départ
		}
		hash := hashDe(x.id)
		if kindDe(x.id) == "jeton_periode" {
			if a.cfg.RegistryCheckpoints == "aucun" {
				continue
			}
			if a.premiereEntree("inclusion_registre", "ancre_registre_periode:"+hash, x.t, nil) == nil {
				a.ecart("AN-36", "", "%s %s envoyé sans inclusion préalable de l'ancre de la période", Iso(x.t), x.id)
			}
			continue
		}
		ancreID := "ancre_registre_point:" + hash
		envoyee := false
		if d, ok := a.avant[ancreID]; ok && (d.State == "envoyee" || d.State == "a_envoyer") {
			envoyee = true
		}
		for _, y := range a.actions {
			if y.action == "envoyer_registre" && y.id == ancreID && y.t <= x.t {
				envoyee = true
			}
		}
		if !envoyee {
			continue
		}
		if a.premiereEntree("inclusion_registre", ancreID, x.t, nil) != nil {
			continue
		}
		if a.premiereEntree("echec_registre", ancreID, x.t, func(d *Value) bool { return chaineOu(d, "", "code") == "empreinte_squattee" }) != nil {
			continue
		}
		d := a.finale[x.id]
		justifie := false
		for _, y := range a.actions {
			if y.action == "journaliser" && y.id == x.id && y.t <= x.t && chaineOu(y.detail, "", "event") == "ordre_ancres_non_respecte" {
				if d != nil {
					if c, err := Ms(d.CreatedAt); err == nil && y.t != c+a.cfg.SquatWaitS*1000 {
						a.ecart("AN-36", "", "%s %s : ordre_ancres_non_respecte à %s, attendu à admission + squat_wait_s = %s", Iso(x.t), x.id, Iso(y.t), Iso(c+a.cfg.SquatWaitS*1000))
					}
				}
				justifie = true
			}
		}
		if !justifie {
			a.ecart("AN-36", "", "%s %s envoyé sans inclusion de l'ancre ni ligne ordre_ancres_non_respecte", Iso(x.t), x.id)
		}
	}
}

// AN-37 : attente de reprise d'EX-8.9 recalculée depuis les entrées :
// Retry-After pour 429 et 503, 0 pour le premier 408 d'une demande chez un
// prestataire, sinon min(max_ms, initial_ms × factor^(k−1)) plus la gigue
// injectée, consommée dans l'ordre.
func (a *analyseTrace) an37() {
	a.declarer("AN-37", "attente de reprise d'EX-8.9 (Retry-After, premier 408, suite géométrique plafonnée, gigue)")
	k := map[string]int64{}
	premier408 := map[string]bool{}
	gigue := 0
	prendreGigue := func() int64 {
		if gigue >= len(a.gigues) {
			return 0
		}
		g := a.gigues[gigue]
		gigue++
		return g
	}
	// ordre de consommation des gigues : les entrées dans l'ordre de la trace
	etatOts := map[string]string{}
	for id, d := range a.avant {
		if prefixe(d.Kind, "ots_") {
			etatOts[id] = d.State
		}
	}
	for _, e := range a.entrees {
		switch e.typ {
		case "reponse_ots":
			id := chaineOu(e.data, "", "request_id")
			st := etatOts[id]
			for _, x := range a.actions {
				if x.t < e.t && x.action == "ecrire_file" && x.id == id {
					st = chaineOu(x.detail, "", "state")
				}
			}
			if (st == "envoyee" || st == "a_reprendre") && (chaineOu(e.data, "", "attestation") == "aucune" || entierOu(e.data, 0, "calendars_answered") < a.cfg.MinResponses) {
				prendreGigue()
			}
		case "reponse_rfc3161":
			id := chaineOu(e.data, "", "request_id")
			var rejet, prog *actionLue
			for i := range a.actions {
				x := &a.actions[i]
				if x.t != e.t || x.id != id {
					continue
				}
				if x.action == "rejeter_reponse" && rejet == nil {
					rejet = x
				}
				if rejet != nil && x.action == "programmer" && prog == nil {
					prog = x
				}
			}
			if rejet == nil || chaineOu(rejet.detail, "", "class") != "transitoire" {
				continue
			}
			prov := ""
			if d := a.finale[id]; d != nil {
				for _, att := range d.Attempts {
					if att.N == entierOu(e.data, 0, "attempt") && att.Provider != nil {
						prov = *att.Provider
					}
				}
			}
			c := id + "|" + prov
			k[c]++
			httpStatus := ptrEntier(e.data, "http_status")
			retryAfter := ptrEntier(e.data, "retry_after_s")
			immediat := httpStatus != nil && *httpStatus == 408 && !premier408[c]
			if immediat {
				premier408[c] = true
			}
			avecRetryAfter := httpStatus != nil && (*httpStatus == 429 || *httpStatus == 503) && retryAfter != nil
			var g int64
			if !immediat && !avecRetryAfter {
				g = prendreGigue()
			}
			attendu, raison := CalculerAttente(httpStatus, retryAfter, k[c], !immediat, a.cfg.Retry, g)
			if prog == nil {
				a.ecart("AN-37", "", "%s %s : aucune action programmer après le rejet transitoire", Iso(e.t), id)
				continue
			}
			next, err := Ms(chaineOu(prog.detail, "", "next_at"))
			if err != nil {
				a.ecart("AN-37", "", "%s %s : next_at illisible", Iso(e.t), id)
				continue
			}
			if float64(next-e.t) != attendu || chaineOu(prog.detail, "", "reason") != raison {
				a.ecart("AN-37", "", "%s %s : attente %d ms (%s), attendu %.0f ms (%s) pour k = %d", Iso(e.t), id, next-e.t, chaineOu(prog.detail, "", "reason"), attendu, raison, k[c])
			}
		}
	}
}

// AN-39 et AN-58 : min_interval_ms entre deux requêtes au même prestataire,
// toutes demandes confondues ; à un même instant, jeton_periode avant
// jeton_point (EX-8.7).
func (a *analyseTrace) an39() {
	a.declarer("AN-39", "min_interval_ms respecté par prestataire ; jeton_periode servi avant jeton_point (EX-8.7, AN-58)")
	dernier := map[string]*actionLue{}
	for i := range a.actions {
		x := &a.actions[i]
		if x.action != "envoyer_rfc3161" {
			continue
		}
		prov := chaineOu(x.detail, "", "provider")
		var min int64
		for _, p := range a.cfg.Providers {
			if p.ID == prov {
				min = p.MinIntervalMs
			}
		}
		if prec, ok := dernier[prov]; ok {
			if x.t-prec.t < min {
				a.ecart("AN-39", "", "%s : %d ms entre deux requêtes à %s, min_interval_ms %d", Iso(x.t), x.t-prec.t, prov, min)
			}
			if x.t == prec.t && kindDe(x.id) == "jeton_periode" && kindDe(prec.id) == "jeton_point" {
				a.ecart("AN-39", "", "%s : %s servi avant %s chez %s", Iso(x.t), prec.id, x.id, prov)
			}
		}
		dernier[prov] = x
	}
}

// AN-40 et AN-48 : capture (stocker) avant obtenue pour une ancre au
// registre ; empreinte_squattee → refusee sans nouvel essai ; inclusion_late
// au-delà de inclusion_alert_s (EX-8.10, EX-9.7).
func (a *analyseTrace) an40() {
	a.declarer("AN-40", "registre : capture avant obtenue, empreinte_squattee → refusee, inclusion_late (EX-8.10, EX-9.7, AN-48)")
	for _, x := range a.actions {
		if x.action != "ecrire_file" || !prefixe(kindDe(x.id), "ancre_registre_") || chaineOu(x.detail, "", "state") != "obtenue" {
			continue
		}
		ok := false
		for _, y := range a.actions {
			if y.i < x.i && y.t == x.t && y.id == x.id && y.action == "stocker" {
				ok = true
			}
		}
		if !ok {
			a.ecart("AN-40", "", "%s %s obtenue sans stocker (index de capture) au préalable", Iso(x.t), x.id)
		}
	}
	for _, e := range a.entrees {
		if e.typ != "echec_registre" || chaineOu(e.data, "", "code") != "empreinte_squattee" {
			continue
		}
		id := chaineOu(e.data, "", "request_id")
		refusee := false
		for _, x := range a.actions {
			if x.id != id {
				continue
			}
			if x.t == e.t && x.action == "ecrire_file" && chaineOu(x.detail, "", "state") == "refusee" {
				refusee = true
			}
			if x.t >= e.t && x.action == "envoyer_registre" {
				a.ecart("AN-40", "", "%s %s renvoyée après empreinte_squattee", Iso(x.t), id)
			}
		}
		if !refusee {
			a.ecart("AN-40", "", "%s %s : empreinte_squattee sans ligne refusee", Iso(e.t), id)
		}
	}
	for _, e := range a.entrees {
		if e.typ != "inclusion_registre" {
			continue
		}
		id := chaineOu(e.data, "", "request_id")
		var premier *int64
		if d, ok := a.avant[id]; ok && len(d.Attempts) > 0 && d.State == "envoyee" {
			if v, err := Ms(d.Attempts[0].StartedAt); err == nil {
				premier = &v
			}
		}
		if premier == nil {
			for _, x := range a.actions {
				if x.id == id && x.action == "envoyer_registre" && x.t <= e.t {
					v := x.t
					premier = &v
					break
				}
			}
		}
		if premier == nil || e.t-*premier <= a.cfg.InclusionAlertS*1000 {
			continue
		}
		alerte := false
		for _, x := range a.actions {
			if x.id == id && x.action == "alerter" && x.t <= e.t && chaineOu(x.detail, "", "code") == "inclusion_late" {
				alerte = true
			}
		}
		if !alerte {
			a.ecart("AN-40", "", "%s %s incluse %d s après l'envoi sans alerte inclusion_late", Iso(e.t), id, (e.t-*premier)/1000)
		}
	}
}

// AN-41 : en_attente dès min_responses réponses, mise à niveau à
// first_after_s puis interval_s (≥ 60 s), complete à la première attestation
// Bitcoin avec réexport (EX-8.11).
func (a *analyseTrace) an41() {
	a.declarer("AN-41", "OpenTimestamps : seuil min_responses, cadence de mise à niveau, complete et réexport (EX-8.11)")
	intervalle := a.cfg.UpgradeIntervalS
	if intervalle < 60 {
		intervalle = 60
	}
	demarrages := map[int64]bool{}
	for _, e := range a.entrees {
		if e.typ == "demarrage" {
			demarrages[e.t] = true
		}
	}
	etats := a.etatsSuccessifs()
	for _, x := range a.actions {
		if !prefixe(kindDe(x.id), "ots_") {
			continue
		}
		switch {
		case x.action == "ecrire_file" && chaineOu(x.detail, "", "state") == "en_attente":
			if etats[x.i][x.id] == "en_attente" {
				continue // mise à niveau sans attestation Bitcoin : un seul calendrier interrogé (EX-6.6, EX-8.3)
			}
			var meme *entreeLue
			for i := range a.entrees {
				e := &a.entrees[i]
				if e.t == x.t && e.typ == "reponse_ots" && chaineOu(e.data, "", "request_id") == x.id {
					meme = e
				}
			}
			if meme == nil {
				a.ecart("AN-41", "", "%s %s en_attente sans réponse des calendriers à cet instant", Iso(x.t), x.id)
				continue
			}
			if chaineOu(meme.data, "", "attestation") != "en_attente" || entierOu(meme.data, 0, "calendars_answered") < a.cfg.MinResponses {
				a.ecart("AN-41", "", "%s %s en_attente avec %d réponse(s) (%s), min_responses %d", Iso(x.t), x.id, entierOu(meme.data, 0, "calendars_answered"), chaineOu(meme.data, "", "attestation"), a.cfg.MinResponses)
			}
		case x.action == "programmer" && chaineOu(x.detail, "", "reason") == "mise_a_niveau":
			if demarrages[x.t] {
				continue // max(due_at, now) au démarrage (EX-8.12)
			}
			next, err := Ms(chaineOu(x.detail, "", "next_at"))
			if err != nil {
				continue
			}
			premiere := true
			for _, y := range a.actions {
				if y.i < x.i && y.id == x.id && y.action == "programmer" && chaineOu(y.detail, "", "reason") == "mise_a_niveau" {
					premiere = false
				}
			}
			if d, ok := a.avant[x.id]; ok && d.State == "en_attente" {
				premiere = false
			}
			attendu := intervalle * 1000
			if premiere {
				attendu = a.cfg.UpgradeFirstAfterS * 1000
			}
			if next-x.t != attendu && next-x.t != 86400*1000 {
				a.ecart("AN-41", "", "%s %s : mise à niveau programmée %d s plus tard, attendu %d s", Iso(x.t), x.id, (next-x.t)/1000, attendu/1000)
			}
		case x.action == "ecrire_file" && chaineOu(x.detail, "", "state") == "complete":
			ok := false
			for i := range a.entrees {
				e := &a.entrees[i]
				if e.t == x.t && e.typ == "reponse_ots" && chaineOu(e.data, "", "request_id") == x.id && chaineOu(e.data, "", "attestation") == "complete" {
					ok = true
				}
			}
			if !ok {
				a.ecart("AN-41", "", "%s %s complete sans attestation Bitcoin reçue à cet instant", Iso(x.t), x.id)
			}
			reexport := false
			for _, y := range a.actions {
				if y.t == x.t && y.id == x.id && y.action == "journaliser" && chaineOu(y.detail, "", "event") == "ots_complete" {
					if b, okb := booleenDe(y.detail, "reexport"); okb && b {
						reexport = true
					}
				}
			}
			if !reexport {
				a.ecart("AN-41", "", "%s %s complete sans ots_complete avec reexport", Iso(x.t), x.id)
			}
		}
	}
}

var reAdresseIP = regexp.MustCompile(`(^|[^0-9.])([0-9]{1,3}\.){3}[0-9]{1,3}([^0-9.]|$)`)

// MotsInterdits sont les mots qu'une ligne de journal ou de file ne porte
// jamais (AN-43, EX-A.6) : mot de passe, secret, en-tête d'autorisation,
// identifiant d'accès, prix. Ils sont comparés sans tenir compte de la casse.
var MotsInterdits = []string{"Password", "Secret", "Authorization", "Credential", "Price"}

// AN-43 : aucune ligne du journal ni de la file ne porte un secret, une
// adresse ou un identifiant de compte.
func (a *analyseTrace) an43() {
	a.declarer("AN-43", "aucun secret, adresse ni identifiant de compte dans le journal et la file")
	verifier := func(quoi, texte string) {
		bas := strings.ToLower(texte)
		for _, m := range MotsInterdits {
			if strings.Contains(bas, strings.ToLower(m)) {
				a.ecart("AN-43", "", "%s porte %q", quoi, m)
			}
		}
		if reAdresseIP.MatchString(texte) {
			a.ecart("AN-43", "", "%s porte une adresse IP", quoi)
		}
	}
	for _, x := range a.actions {
		if x.action == "journaliser" || x.action == "alerter" {
			verifier(fmt.Sprintf("%s %s", Iso(x.t), x.action), Rendu(x.detail))
		}
	}
	for i, l := range a.lignes {
		verifier(fmt.Sprintf("ligne de file de l'action %d", i), l)
	}
}

// Formes représentées de l'annexe A.2 : l'index de capture d'une inclusion
// est SHA-256(UTF-8("capture <id> <bloc>")) ; dans la trace de référence de
// 8.10, la preuve .ots représentée est SHA-256(UTF-8("preuve en attente
// periode 1")), taille déclarée 233.
func (a *analyseTrace) formesRepresentees(traceID string) {
	a.declarer("A.2", "formes représentées : SHA-256 des index de capture et de la preuve de la trace de référence")
	for _, e := range a.entrees {
		switch e.typ {
		case "inclusion_registre":
			attendu := SHA256Hex([]byte(fmt.Sprintf("capture %s %d", chaineOu(e.data, "", "request_id"), entierOu(e.data, 0, "block_number"))))
			if obtenu := chaineOu(e.data, "", "capture_sha256"); obtenu != attendu {
				a.ecart("A.2", "", "%s capture_sha256 %s, attendu %s", Iso(e.t), obtenu, attendu)
			}
		case "reponse_ots":
			if traceID != "heure-nominale-reference" {
				continue
			}
			attendu := SHA256Hex([]byte("preuve en attente periode 1"))
			if obtenu := chaineOu(e.data, "", "proof_sha256"); obtenu != attendu || entierOu(e.data, 0, "proof_size") != 233 {
				a.ecart("A.2", "", "%s proof_sha256 %s (taille %d), attendu %s (233)", Iso(e.t), obtenu, entierOu(e.data, 0, "proof_size"), attendu)
			}
		}
	}
}

// DelaiAttendu recalcule, hors de toute trace, la suite d'EX-8.9 sans gigue
// pour k échecs consécutifs (5 s, 10 s, 20 s, …, plafond max_ms).
func DelaiAttendu(retry Reprise, k int64) float64 {
	return math.Min(retry.MaxMs, retry.InitialMs*math.Pow(retry.Factor, float64(k-1)))
}
