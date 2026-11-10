// Demandes de la file d'ancrage (CT-5 §8.2, EX-8.3, EX-8.5 ; `$defs/demande`
// du schéma planificateur-ancrage-v0) : sujet, tentatives, résultat ; lecture
// depuis une valeur JSON et écriture en valeur JSON (forme canonique JCS
// pour la file NDJSON, règle 3 d'EX-8.5).

package main

import (
	"fmt"
	"sort"
	"strings"
)

// Sortes, états et rôles (CT-5 §8.2, EX-8.3, 4.4).
var (
	Sortes      = []string{"ancre_registre_point", "jeton_point", "ots_point", "ancre_registre_periode", "jeton_periode", "ots_periode"}
	Etats       = []string{"a_envoyer", "attente_registre", "envoyee", "a_reprendre", "en_attente", "obtenue", "complete", "sans_objet", "refusee", "remplacee"}
	EtatsFinaux = map[string]bool{"obtenue": true, "complete": true, "sans_objet": true, "refusee": true, "remplacee": true}
	Roles       = []string{"principal", "secours", "second_rang", "interne"}
)

// TailleIndexCapture est la taille représentée d'un index de capture (A.2).
const TailleIndexCapture = 4096

// DureePeriode est la durée d'une période de CT-1 (secondes).
const DureePeriode = 3600

func dans(s string, liste []string) bool {
	for _, x := range liste {
		if x == s {
			return true
		}
	}
	return false
}

// Sujet est l'objet ancré : un point de contrôle ou une période.
type Sujet struct {
	Kind        string
	OrgID       string
	JournalID   string
	PeriodStart int64
	Hash        string
	TreeSize    *int64
	DeclaredAt  string
}

func (s *Sujet) valeur() *Value {
	return vObj("kind", vStr(s.Kind), "org_id", vStr(s.OrgID), "journal_id", vStr(s.JournalID), "period_start", vInt(s.PeriodStart), "hash", vStr(s.Hash), "tree_size", vIntOuNul(s.TreeSize), "declared_at", vStr(s.DeclaredAt))
}

// Tentative est une tentative d'une demande (`$defs/tentative`).
type Tentative struct {
	N             int64
	Provider      *string
	StartedAt     string
	Nonce         *string
	CorrelationID string
	Outcome       string
	ErrorCode     *string
	HTTPStatus    *int64
	PKIStatus     *int64
	FailureInfo   *string
	RetryAfterS   *int64
	NextAt        *string
	Detail        string
}

func (a *Tentative) valeur() *Value {
	return vObj("n", vInt(a.N), "provider", vStrOuNul(a.Provider), "started_at", vStr(a.StartedAt), "nonce", vStrOuNul(a.Nonce), "correlation_id", vStr(a.CorrelationID), "outcome", vStr(a.Outcome), "error_code", vStrOuNul(a.ErrorCode), "http_status", vIntOuNul(a.HTTPStatus), "pki_status", vIntOuNul(a.PKIStatus), "failure_info", vStrOuNul(a.FailureInfo), "retry_after_s", vIntOuNul(a.RetryAfterS), "next_at", vStrOuNul(a.NextAt), "detail", vStr(a.Detail))
}

// Resultat est la pièce obtenue (`$defs/resultat`).
type Resultat struct {
	SHA256     string
	Size       int64
	Provider   *string
	ObtainedAt string
	Bound      *string
}

func (r *Resultat) valeur() *Value {
	if r == nil {
		return vNull()
	}
	return vObj("sha256", vStr(r.SHA256), "size", vInt(r.Size), "provider", vStrOuNul(r.Provider), "obtained_at", vStr(r.ObtainedAt), "bound", vStrOuNul(r.Bound))
}

// Demande est une entrée de la file (`$defs/demande`).
type Demande struct {
	Version   int64
	ID        string
	Kind      string
	Subject   *Sujet
	Deadlines []int64
	State     string
	CreatedAt string
	DueAt     *string
	Attempts  []*Tentative
	// AttemptsTotal est le nombre de tentatives depuis la création (EX-8.5,
	// règle 7 ; révision 0.6) ; nil pour une ligne écrite avant la révision.
	AttemptsTotal *int64
	Result        *Resultat
	ReplacedBy    *string
}

// FenetreTentatives est le nombre maximal de tentatives qu'une ligne de file
// porte (EX-8.5, règle 7 ; révision 0.6 ; maxItems de `$defs/demande`).
const FenetreTentatives = 32

// Total rend attempts_total : le membre lu ou écrit, sinon, pour une ligne
// d'avant la révision 0.6 qui portait toutes ses tentatives, leur nombre.
func (d *Demande) Total() int64 {
	if d.AttemptsTotal != nil {
		return *d.AttemptsTotal
	}
	return int64(len(d.Attempts))
}

// Fenetre réduit les tentatives à celles qu'une ligne porte (EX-8.5, règle
// 7) : les tentatives en cours toujours, puis les plus récentes par rang
// décroissant jusqu'à 32 ; rangées par rang croissant, jamais renumérotées.
func Fenetre(l []*Tentative) []*Tentative {
	garde := map[*Tentative]bool{}
	for _, a := range l {
		if a.Outcome == "en_cours" {
			garde[a] = true
		}
	}
	autres := []*Tentative{}
	for _, a := range l {
		if a.Outcome != "en_cours" {
			autres = append(autres, a)
		}
	}
	sort.SliceStable(autres, func(i, j int) bool { return autres[i].N > autres[j].N })
	for _, a := range autres {
		if len(garde) >= FenetreTentatives {
			break
		}
		garde[a] = true
	}
	out := []*Tentative{}
	for _, a := range l {
		if garde[a] {
			out = append(out, a)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].N < out[j].N })
	return out
}

// ControlerLigneEcrite dit si une ligne écrite par un planificateur de la
// révision 0.6 respecte `$defs/demande` révisé et la règle 7 d'EX-8.5 : au plus
// 32 tentatives, rangs strictement croissants, attempts_total présent (0 à
// 100 000) et égal au plus grand rang (0 sans tentative).
func ControlerLigneEcrite(d *Demande) error {
	if len(d.Attempts) > FenetreTentatives {
		return fmt.Errorf("%s : %d tentatives, au plus %d", d.ID, len(d.Attempts), FenetreTentatives)
	}
	if d.AttemptsTotal == nil {
		return fmt.Errorf("%s : attempts_total absent", d.ID)
	}
	var max int64
	for i, a := range d.Attempts {
		if i > 0 && a.N <= d.Attempts[i-1].N {
			return fmt.Errorf("%s : rangs non strictement croissants", d.ID)
		}
		if a.N > max {
			max = a.N
		}
	}
	if *d.AttemptsTotal != max || *d.AttemptsTotal > 100000 {
		return fmt.Errorf("%s : attempts_total %d, plus grand rang %d", d.ID, *d.AttemptsTotal, max)
	}
	return nil
}

// Valeur rend la demande en valeur JSON (clés du schéma).
func (d *Demande) Valeur() *Value {
	att := &Value{Kind: KindArray, Arr: []*Value{}}
	for _, a := range d.Attempts {
		att.Arr = append(att.Arr, a.valeur())
	}
	o := vObj("version", vInt(d.Version), "id", vStr(d.ID), "kind", vStr(d.Kind), "subject", d.Subject.valeur(), "deadlines", vEntiers(d.Deadlines), "state", vStr(d.State), "created_at", vStr(d.CreatedAt), "due_at", vStrOuNul(d.DueAt), "attempts", att)
	if d.AttemptsTotal != nil {
		o.Obj = append(o.Obj, Member{Key: "attempts_total", Val: vInt(*d.AttemptsTotal)})
	}
	o.Obj = append(o.Obj, Member{Key: "result", Val: d.Result.valeur()}, Member{Key: "replaced_by", Val: vStrOuNul(d.ReplacedBy)})
	return o
}

// LigneFile rend la ligne NDJSON d'une demande (forme canonique JCS).
func LigneFile(d *Demande) string {
	b, err := Canonique(d.Valeur())
	if err != nil {
		panic(refus("", "forme canonique impossible : %s", err.Error()))
	}
	return string(b)
}

func clesExactes(v *Value, quoi string, cles ...string) error {
	if v == nil || v.Kind != KindObject {
		return fmt.Errorf("%s : objet attendu", quoi)
	}
	for _, m := range v.Obj {
		if !dans(m.Key, cles) {
			return fmt.Errorf("%s : clé inconnue %s", quoi, m.Key)
		}
	}
	for _, k := range cles {
		if !v.Has(k) {
			return fmt.Errorf("%s : clé %s absente", quoi, k)
		}
	}
	return nil
}

// SujetDe lit un sujet.
func SujetDe(v *Value) (*Sujet, error) {
	if err := clesExactes(v, "subject", "kind", "org_id", "journal_id", "period_start", "hash", "tree_size", "declared_at"); err != nil {
		return nil, err
	}
	s := &Sujet{}
	var ok bool
	if s.Kind, ok = chaineDe(v, "kind"); !ok || (s.Kind != "point" && s.Kind != "periode") {
		return nil, fmt.Errorf("subject.kind : point ou periode attendu")
	}
	if s.OrgID, ok = chaineDe(v, "org_id"); !ok {
		return nil, fmt.Errorf("subject.org_id : chaîne attendue")
	}
	if s.JournalID, ok = chaineDe(v, "journal_id"); !ok {
		return nil, fmt.Errorf("subject.journal_id : chaîne attendue")
	}
	if s.PeriodStart, ok = entierDe(v, "period_start"); !ok {
		return nil, fmt.Errorf("subject.period_start : entier attendu")
	}
	if s.Hash, ok = chaineDe(v, "hash"); !ok {
		return nil, fmt.Errorf("subject.hash : chaîne attendue")
	}
	if !estNul(v, "tree_size") {
		n, ok := entierDe(v, "tree_size")
		if !ok {
			return nil, fmt.Errorf("subject.tree_size : entier ou null attendu")
		}
		s.TreeSize = &n
	}
	if s.DeclaredAt, ok = chaineDe(v, "declared_at"); !ok {
		return nil, fmt.Errorf("subject.declared_at : chaîne attendue")
	}
	return s, nil
}

// TentativeDe lit une tentative.
func TentativeDe(v *Value) (*Tentative, error) {
	if err := clesExactes(v, "attempt", "n", "provider", "started_at", "nonce", "correlation_id", "outcome", "error_code", "http_status", "pki_status", "failure_info", "retry_after_s", "next_at", "detail"); err != nil {
		return nil, err
	}
	a := &Tentative{Provider: ptrChaine(v, "provider"), Nonce: ptrChaine(v, "nonce"), ErrorCode: ptrChaine(v, "error_code"), HTTPStatus: ptrEntier(v, "http_status"), PKIStatus: ptrEntier(v, "pki_status"), FailureInfo: ptrChaine(v, "failure_info"), RetryAfterS: ptrEntier(v, "retry_after_s"), NextAt: ptrChaine(v, "next_at")}
	var ok bool
	if a.N, ok = entierDe(v, "n"); !ok {
		return nil, fmt.Errorf("attempt.n : entier attendu")
	}
	if a.StartedAt, ok = chaineDe(v, "started_at"); !ok {
		return nil, fmt.Errorf("attempt.started_at : chaîne attendue")
	}
	if a.CorrelationID, ok = chaineDe(v, "correlation_id"); !ok {
		return nil, fmt.Errorf("attempt.correlation_id : chaîne attendue")
	}
	if a.Outcome, ok = chaineDe(v, "outcome"); !ok {
		return nil, fmt.Errorf("attempt.outcome : chaîne attendue")
	}
	if a.Detail, ok = chaineDe(v, "detail"); !ok {
		return nil, fmt.Errorf("attempt.detail : chaîne attendue")
	}
	return a, nil
}

// DemandeDe lit une demande (ligne de file ou entrée de queue_before).
func DemandeDe(v *Value) (*Demande, error) {
	// attempts_total (révision 0.6) est facultatif à la lecture : une ligne écrite
	// avant la révision ne le porte pas (EX-8.5, règle 7).
	cles := []string{"version", "id", "kind", "subject", "deadlines", "state", "created_at", "due_at", "attempts", "result", "replaced_by"}
	if v != nil && v.Kind == KindObject && v.Has("attempts_total") {
		cles = append(cles, "attempts_total")
	}
	if err := clesExactes(v, "demande", cles...); err != nil {
		return nil, err
	}
	d := &Demande{DueAt: ptrChaine(v, "due_at"), ReplacedBy: ptrChaine(v, "replaced_by")}
	var ok bool
	if v.Has("attempts_total") {
		n, ok := entierDe(v, "attempts_total")
		if !ok || n < 0 || n > 100000 {
			return nil, fmt.Errorf("attempts_total : entier de 0 à 100 000 attendu")
		}
		d.AttemptsTotal = &n
	}
	if d.Version, ok = entierDe(v, "version"); !ok {
		return nil, fmt.Errorf("version : entier attendu")
	}
	if d.ID, ok = chaineDe(v, "id"); !ok {
		return nil, fmt.Errorf("id : chaîne attendue")
	}
	if d.Kind, ok = chaineDe(v, "kind"); !ok || !dans(d.Kind, Sortes) {
		return nil, fmt.Errorf("kind : sorte de CT-5 §8.2 attendue")
	}
	if d.State, ok = chaineDe(v, "state"); !ok || !dans(d.State, Etats) {
		return nil, fmt.Errorf("state : état d'EX-8.3 attendu")
	}
	if d.CreatedAt, ok = chaineDe(v, "created_at"); !ok {
		return nil, fmt.Errorf("created_at : chaîne attendue")
	}
	var err error
	if d.Subject, err = SujetDe(v.Get("subject")); err != nil {
		return nil, err
	}
	dl := v.Get("deadlines")
	if dl == nil || dl.Kind != KindArray {
		return nil, fmt.Errorf("deadlines : liste attendue")
	}
	d.Deadlines = entiersDe(v, "deadlines")
	if len(d.Deadlines) != len(dl.Arr) {
		return nil, fmt.Errorf("deadlines : entiers attendus")
	}
	at := v.Get("attempts")
	if at == nil || at.Kind != KindArray {
		return nil, fmt.Errorf("attempts : liste attendue")
	}
	if len(at.Arr) > 100000 {
		return nil, fmt.Errorf("attempts : au plus 100 000 éléments")
	}
	d.Attempts = []*Tentative{}
	for _, x := range at.Arr {
		a, err := TentativeDe(x)
		if err != nil {
			return nil, err
		}
		d.Attempts = append(d.Attempts, a)
	}
	if !estNul(v, "result") {
		r := v.Get("result")
		if err := clesExactes(r, "result", "sha256", "size", "provider", "obtained_at", "bound"); err != nil {
			return nil, err
		}
		res := &Resultat{Provider: ptrChaine(r, "provider"), Bound: ptrChaine(r, "bound")}
		if res.SHA256, ok = chaineDe(r, "sha256"); !ok {
			return nil, fmt.Errorf("result.sha256 : chaîne attendue")
		}
		if res.Size, ok = entierDe(r, "size"); !ok {
			return nil, fmt.Errorf("result.size : entier attendu")
		}
		if res.ObtainedAt, ok = chaineDe(r, "obtained_at"); !ok {
			return nil, fmt.Errorf("result.obtained_at : chaîne attendue")
		}
		d.Result = res
	}
	return d, nil
}

// FileLue est le résultat de la relecture d'une file NDJSON.
type FileLue struct {
	Demandes []*Demande
	Lignes   int
	Tronquee bool
	Erreurs  []string
}

// LireFile relit une file NDJSON (EX-8.5, règle 3) : les lignes sont
// rejouées dans l'ordre, la dernière ligne d'un id fait foi, une ligne
// finale tronquée est ignorée et signalée, jamais réparée.
func LireFile(texte string) *FileLue {
	morceaux := strings.Split(texte, "\n")
	derniere := morceaux[len(morceaux)-1]
	morceaux = morceaux[:len(morceaux)-1]
	r := &FileLue{Erreurs: []string{}}
	parID := map[string]*Demande{}
	var ordre []string
	admettre := func(ligne string, i int) bool {
		v, err := ParseJSON([]byte(ligne))
		if err != nil {
			return false
		}
		d, err := DemandeDe(v)
		if err != nil {
			r.Erreurs = append(r.Erreurs, fmt.Sprintf("ligne %d : demande mal formée (%s)", i+1, err.Error()))
			return true
		}
		if d.ID != d.Kind+":"+d.Subject.Hash {
			r.Erreurs = append(r.Erreurs, fmt.Sprintf("ligne %d : id %s différent de <kind>:<hash>", i+1, d.ID))
		}
		if prec, ok := parID[d.ID]; ok && EtatsFinaux[prec.State] && prec.State != d.State {
			r.Erreurs = append(r.Erreurs, fmt.Sprintf("ligne %d : %s déjà dans l'état final %s", i+1, d.ID, prec.State))
		}
		if _, ok := parID[d.ID]; !ok {
			ordre = append(ordre, d.ID)
		}
		parID[d.ID] = d
		return true
	}
	for i, ligne := range morceaux {
		if ligne == "" {
			continue
		}
		r.Lignes++
		if !admettre(ligne, i) {
			r.Erreurs = append(r.Erreurs, fmt.Sprintf("ligne %d : JSON illisible", i+1))
		}
	}
	if derniere != "" {
		r.Lignes++
		if !admettre(derniere, len(morceaux)) {
			r.Tronquee = true
		}
	}
	for _, id := range ordre {
		r.Demandes = append(r.Demandes, parID[id])
	}
	return r
}

// trierFile range des demandes par (created_at, id).
func trierFile(l []*Demande) {
	sort.SliceStable(l, func(i, j int) bool {
		if l[i].CreatedAt != l[j].CreatedAt {
			return l[i].CreatedAt < l[j].CreatedAt
		}
		return l[i].ID < l[j].ID
	})
}
