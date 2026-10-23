// Évaluation (CT-3 sections 4 à 6) : SELECTIONNE (EX-4.3), RESOUDRE
// (EX-4.4), NUMERIQUE et COMPARER (EX-4.5, EX-4.6), PREDICAT (table 4.9),
// VALEUR (EX-4.8), ISSUE (EX-6.2), EVALUER (6.2), chaîne policy.rule
// (EX-6.4), fenêtres (EX-5.2 à EX-5.6) et CANDIDATS (EX-4.11).

package main

import (
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

// Verite est une valeur de la logique à trois valeurs de Kleene (4.10).
type Verite int

// VRAI, FAUX et INDETERMINE (CT-3 §0).
const (
	FAUX Verite = iota
	VRAI
	INDETERMINE
)

func (v Verite) String() string {
	switch v {
	case VRAI:
		return "VRAI"
	case FAUX:
		return "FAUX"
	}
	return "INDETERMINE"
}

// Selectionne applique EX-4.3 : nom exact, octet pour octet ; préfixe p*
// dont p est un préfixe du nom ; * seul : tout nom. Aucun autre joker.
func Selectionne(selecteurs []string, nom string) bool {
	for _, s := range selecteurs {
		if strings.HasSuffix(s, "*") {
			if strings.HasPrefix(nom, s[:len(s)-1]) {
				return true
			}
		} else if s == nom {
			return true
		}
	}
	return false
}

var reIndice = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})$`)

// Resoudre applique EX-4.4 sur R ; rend la valeur désignée, ou nil si le
// pointeur n'est pas résolu.
func Resoudre(p string, r *Value) *Value {
	if p == "" {
		return r
	}
	x := r
	for _, j := range strings.Split(p[1:], "/") {
		j = strings.ReplaceAll(j, "~1", "/")
		j = strings.ReplaceAll(j, "~0", "~")
		switch {
		case x.Kind == KindObject && x.Get(j) != nil:
			x = x.Get(j)
		case x.Kind == KindArray && reIndice.MatchString(j):
			n, _ := strconv.Atoi(j)
			if n >= len(x.Arr) {
				return nil
			}
			x = x.Arr[n]
		default:
			return nil
		}
	}
	return x
}

// Decimal est une valeur numérique (m, e) : m × 10^(−e) (EX-4.6).
type Decimal struct {
	M *big.Int
	E int
}

var reDecimal = regexp.MustCompile(`^-?(0|[1-9][0-9]{0,29})(\.[0-9]{1,18})?$`)

var entierSurMax = big.NewInt(EntierSurMax)

// LireDecimal lit une chaîne de la grammaire D (EX-4.6).
func LireDecimal(s string) (Decimal, bool) {
	if !reDecimal.MatchString(s) {
		return Decimal{}, false
	}
	e := 0
	chiffres := s
	if i := strings.IndexByte(s, '.'); i >= 0 {
		e = len(s) - i - 1
		chiffres = s[:i] + s[i+1:]
	}
	m, ok := new(big.Int).SetString(chiffres, 10)
	if !ok {
		return Decimal{}, false
	}
	return Decimal{M: m, E: e}, true
}

// Numerique applique EX-4.5 : nombre JSON dont la valeur mathématique est
// un entier de [-(2^53-1), 2^53-1] (lu depuis son texte, sans flottant), ou
// chaîne D.
func Numerique(v *Value) (Decimal, bool) {
	switch v.Kind {
	case KindNumber:
		r, ok := RationnelDe(v.Num)
		if !ok || !r.IsInt() {
			return Decimal{}, false
		}
		m := new(big.Int).Set(r.Num())
		if new(big.Int).Abs(m).Cmp(entierSurMax) > 0 {
			return Decimal{}, false
		}
		return Decimal{M: m, E: 0}, true
	case KindString:
		return LireDecimal(v.Str)
	}
	return Decimal{}, false
}

// Comparer compare m1 × 10^(E−e1) et m2 × 10^(E−e2), E = max(e1, e2).
func Comparer(a, b Decimal) int {
	e := a.E
	if b.E > e {
		e = b.E
	}
	dix := big.NewInt(10)
	x := new(big.Int).Mul(a.M, new(big.Int).Exp(dix, big.NewInt(int64(e-a.E)), nil))
	y := new(big.Int).Mul(b.M, new(big.Int).Exp(dix, big.NewInt(int64(e-b.E)), nil))
	return x.Cmp(y)
}

// Observateur reçoit les faits notables d'une évaluation (couverture de
// l'épreuve d'acceptation, EX-A.4) ; il peut être nil.
type Observateur interface {
	PointeurNonResolu(path string)
	TypeDifferent(path, op string)
	EgaliteNumerique(path, op string)
}

// Predicat applique la table de 4.9.
func Predicat(p *Value, r *Value, obs Observateur) Verite {
	path := p.Get("path").S()
	op := p.Get("op").S()
	val := p.Get("value")
	x := Resoudre(path, r)
	if op == "existe" {
		if x == nil {
			if obs != nil {
				obs.PointeurNonResolu(path)
			}
			return FAUX
		}
		return VRAI
	}
	if x == nil {
		if obs != nil {
			obs.PointeurNonResolu(path)
		}
		return INDETERMINE
	}
	typeDiff := func() Verite {
		if obs != nil {
			obs.TypeDifferent(path, op)
		}
		return INDETERMINE
	}
	vrai := func(b bool) Verite {
		if b {
			return VRAI
		}
		return FAUX
	}
	switch op {
	case "egal":
		if x.Kind != val.Kind || (x.Kind != KindString && x.Kind != KindBool) {
			return typeDiff()
		}
		if x.Kind == KindString {
			return vrai(x.Str == val.Str)
		}
		return vrai(x.Bool == val.Bool)
	case "dans":
		if x.Kind != KindString {
			return typeDiff()
		}
		for _, e := range val.Arr {
			if e.Str == x.Str {
				return VRAI
			}
		}
		return FAUX
	case "commence_par":
		if x.Kind != KindString {
			return typeDiff()
		}
		return vrai(strings.HasPrefix(x.Str, val.Str))
	case "finit_par":
		if x.Kind != KindString {
			return typeDiff()
		}
		return vrai(strings.HasSuffix(x.Str, val.Str))
	case "egal_numerique", "strictement_superieur", "superieur_ou_egal", "strictement_inferieur", "inferieur_ou_egal":
		a, ok := Numerique(x)
		if !ok {
			return typeDiff()
		}
		b, ok := LireDecimal(val.S())
		if !ok {
			return INDETERMINE // littéral hors grammaire : document invalide (schéma)
		}
		c := Comparer(a, b)
		if c == 0 && obs != nil {
			obs.EgaliteNumerique(path, op)
		}
		switch op {
		case "egal_numerique":
			return vrai(c == 0)
		case "strictement_superieur":
			return vrai(c > 0)
		case "superieur_ou_egal":
			return vrai(c >= 0)
		case "strictement_inferieur":
			return vrai(c < 0)
		default:
			return vrai(c <= 0)
		}
	}
	return INDETERMINE
}

// ValeurCondition applique EX-4.8 (récursion sur all, any, none).
func ValeurCondition(c *Value, r *Value, obs Observateur) Verite {
	k, l := combinaison(c)
	if l == nil {
		return Predicat(c, r, obs)
	}
	nv, nf, ni := 0, 0, 0
	for _, e := range l.Arr {
		switch ValeurCondition(e, r, obs) {
		case VRAI:
			nv++
		case FAUX:
			nf++
		default:
			ni++
		}
	}
	switch k {
	case "all":
		if nf > 0 {
			return FAUX
		}
		if ni > 0 {
			return INDETERMINE
		}
		return VRAI
	case "any":
		if nv > 0 {
			return VRAI
		}
		if ni > 0 {
			return INDETERMINE
		}
		return FAUX
	default: // none
		if nv > 0 {
			return FAUX
		}
		if ni > 0 {
			return INDETERMINE
		}
		return VRAI
	}
}

// Et est le all de EX-4.8 à deux éléments.
func Et(a, b Verite) Verite {
	if a == FAUX || b == FAUX {
		return FAUX
	}
	if a == INDETERMINE || b == INDETERMINE {
		return INDETERMINE
	}
	return VRAI
}

// Portee est la clé K d'une fenêtre (EX-5.2) : version, règle, outil
// annoncé, demandeur, valeurs désignées.
type Portee struct {
	PolicyVersion string
	Regle         string
	Outil         string
	LaunchedBy    string
	Valeurs       []string
}

// Egale compare deux portées.
func (k Portee) Egale(o Portee) bool {
	if k.PolicyVersion != o.PolicyVersion || k.Regle != o.Regle || k.Outil != o.Outil || k.LaunchedBy != o.LaunchedBy || len(k.Valeurs) != len(o.Valeurs) {
		return false
	}
	for i := range k.Valeurs {
		if k.Valeurs[i] != o.Valeurs[i] {
			return false
		}
	}
	return true
}

// JSON rend $defs/portee.
func (k Portee) JSON() *Value {
	return Objet("policy_version", Chaine(k.PolicyVersion), "rule", Chaine(k.Regle), "tool", Chaine(k.Outil),
		"launched_by", Chaine(k.LaunchedBy), "values", TableauChaines(k.Valeurs))
}

// LirePortee lit $defs/portee.
func LirePortee(v *Value) Portee {
	return Portee{PolicyVersion: v.Get("policy_version").S(), Regle: v.Get("rule").S(), Outil: v.Get("tool").S(),
		LaunchedBy: v.Get("launched_by").S(), Valeurs: chaines(v.Get("values"))}
}

// Fenetre est une fenêtre ouverte W(K) ($defs/fenetre_ouverte).
type Fenetre struct {
	Portee  Portee
	Debut   Instant
	Fin     Instant
	Restant int64
	Ticket  string
}

// JSON rend $defs/fenetre_ouverte.
func (f *Fenetre) JSON() *Value {
	return Objet("scope", f.Portee.JSON(), "start", Chaine(f.Debut.String()), "end", Chaine(f.Fin.String()),
		"remaining", Entier(f.Restant), "ticket", Chaine(f.Ticket))
}

// LireFenetre lit $defs/fenetre_ouverte.
func LireFenetre(v *Value) (*Fenetre, error) {
	d, err := LireInstant(v.Get("start").S())
	if err != nil {
		return nil, err
	}
	f, err := LireInstant(v.Get("end").S())
	if err != nil {
		return nil, err
	}
	r, _ := EntierJSON(v.Get("remaining"))
	return &Fenetre{Portee: LirePortee(v.Get("scope")), Debut: d, Fin: f, Restant: r, Ticket: v.Get("ticket").S()}, nil
}

// Ouverture est la fenêtre qu'ouvrira un ticket ouvrant ($defs/ouverture).
type Ouverture struct {
	Portee    Portee
	DureeMs   int64
	MaxAppels int64
}

// JSON rend $defs/ouverture.
func (o *Ouverture) JSON() *Value {
	if o == nil {
		return Nul()
	}
	return Objet("scope", o.Portee.JSON(), "duration_ms", Entier(o.DureeMs), "max_calls", Entier(o.MaxAppels))
}

// LireOuverture lit $defs/ouverture ou null.
func LireOuverture(v *Value) *Ouverture {
	if v == nil || v.IsNull() {
		return nil
	}
	d, _ := EntierJSON(v.Get("duration_ms"))
	m, _ := EntierJSON(v.Get("max_calls"))
	return &Ouverture{Portee: LirePortee(v.Get("scope")), DureeMs: d, MaxAppels: m}
}

// Demande est ce que l'évaluation lit d'une requête evaluer (EX-3.5).
type Demande struct {
	Outil      string
	Arguments  *Value
	LaunchedBy string
}

// DemandeDe extrait la demande d'une requête evaluer (12.3).
func DemandeDe(req *Value) Demande {
	args := req.Get("arguments")
	if args == nil {
		args = Objet()
	}
	return Demande{Outil: req.Get("tool_announced").S(), Arguments: args, LaunchedBy: req.Get("delegation").Get("launched_by").S()}
}

// Sortie est la sortie d'EVALUER : $defs/evaluation de ticket-v0, plus la
// fenêtre consommée (indice dans F, −1 sinon).
type Sortie struct {
	Regle     string
	Decision  string
	ContestMs *int64
	Ouverture *Ouverture
	Consommee int
}

type issue struct {
	rang   int
	indice int
	dec    string
	marque string
	fen    int // fenêtre qui a donné l'issue de rang 2
	portee *Portee
}

// portee rend la portée de d pour une règle fenetre (EX-5.2), ou nil si
// elle est indéterminée.
func porteeDe(pv string, r *Regle, d Demande, racine *Value) *Portee {
	k := &Portee{PolicyVersion: pv, Regle: r.Nom, Outil: d.Outil, LaunchedBy: d.LaunchedBy, Valeurs: []string{}}
	for _, p := range r.Fenetre.MemesArguments {
		x := Resoudre(p, racine)
		if x == nil || x.Kind != KindString {
			return nil
		}
		k.Valeurs = append(k.Valeurs, x.Str)
	}
	return k
}

// Evaluer applique l'algorithme EVALUER de 6.2. pv est la policy_version en
// vigueur ; F n'est pas modifié (la fenêtre consommée est rendue par son
// indice).
func Evaluer(p *Politique, pv string, d Demande, f []*Fenetre, t Instant, obs Observateur) Sortie {
	racine := Objet("arguments", d.Arguments)
	var c []issue
	for i := range p.Regles {
		r := &p.Regles[i]
		if !Selectionne(r.Outils, d.Outil) {
			continue
		}
		v := VRAI
		if r.Quand != nil {
			v = ValeurCondition(r.Quand, racine, obs)
		}
		var k *Portee
		if r.Niveau == "fenetre" {
			k = porteeDe(pv, r, d, racine)
			det := VRAI
			if k == nil {
				det = INDETERMINE
			}
			v = Et(v, det)
		}
		if v == FAUX {
			continue
		}
		is := issue{indice: i, fen: -1, portee: k}
		switch {
		case r.Niveau == "automatique" && r.Decision == "autorise":
			if v == VRAI {
				is.rang, is.dec = 1, "autorise"
			}
		case r.Niveau == "automatique":
			is.rang, is.dec = 5, "refuse"
			if v == INDETERMINE {
				is.marque = " [indetermine]"
			}
		case r.Niveau == "fenetre":
			if v == INDETERMINE {
				is.rang, is.dec, is.marque = 3, "a_approuver", " [indetermine]"
			} else {
				is.rang, is.dec = 3, "a_approuver"
				for j, w := range f {
					// EX-5.5 : règle de K, portée K, debut ≤ t < fin, restant ≥ 1
					if w.Portee.Egale(*k) && w.Debut <= t && t < w.Fin && w.Restant >= 1 {
						is.rang, is.dec = 2, "autorise"
						is.marque = fmt.Sprintf(" [fenetre %s %s]", w.Ticket, w.Fin)
						is.fen = j
						break
					}
				}
			}
		default: // revue
			is.rang, is.dec = 4, "a_approuver"
			if v == INDETERMINE {
				is.marque = " [indetermine]"
			}
		}
		if is.rang > 0 {
			c = append(c, is)
		}
	}
	s := Sortie{Consommee: -1}
	if len(c) == 0 {
		s.Regle = p.Defaut.Nom
		if p.Defaut.Niveau == "automatique" {
			s.Decision = p.Defaut.Decision
		} else {
			s.Decision = "a_approuver"
			s.ContestMs = p.Defaut.ContestMs
		}
		return s
	}
	best := c[0]
	for _, is := range c[1:] {
		if is.rang > best.rang {
			best = is
		}
	}
	r := &p.Regles[best.indice]
	s.Regle = r.Nom + best.marque
	s.Decision = best.dec
	if best.rang == 2 {
		s.Consommee = best.fen
	}
	if s.Decision == "a_approuver" {
		s.ContestMs = r.ContestMs
		if best.rang == 3 && best.marque == "" {
			s.Ouverture = &Ouverture{Portee: *best.portee, DureeMs: r.Fenetre.DureeMs, MaxAppels: r.Fenetre.MaxAppels}
		}
	}
	return s
}

// Candidats applique EX-4.11 : noms de L, dans l'ordre de L, sans doublon,
// pour lesquels une règle qui sélectionne le nom a le niveau fenetre ou
// revue, ou automatique avec refuse ; ou la règle par défaut n'est pas
// (automatique, autorise) et aucune règle à when nul ne sélectionne le nom.
func Candidats(p *Politique, l []string) []string {
	out := []string{}
	vus := map[string]bool{}
	defautAutorise := p.Defaut.Niveau == "automatique" && p.Defaut.Decision == "autorise"
	for _, nom := range l {
		if vus[nom] {
			continue
		}
		vus[nom] = true
		cond1, inconditionnelle := false, false
		for _, r := range p.Regles {
			if !Selectionne(r.Outils, nom) {
				continue
			}
			if r.Niveau == "fenetre" || r.Niveau == "revue" || (r.Niveau == "automatique" && r.Decision == "refuse") {
				cond1 = true
			}
			if r.Quand == nil {
				inconditionnelle = true
			}
		}
		if cond1 || (!defautAutorise && !inconditionnelle) {
			out = append(out, nom)
		}
	}
	return out
}
