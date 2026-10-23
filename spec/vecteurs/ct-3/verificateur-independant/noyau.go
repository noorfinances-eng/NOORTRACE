// Vérification d'une remise par le noyau avant scellement (CT-3 9.4,
// EX-9.11 ; CT-2 version 0.3, EX-7.5) : SG-1 à SG-7, dans cet ordre, la
// raison de la première vérification en échec ; à l'intérieur d'une
// vérification, les raisons dans l'ordre de la table. SG-7 (séparation des
// tâches) est normative depuis la version 0.3 de CT-2.

package main

import (
	"regexp"
	"strings"
)

// RetenueNoyau est un événement retenue du journal tel que le noyau le voit
// (annexe A.7) : seq, policy.ticket, hash, ts et delegation.launched_by.
type RetenueNoyau struct {
	Seq        int64
	Ticket     string
	Hash       string
	Ts         Instant
	LaunchedBy string
}

// Separation est le membre separation d'une politique d'approbation
// (CT-3 10.1) : self_approval et identities.
type Separation struct {
	AutoApprobation string
	Identites       []Identite
}

// ContexteNoyau est le journal tel que le noyau le voit (annexe A.7).
type ContexteNoyau struct {
	OrgID, JournalID string
	Retenues         []RetenueNoyau
	Decides          map[string]bool
	ExpireAfterMs    int64
	// Separation est la séparation des tâches de la politique de la
	// version du ticket (SG-7) ; nil si le contexte ne la porte pas.
	Separation *Separation
	EcritureA  Instant
}

// LireContexteNoyau lit le membre context d'un cas de decisions/.
func LireContexteNoyau(v *Value) (*ContexteNoyau, error) {
	c := &ContexteNoyau{OrgID: v.Get("org_id").S(), JournalID: v.Get("journal_id").S(), Decides: map[string]bool{}}
	for _, r := range v.Get("retained").Arr {
		ts, err := LireInstant(r.Get("ts").S())
		if err != nil {
			return nil, err
		}
		seq, _ := EntierJSON(r.Get("seq"))
		c.Retenues = append(c.Retenues, RetenueNoyau{Seq: seq, Ticket: r.Get("ticket").S(), Hash: r.Get("hash").S(), Ts: ts, LaunchedBy: r.Get("launched_by").S()})
	}
	for _, d := range v.Get("decided").Arr {
		c.Decides[d.Get("ticket").S()] = true
	}
	c.ExpireAfterMs, _ = EntierJSON(v.Get("expire_after_ms"))
	if sep := v.Get("separation"); sep != nil && sep.Kind == KindObject {
		s := &Separation{AutoApprobation: sep.Get("self_approval").S()}
		for _, id := range sep.Get("identities").Arr {
			s.Identites = append(s.Identites, Identite{LaunchedBy: id.Get("launched_by").S(), Adresses: chaines(id.Get("addresses"))})
		}
		c.Separation = s
	}
	w, err := LireInstant(v.Get("write_at").S())
	if err != nil {
		return nil, err
	}
	c.EcritureA = w
	return c, nil
}

var reSourceEX88 = regexp.MustCompile(`^(CuratorSet c=[0-9]{1,20} r=0x[0-9a-f]{40} s=0x[0-9a-f]{40} h=[0-9]{1,20}\.\.[0-9]{1,20} b=0x[0-9a-f]{64}( repli)?|jeu statique de la politique .{1,128})$`)

// VerificationSG est une vérification de la table d'EX-9.11 : son
// identifiant et la fonction qui rend la raison de refus, ou "".
type VerificationSG struct {
	ID       string
	Verifier func(*Schemas, *ContexteNoyau, *Value) string
}

// VerificationsSG est la table d'EX-9.11 (CT-2 EX-7.5), dans l'ordre.
var VerificationsSG = []VerificationSG{
	{"SG-1", sg1}, {"SG-2", sg2}, {"SG-3", sg3}, {"SG-4", sg4},
	{"SG-5", sg5}, {"SG-6", sg6}, {"SG-7", sg7},
}

// VerifierRemise applique SG-1 à SG-7 et rend (« scelle », « ») ou
// (« refuse », raison de la première vérification en échec).
func VerifierRemise(sch *Schemas, c *ContexteNoyau, rem *Value) (string, string) {
	for _, v := range VerificationsSG {
		if r := v.Verifier(sch, c, rem); r != "" {
			return "refuse", r
		}
	}
	return "scelle", ""
}

// EchecsRemise rend, pour chaque vérification évaluée seule, la raison de
// son échec (vérifications réussies absentes) : sert à reconnaître les cas
// d'ordre d'EX-A.8, où deux vérifications voisines échouent.
func EchecsRemise(sch *Schemas, c *ContexteNoyau, rem *Value) map[string]string {
	out := map[string]string{}
	for _, v := range VerificationsSG {
		if r := v.Verifier(sch, c, rem); r != "" {
			out[v.ID] = r
		}
	}
	return out
}

// retenueDeLaDemande rend l'événement retenue du ticket dont le hash est
// approval.request_hash (SG-2), ou nil.
func retenueDeLaDemande(c *ContexteNoyau, rem *Value) *RetenueNoyau {
	ticket := rem.Get("ticket").S()
	rh := rem.Get("approval").Get("request_hash").S()
	for i := range c.Retenues {
		if r := &c.Retenues[i]; r.Ticket == ticket && r.Hash == rh {
			return r
		}
	}
	return nil
}

// SG-1 : forme de $defs/remise ; approval sans at ; approval.ticket égal au
// ticket de la remise ; remise_id de la forme <ticket>/<n> ; source d'EX-8.8.
func sg1(sch *Schemas, _ *ContexteNoyau, rem *Value) string {
	if errs := sch.Valider(RefTicket+"#/$defs/remise", rem); len(errs) > 0 {
		return "remise_mal_formee"
	}
	ap := rem.Get("approval")
	ticket := rem.Get("ticket").S()
	if ap.Has("at") || ap.Get("ticket").S() != ticket || !strings.HasPrefix(rem.Get("remise_id").S(), ticket+"/") || !reSourceEX88.MatchString(rem.Get("approver_set").Get("source").S()) {
		return "remise_mal_formee"
	}
	return ""
}

// SG-2 : un événement retenue porte policy.ticket = ticket, et l'un d'eux a
// pour hash request_hash.
func sg2(_ *Schemas, c *ContexteNoyau, rem *Value) string {
	ticket := rem.Get("ticket").S()
	trouve := false
	for _, r := range c.Retenues {
		if r.Ticket == ticket {
			trouve = true
		}
	}
	if !trouve {
		return "ticket_inconnu"
	}
	if retenueDeLaDemande(c, rem) == nil {
		return "request_hash_different"
	}
	return ""
}

// SG-3 : aucune décision scellée pour ce ticket.
func sg3(_ *Schemas, c *ContexteNoyau, rem *Value) string {
	if c.Decides[rem.Get("ticket").S()] {
		return "ticket_deja_decide"
	}
	return ""
}

// SG-4 : pour approuve et refuse, l'instant d'écriture strictement antérieur
// à request_ts + E (request_ts : ts de la retenue de hash request_hash).
func sg4(_ *Schemas, c *ContexteNoyau, rem *Value) string {
	dec := rem.Get("approval").Get("decision").S()
	if dec != "approuve" && dec != "refuse" {
		return ""
	}
	r := retenueDeLaDemande(c, rem)
	if r == nil {
		return "" // relève de SG-2
	}
	if !(c.EcritureA < r.Ts+Instant(c.ExpireAfterMs)) {
		return "echeance_depassee"
	}
	return ""
}

// SG-5 : E-5 et E-9 de CT-1 sur le A de la remise.
func sg5(_ *Schemas, c *ContexteNoyau, rem *Value) string {
	ap := rem.Get("approval")
	appr := chaines(ap.Get("approvers"))
	sigs := chaines(ap.Get("signatures"))
	if len(appr) != len(sigs) {
		return "signature_invalide"
	}
	a := ObjetA(ap.Get("decision").S(), c.JournalID, c.OrgID, ap.Get("request_hash").S(), rem.Get("ticket").S())
	for i := range appr {
		s, err := DecoderSignature(sigs[i])
		if err != nil || !s.Canonique() {
			return "signature_invalide"
		}
		adr, err := AdresseVote(a, s)
		if err != nil || adr != appr[i] {
			return "signature_invalide"
		}
	}
	return ""
}

// SG-6 : A-3 de CT-1, raisons dans l'ordre de la table.
func sg6(_ *Schemas, _ *ContexteNoyau, rem *Value) string {
	ap := rem.Get("approval")
	dec := ap.Get("decision").S()
	appr := chaines(ap.Get("approvers"))
	js := rem.Get("approver_set")
	membres := chaines(js.Get("members"))
	vus := map[string]bool{}
	for _, x := range appr {
		if vus[x] {
			return "approbateur_double"
		}
		vus[x] = true
	}
	for _, x := range appr {
		if !contient(membres, x) {
			return "approbateur_hors_jeu"
		}
	}
	rq, _ := EntierJSON(ap.Get("threshold").Get("required"))
	sz, _ := EntierJSON(ap.Get("threshold").Get("size"))
	jrq, _ := EntierJSON(js.Get("threshold").Get("required"))
	jsz, _ := EntierJSON(js.Get("threshold").Get("size"))
	if rq != jrq || sz != jsz || !(rq <= sz) || sz != int64(len(membres)) {
		return "seuil_different_du_jeu"
	}
	if dec == "expire" && len(appr) > 0 {
		return "expire_avec_signatures"
	}
	if (dec == "approuve" || dec == "refuse") && int64(len(appr)) < rq {
		return "seuil_non_atteint"
	}
	return ""
}

// SG-7 : séparation des tâches (CT-2 EX-7.5, CT-3 EX-9.11) : sous
// separation.self_approval « interdite », aucune adresse de approvers n'est
// une adresse de l'entrée de separation.identities dont launched_by est égal,
// octet pour octet, au delegation.launched_by de l'événement retenue. Les
// adresses sont en hexadécimal minuscule (CT-1 §3, motif adresse de
// politique-approbation-v0) : l'égalité des chaînes est l'égalité des
// adresses.
func sg7(_ *Schemas, c *ContexteNoyau, rem *Value) string {
	if c.Separation == nil || c.Separation.AutoApprobation != "interdite" {
		return ""
	}
	r := retenueDeLaDemande(c, rem)
	if r == nil {
		return "" // relève de SG-2
	}
	var adresses []string
	for _, id := range c.Separation.Identites {
		if id.LaunchedBy == r.LaunchedBy {
			adresses = append(adresses, id.Adresses...)
		}
	}
	for _, x := range chaines(rem.Get("approval").Get("approvers")) {
		if contient(adresses, x) {
			return "auto_approbation"
		}
	}
	return ""
}
