// Vérification d'une remise par le noyau avant scellement (CT-3 9.4,
// EX-9.11) : SG-1 à SG-6, dans cet ordre, la raison de la première
// vérification en échec ; à l'intérieur d'une vérification, les raisons
// dans l'ordre de la table.

package main

import (
	"regexp"
	"strings"
)

// ContexteNoyau est le journal tel que le noyau le voit (annexe A.7).
type ContexteNoyau struct {
	OrgID, JournalID string
	Retenues         []struct {
		Seq    int64
		Ticket string
		Hash   string
		Ts     Instant
	}
	Decides       map[string]bool
	ExpireAfterMs int64
	EcritureA     Instant
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
		c.Retenues = append(c.Retenues, struct {
			Seq    int64
			Ticket string
			Hash   string
			Ts     Instant
		}{seq, r.Get("ticket").S(), r.Get("hash").S(), ts})
	}
	for _, d := range v.Get("decided").Arr {
		c.Decides[d.Get("ticket").S()] = true
	}
	c.ExpireAfterMs, _ = EntierJSON(v.Get("expire_after_ms"))
	w, err := LireInstant(v.Get("write_at").S())
	if err != nil {
		return nil, err
	}
	c.EcritureA = w
	return c, nil
}

var reSourceEX88 = regexp.MustCompile(`^(CuratorSet c=[0-9]{1,20} r=0x[0-9a-f]{40} s=0x[0-9a-f]{40} h=[0-9]{1,20}\.\.[0-9]{1,20} b=0x[0-9a-f]{64}( repli)?|jeu statique de la politique .{1,128})$`)

// VerifierRemise applique SG-1 à SG-6 et rend (« scelle », « ») ou
// (« refuse », raison).
func VerifierRemise(sch *Schemas, c *ContexteNoyau, rem *Value) (string, string) {
	// SG-1 : forme de $defs/remise ; approval sans at ; approval.ticket égal
	// au ticket de la remise ; remise_id de la forme <ticket>/<n> ; source
	// d'EX-8.8.
	if errs := sch.Valider(RefTicket+"#/$defs/remise", rem); len(errs) > 0 {
		return "refuse", "remise_mal_formee"
	}
	ap := rem.Get("approval")
	ticket := rem.Get("ticket").S()
	if ap.Has("at") || ap.Get("ticket").S() != ticket || !strings.HasPrefix(rem.Get("remise_id").S(), ticket+"/") || !reSourceEX88.MatchString(rem.Get("approver_set").Get("source").S()) {
		return "refuse", "remise_mal_formee"
	}
	// SG-2 : un événement retenue porte policy.ticket = ticket, et l'un
	// d'eux a pour hash request_hash.
	rh := ap.Get("request_hash").S()
	trouve, egal := false, false
	var ts Instant
	for _, r := range c.Retenues {
		if r.Ticket == ticket {
			trouve = true
			if r.Hash == rh {
				egal, ts = true, r.Ts
			}
		}
	}
	if !trouve {
		return "refuse", "ticket_inconnu"
	}
	if !egal {
		return "refuse", "request_hash_different"
	}
	// SG-3 : aucune décision scellée pour ce ticket.
	if c.Decides[ticket] {
		return "refuse", "ticket_deja_decide"
	}
	dec := ap.Get("decision").S()
	// SG-4 : approval.at strictement antérieur à request_ts + E.
	if (dec == "approuve" || dec == "refuse") && !(c.EcritureA < ts+Instant(c.ExpireAfterMs)) {
		return "refuse", "echeance_depassee"
	}
	// SG-5 : E-5 et E-9 de CT-1 sur le A de la remise.
	appr := chaines(ap.Get("approvers"))
	sigs := chaines(ap.Get("signatures"))
	if len(appr) != len(sigs) {
		return "refuse", "signature_invalide"
	}
	a := ObjetA(dec, c.JournalID, c.OrgID, rh, ticket)
	for i := range appr {
		s, err := DecoderSignature(sigs[i])
		if err != nil || !s.Canonique() {
			return "refuse", "signature_invalide"
		}
		adr, err := AdresseVote(a, s)
		if err != nil || adr != appr[i] {
			return "refuse", "signature_invalide"
		}
	}
	// SG-6 : A-3 de CT-1.
	js := rem.Get("approver_set")
	membres := chaines(js.Get("members"))
	vus := map[string]bool{}
	for _, x := range appr {
		if vus[x] {
			return "refuse", "approbateur_double"
		}
		vus[x] = true
	}
	for _, x := range appr {
		if !contient(membres, x) {
			return "refuse", "approbateur_hors_jeu"
		}
	}
	rq, _ := EntierJSON(ap.Get("threshold").Get("required"))
	sz, _ := EntierJSON(ap.Get("threshold").Get("size"))
	jrq, _ := EntierJSON(js.Get("threshold").Get("required"))
	jsz, _ := EntierJSON(js.Get("threshold").Get("size"))
	if rq != jrq || sz != jsz || !(rq <= sz) || sz != int64(len(membres)) {
		return "refuse", "seuil_different_du_jeu"
	}
	if dec == "expire" && len(appr) > 0 {
		return "refuse", "expire_avec_signatures"
	}
	if (dec == "approuve" || dec == "refuse") && int64(len(appr)) < rq {
		return "refuse", "seuil_non_atteint"
	}
	return "scelle", ""
}
