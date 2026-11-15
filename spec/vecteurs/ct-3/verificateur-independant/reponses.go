// Vérification d'une réponse d'evaluer par le noyau (CT-2 EX-7.16, révision
// 0.8 ; CT-3 §12.3, EX-12.6, révision 0.5) et famille reponses-evaluer/ :
// huit membres, forme de $defs/reponse_evaluer, l'une des sept combinaisons
// de la table d'EX-7.16, couple (policy_version, policy_sha256) d'un charger
// que le noyau a lui-même émis pour la version attendue, approval d'une
// décision scellée égal à celui du noyau (RL-1), puis l'action du mandataire
// en mode erreur (section 11).

package main

import (
	"unicode/utf8"
)

// FamReponses est la famille des réponses d'evaluer jugées par le noyau.
const FamReponses = "reponses-evaluer"

// RaisonPolitiqueNonEpinglee est la raison nommée par CT-2 EX-7.16
// (révision 0.8) : la réponse n'est pas rendue sous une politique que le
// noyau a lui-même épinglée.
const RaisonPolitiqueNonEpinglee = "politique_non_epinglee"

// membresReponse sont les neuf membres de la réponse d'evaluer (12.3).
var membresReponse = []string{"rule", "decision", "ticket", "ticket_state", "approval", "approver_set", "policy_version", "policy_sha256", "approval_sha256"}

// Epinglage est ce que le noyau garde d'un charger réussi (CT-2 EX-7.15,
// EX-7.16) : l'empreinte de l'ensemble qu'il a déclarée et le SHA-256 du JCS
// du membre approval qu'il a envoyé.
type Epinglage struct {
	PolicySHA256   string
	ApprovalSHA256 string
}

// ContexteReponse est ce que le noyau sait quand il reçoit une réponse
// d'evaluer (CT-2 EX-7.16) : les versions dont il détient l'ensemble de
// politique (charger réussi) avec leur épinglage, code.policy_version de la
// requête, code.policy_version de la retenue du ticket rapproché ("" sans
// ticket rapproché) et la décision qu'il a scellée pour ce ticket (nil sans).
type ContexteReponse struct {
	Versions        map[string]Epinglage
	VersionRequete  string
	VersionRetenue  string
	DecisionScellee *Value
}

// LireContexteReponse lit le membre context d'un cas de reponses-evaluer/.
func LireContexteReponse(v *Value) ContexteReponse {
	c := ContexteReponse{Versions: map[string]Epinglage{}}
	if vs := v.Get("versions"); vs != nil && vs.Kind == KindObject {
		for _, m := range vs.Obj {
			c.Versions[m.Key] = Epinglage{PolicySHA256: m.Val.Get("policy_sha256").S(), ApprovalSHA256: m.Val.Get("approval_sha256").S()}
		}
	}
	c.VersionRequete = v.Get("request_policy_version").S()
	if r := v.Get("retained_policy_version"); r != nil && r.Kind == KindString {
		c.VersionRetenue = r.Str
	}
	if d := v.Get("sealed_decision"); d != nil && d.Kind == KindObject {
		c.DecisionScellee = d
	}
	return c
}

// epinglageForme : policy_version chaîne de 1 à 128 points de code,
// policy_sha256 et approval_sha256 hexadécimaux minuscules de 32 octets
// (12.3, CT-1 §3).
func epinglageForme(r *Value) bool {
	pv, sha, apr := r.Get("policy_version"), r.Get("policy_sha256"), r.Get("approval_sha256")
	if pv == nil || pv.Kind != KindString || sha == nil || sha.Kind != KindString || apr == nil || apr.Kind != KindString {
		return false
	}
	n := utf8.RuneCountInString(pv.Str)
	return n >= 1 && n <= 128 && reHex32.MatchString(sha.Str) && reHex32.MatchString(apr.Str)
}

// jeuExploitable : forme de $defs/approver_set (déjà jugée par le schéma),
// source d'EX-8.8, membres distincts, size égal au nombre de membres,
// required au plus size (CT-2 EX-7.16, EX-9.4 ; CT-3 EX-12.6).
func jeuExploitable(js *Value) bool {
	if js == nil || js.Kind != KindObject || !reSourceEX88.MatchString(js.Get("source").S()) {
		return false
	}
	membres := chaines(js.Get("members"))
	vus := map[string]bool{}
	for _, m := range membres {
		if vus[m] {
			return false
		}
		vus[m] = true
	}
	rq, ok1 := EntierJSON(js.Get("threshold").Get("required"))
	sz, ok2 := EntierJSON(js.Get("threshold").Get("size"))
	return ok1 && ok2 && len(membres) >= 1 && sz == int64(len(membres)) && rq >= 1 && rq <= sz
}

// combinaisonAdmise : l'une des sept combinaisons de la table d'EX-7.16
// (EX-12.6), la forme de $defs/reponse_evaluer étant déjà jugée.
func combinaisonAdmise(r *Value) bool {
	dec := r.Get("decision").S()
	rule, ticket, etat, ap, jeu := r.Get("rule"), r.Get("ticket"), r.Get("ticket_state"), r.Get("approval"), r.Get("approver_set")
	if ticket.IsNull() {
		return etat.IsNull() && ap.IsNull() && jeu.IsNull() && (dec == "autorise" || dec == "refuse")
	}
	if etat.IsNull() {
		return false
	}
	scelle := func(d string) bool {
		return ap.Kind == KindObject && ap.Get("ticket").S() == ticket.S() && ap.Get("decision").S() == d && jeu.IsNull()
	}
	switch etat.S() {
	case "nouveau":
		return dec == "a_approuver" && rule.Kind == KindString && ap.IsNull() && jeuExploitable(jeu)
	case "en_attente":
		return dec == "a_approuver" && rule.Kind == KindString && ap.IsNull() && jeu.IsNull()
	case "approuve":
		return dec == "autorise" && scelle("approuve")
	case "refuse", "expire":
		return dec == "refuse" && scelle(etat.S())
	}
	return false
}

// VerifierReponseEvaluer juge une réponse d'evaluer comme le noyau (CT-2
// EX-7.16, révision 0.8) et rend : valide, raison ("" si valide ;
// politique_non_epinglee, forme, approval_different) et l'action du
// mandataire en mode erreur (section 11 : relayer, verifier_relais, resultat,
// erreur). Ordre : objet ; épinglage présent et bien formé (sinon
// politique_non_epinglee : la réponse ne reporte pas la politique sous
// laquelle elle est rendue) ; exactement les neuf membres, forme du schéma et
// combinaison d'EX-12.6 (sinon forme) ; version détenue, empreinte égale à
// celle déclarée à son charger, approval_sha256 égal au condensé du membre
// approval envoyé à ce charger, version attendue (requête sans ticket
// rapproché, retenue du ticket rapproché) ; pour une décision scellée,
// approval égal clé pour clé à celui du noyau (RL-1).
func VerifierReponseEvaluer(sch *Schemas, c ContexteReponse, r *Value) (bool, string, string) {
	if r == nil || r.Kind != KindObject {
		return false, "forme", "erreur"
	}
	if !epinglageForme(r) {
		return false, RaisonPolitiqueNonEpinglee, "erreur"
	}
	if len(r.Obj) != len(membresReponse) {
		return false, "forme", "erreur"
	}
	for _, m := range membresReponse {
		if !r.Has(m) {
			return false, "forme", "erreur"
		}
	}
	if errs := sch.Valider(RefTicket+"#/$defs/reponse_evaluer", r); len(errs) > 0 {
		return false, "forme", "erreur"
	}
	if !combinaisonAdmise(r) {
		return false, "forme", "erreur"
	}
	pv := r.Get("policy_version").S()
	e, detenue := c.Versions[pv]
	if !detenue || e.PolicySHA256 != r.Get("policy_sha256").S() || e.ApprovalSHA256 != r.Get("approval_sha256").S() {
		return false, RaisonPolitiqueNonEpinglee, "erreur"
	}
	etat := r.Get("ticket_state")
	rapproche := !r.Get("ticket").IsNull() && etat.S() != "nouveau"
	attendue := c.VersionRequete
	if rapproche {
		attendue = c.VersionRetenue
	}
	if attendue == "" || pv != attendue {
		return false, RaisonPolitiqueNonEpinglee, "erreur"
	}
	switch etat.S() {
	case "approuve", "refuse", "expire":
		if c.DecisionScellee == nil || !EgalJSON(r.Get("approval"), c.DecisionScellee) {
			return false, "approval_different", "erreur"
		}
	}
	dec := r.Get("decision").S()
	switch {
	case dec == "autorise" && r.Get("ticket").IsNull():
		return true, "", "relayer"
	case dec == "autorise":
		return true, "", "verifier_relais"
	}
	return true, "", "resultat"
}

// familleReponses rejoue reponses-evaluer/cas.json.
func familleReponses(c *Contexte) {
	const f = FamReponses
	d, ok := c.lire("reponses-evaluer/cas.json")
	if !ok {
		return
	}
	fond := "CT-2 EX-7.16 (révision 0.8) : neuf membres, combinaison d'EX-12.6, épinglage (policy_version, policy_sha256, approval_sha256) d'un charger du noyau pour la version attendue (politique_non_epinglee), approval de la décision scellée (RL-1) ; CT-3 §12.2, §12.3, EX-12.6 (révision 0.5)"
	raisons := map[string]string{}
	vues := map[string]bool{}
	for _, cas := range d.Get("cases").Arr {
		id := "reponses-evaluer/cas.json " + cas.Get("id").S()
		ctx := LireContexteReponse(cas.Get("context"))
		valide, raison, action := VerifierReponseEvaluer(c.Sch, ctx, cas.Get("response"))
		exp := cas.Get("expected")
		c.R.ComparerJSON(f, id, "expected.valid", exp.Get("valid"), Booleen(valide), fond)
		c.R.ComparerJSON(f, id, "expected.reason", exp.Get("reason"), chaineOuNulle(raison), fond)
		c.R.Comparer(f, id, "expected.action", exp.Get("action").S(), action, "CT-3 section 11 (EX-11.3 à EX-11.8 ; CT-2 EX-4.49, EX-7.21) : relais, vérifications de relais, résultat rendu par l'enregistreur, -31010")
		raisons[cas.Get("id").S()] = raison
		if valide {
			vues[cas.Get("response").Get("decision").S()+"/"+Compact(cas.Get("response").Get("ticket_state"))] = true
		}
	}
	for _, id := range []string{"huit-membres", "empreinte-autre", "version-inconnue", "version-de-la-requete-pour-un-ticket-rapproche", "approval-sha256-autres-regles"} {
		r, present := raisons[id]
		c.R.Exiger(f, "reponses-evaluer/cas.json", "cas "+id+" présent, invalide, raison politique_non_epinglee", present && r == RaisonPolitiqueNonEpinglee, r, "révision du protocole d'approbation (étape 8, décision du porteur du 14 novembre 2026) : les cinq cas négatifs de CT-2 EX-7.16")
	}
	for _, k := range []string{`autorise/null`, `refuse/null`, `a_approuver/"nouveau"`, `a_approuver/"en_attente"`, `autorise/"approuve"`, `refuse/"refuse"`, `refuse/"expire"`} {
		c.R.Exiger(f, "reponses-evaluer/cas.json", "combinaison "+k+" servie par un cas valide", vues[k], "aucun", "CT-2 EX-7.16 : les sept combinaisons de la table")
	}
}
