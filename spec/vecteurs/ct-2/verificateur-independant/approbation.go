// Approbation vue du frontal MCP (CT-2 version 0.3) : réponse d'evaluer et
// ses combinaisons (EX-7.4, EX-7.16), résultats que l'enregistreur rend
// lui-même (refus par la politique et signal d'approbation, EX-4.49), codes
// d'erreur admis (EX-4.24).

package main

import (
	"fmt"
	"strings"
)

// CleApprobation est la clé _meta du signal d'approbation (EX-4.49).
const CleApprobation = "noortrace/approval"

// TexteRefusPolitique est le texte fixe du refus par la politique sans
// ticket (4.4 pas 5, EX-4.49, CT-3 EX-11.8).
const TexteRefusPolitique = "noortrace: appel refuse par la politique"

// TexteSignal rend le texte fixe du signal d'approbation (EX-4.49) :
// « noortrace: appel soumis a approbation ; ticket=<ticket> ; state=<state> ».
func TexteSignal(ticket, etat string) string {
	return "noortrace: appel soumis a approbation ; ticket=" + ticket + " ; state=" + etat
}

// EtatsSignal sont les valeurs de state du signal (EX-4.49, CT-3 EX-11.7).
var EtatsSignal = map[string]bool{"en_attente": true, "refuse": true, "expire": true}

// ResultatEnregistreur construit un CallToolResult rendu par l'enregistreur
// lui-même (EX-4.49), membres dans l'ordre des exemples : resultType (ère
// moderne seulement), content (un seul bloc text), isError: true, _meta
// (serverInfo, puis noortrace/approval pour le signal) ; jamais de
// structuredContent.
func ResultatEnregistreur(texte string, moderne bool, approbation *Value) *Value {
	r := ObjetVide()
	if moderne {
		Definir(r, "resultType", Chaine("complete"))
	}
	bloc := Objet("type", Chaine("text"), "text", Chaine(texte))
	Definir(r, "content", &Value{Kind: KindArray, Arr: []*Value{bloc}})
	Definir(r, "isError", Booleen(true))
	m := Objet(CleServerInfo, Objet("name", Chaine(NomEnregistreur), "version", Chaine(VersionEnregistreurVecteurs)))
	if approbation != nil {
		Definir(m, CleApprobation, approbation)
	}
	Definir(r, "_meta", m)
	return r
}

// RefusPolitique est le résultat du refus par la politique sans ticket.
func RefusPolitique(moderne bool) *Value {
	return ResultatEnregistreur(TexteRefusPolitique, moderne, nil)
}

// SignalApprobation est le signal d'approbation d'un ticket (EX-4.49).
func SignalApprobation(ticket, etat string, moderne bool) *Value {
	return ResultatEnregistreur(TexteSignal(ticket, etat), moderne, Objet("ticket", Chaine(ticket), "state", Chaine(etat)))
}

// SerialiserOrdre écrit une valeur JSON sans blancs, dans l'ordre de ses
// membres (pas en JCS : EX-4.49 fixe l'ordre des exemples) ; chaînes
// échappées comme en JCS, nombres tels quels.
func SerialiserOrdre(v *Value) string {
	var sb strings.Builder
	serialiserOrdre(&sb, v)
	return sb.String()
}

func serialiserOrdre(sb *strings.Builder, v *Value) {
	switch v.Kind {
	case KindNull:
		sb.WriteString("null")
	case KindBool:
		if v.Bool {
			sb.WriteString("true")
		} else {
			sb.WriteString("false")
		}
	case KindNumber:
		sb.WriteString(v.Num)
	case KindString:
		EchapperChaine(sb, v.Str)
	case KindArray:
		sb.WriteByte('[')
		for i, x := range v.Arr {
			if i > 0 {
				sb.WriteByte(',')
			}
			serialiserOrdre(sb, x)
		}
		sb.WriteByte(']')
	case KindObject:
		sb.WriteByte('{')
		for i, m := range v.Obj {
			if i > 0 {
				sb.WriteByte(',')
			}
			EchapperChaine(sb, m.Key)
			sb.WriteByte(':')
			serialiserOrdre(sb, m.Val)
		}
		sb.WriteByte('}')
	}
}

// LigneResultat est la ligne JSON-RPC qui rend un résultat à l'hôte : id
// recopié en octets depuis la requête (4.4 pas 14).
func LigneResultat(idTexte string, resultat *Value) string {
	return `{"jsonrpc":"2.0","id":` + idTexte + `,"result":` + SerialiserOrdre(resultat) + `}`
}

// Issues d'une réponse d'evaluer (table d'EX-7.16).
const (
	IssueRelais        = "relais"          // autorise, sans ticket
	IssueRefus         = "refus"           // refuse, sans ticket
	IssueNouveau       = "nouveau"         // a_approuver, ticket nouveau
	IssueEnAttente     = "en_attente"      // a_approuver, ticket en attente
	IssueRelaisApprouv = "relais_approuve" // autorise, ticket approuve
	IssueRefusTicket   = "refus_ticket"    // refuse, ticket refuse ou expire
)

// IssueReponseEvaluer classe une réponse d'evaluer selon EX-7.16 : une des
// six combinaisons, avec ticket non nul si et seulement si ticket_state l'est,
// approver_set non nul pour nouveau seulement, et, pour une décision scellée,
// approval.ticket = ticket et approval.decision = ticket_state ; rule et
// ticket non nuls pour a_approuver (CT-1 §5.3). Toute autre réponse est
// invalide (raison non vide) : indisponibilité du service, -31010.
func IssueReponseEvaluer(rep *Value) (string, string) {
	if !EstObjet(rep) {
		return "", "réponse qui n'est pas un objet"
	}
	for _, k := range []string{"rule", "decision", "ticket", "ticket_state", "approval", "approver_set"} {
		if rep.Get(k) == nil {
			return "", "membre " + k + " absent"
		}
	}
	if len(rep.Obj) != 6 {
		return "", "membres en plus des six de CT-3 §12.3"
	}
	nulOuChaine := func(k string) (string, bool, bool) {
		v := rep.Get(k)
		if v.IsNull() {
			return "", true, true
		}
		return v.Str, false, EstChaine(v)
	}
	dec, _, okD := nulOuChaine("decision")
	tk, tkNul, okT := nulOuChaine("ticket")
	st, stNul, okS := nulOuChaine("ticket_state")
	_, ruleNul, okR := nulOuChaine("rule")
	if !okD || !okT || !okS || !okR {
		return "", "rule, decision, ticket ou ticket_state de type invalide"
	}
	if tkNul != stNul {
		return "", "ticket non nul si et seulement si ticket_state l'est (EX-7.16)"
	}
	ap, as := rep.Get("approval"), rep.Get("approver_set")
	if (st == "nouveau") != !as.IsNull() {
		return "", "approver_set non nul pour nouveau seulement (EX-7.16)"
	}
	if !as.IsNull() && !EstObjet(as) {
		return "", "approver_set qui n'est pas un objet"
	}
	scellee := func() string {
		if !EstObjet(ap) {
			return "approval absent pour une décision scellée"
		}
		if chaineDe(ap, "ticket") != tk || chaineDe(ap, "decision") != st {
			return "approval.ticket ou approval.decision différent de ticket ou ticket_state (EX-7.16)"
		}
		return ""
	}
	switch {
	case dec == "autorise" && stNul && ap.IsNull():
		return IssueRelais, ""
	case dec == "refuse" && stNul && ap.IsNull():
		return IssueRefus, ""
	case dec == "a_approuver" && (st == "nouveau" || st == "en_attente") && ap.IsNull():
		if ruleNul || tkNul {
			return "", "rule et ticket non nuls pour a_approuver (CT-1 §5.3)"
		}
		if st == "nouveau" {
			return IssueNouveau, ""
		}
		return IssueEnAttente, ""
	case dec == "autorise" && st == "approuve":
		if r := scellee(); r != "" {
			return "", r
		}
		return IssueRelaisApprouv, ""
	case dec == "refuse" && (st == "refuse" || st == "expire"):
		if r := scellee(); r != "" {
			return "", r
		}
		return IssueRefusTicket, ""
	}
	return "", fmt.Sprintf("combinaison hors de la table d'EX-7.16 (decision %s, ticket_state %s)", texteOuAbsent(rep.Get("decision")), texteOuAbsent(rep.Get("ticket_state")))
}

// ResultatAttendu rend le résultat que l'enregistreur rend lui-même pour une
// issue sans relais, en mode d'attente « erreur » (4.4 pas 5 et 6), ou nil
// pour une issue relayée (relais, relais_approuve).
func ResultatAttendu(issue string, rep *Value, moderne bool) *Value {
	tk, st := chaineDe(rep, "ticket"), chaineDe(rep, "ticket_state")
	switch issue {
	case IssueRefus:
		return RefusPolitique(moderne)
	case IssueNouveau, IssueEnAttente:
		return SignalApprobation(tk, "en_attente", moderne)
	case IssueRefusTicket:
		return SignalApprobation(tk, st, moderne)
	}
	return nil
}

// CodesStandardEX424 sont les codes JSON-RPC standard et ceux de la
// spécification MCP que l'enregistreur peut rendre (EX-4.24).
var CodesStandardEX424 = map[int64]bool{-32700: true, -32600: true, -32601: true, -32602: true, -32603: true, -32020: true, -32021: true, -32022: true}

// CodeAdmisEX424 dit si une erreur rendue par l'enregistreur lui-même porte
// un code qu'EX-4.24 admet : un code de la table de 4.4, ou un code standard ;
// jamais -32000 à -32019, -32020 à -32099 hors des trois de MCP, -32002,
// -32042, 100 à 599, ni -31015 (non attribué).
func CodeAdmisEX424(code int64) (bool, string) {
	switch {
	case code == CodeNonAttribue:
		return false, "-31015 : non attribué, jamais émis (table de 4.4)"
	case code >= -32019 && code <= -32000:
		return false, "plage héritée -32000 à -32019"
	case code >= -32099 && code <= -32020 && !CodesStandardEX424[code]:
		return false, "plage -32020 à -32099 réservée à la spécification MCP"
	case code == -32002 || code == -32042:
		return false, "code d'une révision antérieure de MCP"
	case code >= 100 && code <= 599:
		return false, "code de la plage 100 à 599"
	}
	if _, ok := MessagesErreurs[code]; ok || CodesStandardEX424[code] {
		return true, ""
	}
	return false, "code hors de la table de 4.4 et des codes standard"
}
