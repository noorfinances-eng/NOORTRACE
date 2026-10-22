// Copié sans modification du vérificateur indépendant CT-1
// (spec/vecteurs/ct-1/verificateur-independant/evenement.go).

// Événement v0 (CT-1 §5) : validation de forme (E-1, le schéma
// evenement-v0.schema.json transcrit en Go), forme canonique (E-2),
// cohérence de sorte (E-3), rédaction (E-4), approbation (E-5), références en
// ligne (E-6), hachage (E-7), signature (E-8), rotation (E-10), validité de
// la clé (E-11), et contrôles de paire C-1 à C-3 (§7).

package main

import (
	"bytes"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"
)

// Noms réservés de l'espace noortrace. (§5.1).
const (
	OutilModele      = "noortrace.modele.echange"
	OutilApprobation = "noortrace.approbation.decision"
	OutilRotation    = "noortrace.journal.rotation-cle"
	OutilPolitique   = "noortrace.journal.politique"
)

// Sorte d'événement (table de §5.1).
type Sorte int

// Les sortes.
const (
	SorteOutil Sorte = iota
	SorteModele
	SorteApprobation
	SorteRotation
	SortePolitique
	SorteReserveInconnue
)

// SorteDe déduit la sorte du nom d'outil.
func SorteDe(tool string) Sorte {
	switch tool {
	case OutilModele:
		return SorteModele
	case OutilApprobation:
		return SorteApprobation
	case OutilRotation:
		return SorteRotation
	case OutilPolitique:
		return SortePolitique
	}
	if strings.HasPrefix(tool, "noortrace.") {
		return SorteReserveInconnue
	}
	return SorteOutil
}

var (
	clesEvenement = []string{"version", "seq", "ts", "org_id", "journal_id", "recorder_key_id", "prev_hash",
		"delegation", "code", "intent", "policy", "approval", "execution", "effects", "context", "hash", "sig"}
	reNomOutil      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
	reTypeMime      = regexp.MustCompile(`^[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+$`)
	reMontant       = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]{1,8})?$`)
	reDevise        = regexp.MustCompile(`^[A-Z]{3}$`)
	enumDecisionPol = []string{"autorise", "a_approuver", "refuse", "sans_objet"}
	enumDecisionApp = []string{"approuve", "refuse", "expire"}
	enumStatus      = []string{"executee", "retenue", "refusee"}
	enumAction      = []string{"lecture", "ecriture", "suppression", "envoi", "execution"}
	enumKind        = []string{"document", "donnees", "memoire", "autre"}
	outilsReserves  = []string{OutilModele, OutilApprobation, OutilRotation, OutilPolitique}
)

func dansEnum(s string, e []string) bool {
	for _, x := range e {
		if x == s {
			return true
		}
	}
	return false
}

// manquements accumule les violations de schéma avec leur chemin.
type manquements struct{ liste []string }

func (m *manquements) add(chemin, format string, args ...any) {
	m.liste = append(m.liste, chemin+" : "+fmt.Sprintf(format, args...))
}

// estEntierJSON dit si un littéral de nombre a une valeur entière (sens de
// `type: integer` en JSON Schema : 412.0 est un entier) et rend sa valeur.
func estEntierJSON(lit string) (*big.Int, bool) {
	r, ok := new(big.Rat).SetString(lit)
	if !ok || !r.IsInt() {
		return nil, false
	}
	return new(big.Int).Set(r.Num()), true
}

func (m *manquements) entier(v *Value, chemin string, min, max int64) (int64, bool) {
	if v == nil || v.Kind != KindNumber {
		m.add(chemin, "entier attendu")
		return 0, false
	}
	n, ok := estEntierJSON(v.Num)
	if !ok {
		m.add(chemin, "entier attendu, reçu %s", v.Num)
		return 0, false
	}
	if n.Cmp(big.NewInt(min)) < 0 || n.Cmp(big.NewInt(max)) > 0 {
		m.add(chemin, "entier hors de [%d, %d] : %s", min, max, v.Num)
		return 0, false
	}
	return n.Int64(), true
}

func (m *manquements) chaine(v *Value, chemin string, min, max int, nullable bool) (string, bool) {
	if v == nil {
		m.add(chemin, "obligatoire")
		return "", false
	}
	if v.Kind == KindNull {
		if !nullable {
			m.add(chemin, "null interdit")
			return "", false
		}
		return "", true
	}
	if v.Kind != KindString {
		m.add(chemin, "chaîne attendue, reçu %s", v.Kind)
		return "", false
	}
	l := longueurChaine(v.Str)
	if l < min || l > max {
		m.add(chemin, "longueur %d hors de [%d, %d]", l, min, max)
		return v.Str, false
	}
	return v.Str, true
}

func (m *manquements) hex(v *Value, chemin string, n int, nullable bool) (string, bool) {
	if v == nil {
		m.add(chemin, "obligatoire")
		return "", false
	}
	if v.Kind == KindNull {
		if !nullable {
			m.add(chemin, "null interdit")
			return "", false
		}
		return "", true
	}
	if v.Kind != KindString || !EstHex(v.Str, n) {
		m.add(chemin, "%d octets en hexadécimal minuscule préfixé 0x attendus", n)
		return "", false
	}
	return v.Str, true
}

func (m *manquements) horodatage(v *Value, chemin string) (time.Time, bool) {
	if v == nil || v.Kind != KindString {
		m.add(chemin, "horodatage attendu")
		return time.Time{}, false
	}
	t, ok := ParseHorodatage(v.Str)
	if !ok {
		m.add(chemin, "horodatage RFC 3339 UTC à trois décimales attendu, reçu %q", v.Str)
	}
	return t, ok
}

func (m *manquements) clesExactes(v *Value, chemin string, obligatoires []string, optionnelles ...string) bool {
	if v == nil || v.Kind != KindObject {
		m.add(chemin, "objet attendu")
		return false
	}
	ok := true
	for _, k := range obligatoires {
		if !v.Has(k) {
			m.add(chemin+"."+k, "obligatoire")
			ok = false
		}
	}
	for _, k := range v.Keys() {
		if !dansEnum(k, obligatoires) && !dansEnum(k, optionnelles) {
			m.add(chemin+"."+k, "clé inattendue")
			ok = false
		}
	}
	return ok
}

func (m *manquements) enumeration(v *Value, chemin string, e []string) (string, bool) {
	if v == nil || v.Kind != KindString || !dansEnum(v.Str, e) {
		m.add(chemin, "valeur attendue parmi %v", e)
		return "", false
	}
	return v.Str, true
}

// reference valide une référence de charge utile (§5.4).
func (m *manquements) reference(v *Value, chemin string) {
	if !m.clesExactes(v, chemin, []string{"sha256", "length", "redacted"}, "media_type", "value") {
		return
	}
	m.hex(v.Get("sha256"), chemin+".sha256", 32, false)
	m.entier(v.Get("length"), chemin+".length", 0, EntierSurMax)
	red := v.Get("redacted")
	if red.Kind != KindBool {
		m.add(chemin+".redacted", "booléen attendu")
	} else if red.Bool && v.Has("value") {
		m.add(chemin+".value", "interdite quand redacted vaut true")
	}
	if mt := v.Get("media_type"); mt != nil {
		if mt.Kind != KindString || !reTypeMime.MatchString(mt.Str) || len(mt.Str) > 127 {
			m.add(chemin+".media_type", "type de média en minuscules attendu")
		}
	}
}

// ValiderSchemaEvenement transcrit evenement-v0.schema.json (E-1) et les
// contraintes de forme de §5.2 que le schéma n'exprime pas (org_id et
// journal_id non nuls).
func ValiderSchemaEvenement(ev *Value) []string {
	m := &manquements{}
	if !m.clesExactes(ev, "$", clesEvenement) {
		return m.liste
	}
	if v := ev.Get("version"); v.Kind != KindNumber {
		m.add("$.version", "constante 0 attendue")
	} else if n, ok := estEntierJSON(v.Num); !ok || n.Sign() != 0 {
		m.add("$.version", "constante 0 attendue, reçu %s", v.Num)
	}
	m.entier(ev.Get("seq"), "$.seq", 1, EntierSurMax)
	m.horodatage(ev.Get("ts"), "$.ts")
	for _, k := range []string{"org_id", "journal_id"} {
		if s, ok := m.hex(ev.Get(k), "$."+k, 32, false); ok && s == Zero32 {
			m.add("$."+k, "32 octets nuls interdits (§5.2)")
		}
	}
	if v := ev.Get("recorder_key_id"); v.Kind != KindString || !EstIdentifiantCle(v.Str) {
		m.add("$.recorder_key_id", "identifiant de clé attendu")
	}
	m.hex(ev.Get("prev_hash"), "$.prev_hash", 32, false)
	m.hex(ev.Get("hash"), "$.hash", 32, false)
	m.hex(ev.Get("sig"), "$.sig", 64, false)

	// delegation
	if d := ev.Get("delegation"); m.clesExactes(d, "$.delegation", []string{"launched_by", "on_behalf_of", "scope", "run_id"}) {
		m.chaine(d.Get("launched_by"), "$.delegation.launched_by", 1, 256, false)
		m.chaine(d.Get("on_behalf_of"), "$.delegation.on_behalf_of", 0, 256, true)
		m.chaine(d.Get("scope"), "$.delegation.scope", 1, 1024, false)
		m.chaine(d.Get("run_id"), "$.delegation.run_id", 0, 128, true)
	}
	// code
	if c := ev.Get("code"); m.clesExactes(c, "$.code", []string{"model", "prompt_version", "policy_version", "recorder"}) {
		m.chaine(c.Get("model"), "$.code.model", 0, 256, true)
		m.hex(c.Get("prompt_version"), "$.code.prompt_version", 32, true)
		m.chaine(c.Get("policy_version"), "$.code.policy_version", 1, 128, false)
		m.chaine(c.Get("recorder"), "$.code.recorder", 1, 64, false)
	}
	// intent
	switch it := ev.Get("intent"); it.Kind {
	case KindNull:
	case KindString:
		m.chaine(it, "$.intent", 0, 4096, false)
	case KindObject:
		m.reference(it, "$.intent")
	default:
		m.add("$.intent", "chaîne, référence ou null attendu")
	}
	// policy
	var decisionPol string
	if p := ev.Get("policy"); m.clesExactes(p, "$.policy", []string{"rule", "decision", "ticket", "redaction"}) {
		m.chaine(p.Get("rule"), "$.policy.rule", 0, 1024, true)
		decisionPol, _ = m.enumeration(p.Get("decision"), "$.policy.decision", enumDecisionPol)
		m.chaine(p.Get("ticket"), "$.policy.ticket", 0, 128, true)
		m.chaine(p.Get("redaction"), "$.policy.redaction", 0, 128, true)
		switch decisionPol {
		case "a_approuver":
			if p.Get("rule").Kind != KindString {
				m.add("$.policy.rule", "obligatoire (non null) quand decision vaut a_approuver")
			}
			if t := p.Get("ticket"); t.Kind != KindString || len(t.Str) < 1 {
				m.add("$.policy.ticket", "obligatoire (non vide) quand decision vaut a_approuver")
			}
		case "sans_objet":
			if p.Get("rule").Kind != KindNull {
				m.add("$.policy.rule", "null attendu quand decision vaut sans_objet")
			}
		}
	}
	// approval
	if a := ev.Get("approval"); a.Kind != KindNull {
		if m.clesExactes(a, "$.approval", []string{"decision", "ticket", "request_hash", "threshold", "approvers", "signatures", "at", "reason"}) {
			dec, _ := m.enumeration(a.Get("decision"), "$.approval.decision", enumDecisionApp)
			m.chaine(a.Get("ticket"), "$.approval.ticket", 1, 128, false)
			m.hex(a.Get("request_hash"), "$.approval.request_hash", 32, false)
			if th := a.Get("threshold"); m.clesExactes(th, "$.approval.threshold", []string{"required", "size"}) {
				m.entier(th.Get("required"), "$.approval.threshold.required", 1, 65535)
				m.entier(th.Get("size"), "$.approval.threshold.size", 1, 65535)
			}
			nApp, nSig := -1, -1
			if ap := a.Get("approvers"); ap.Kind != KindArray {
				m.add("$.approval.approvers", "tableau attendu")
			} else {
				nApp = len(ap.Arr)
				vus := map[string]bool{}
				for i, x := range ap.Arr {
					ch := fmt.Sprintf("$.approval.approvers[%d]", i)
					if s, ok := m.hex(x, ch, 20, false); ok {
						if vus[s] {
							m.add(ch, "adresse en double (uniqueItems)")
						}
						vus[s] = true
					}
				}
				if nApp > 65535 {
					m.add("$.approval.approvers", "plus de 65535 éléments")
				}
			}
			if sg := a.Get("signatures"); sg.Kind != KindArray {
				m.add("$.approval.signatures", "tableau attendu")
			} else {
				nSig = len(sg.Arr)
				for i, x := range sg.Arr {
					m.hex(x, fmt.Sprintf("$.approval.signatures[%d]", i), 65, false)
				}
			}
			m.horodatage(a.Get("at"), "$.approval.at")
			m.chaine(a.Get("reason"), "$.approval.reason", 0, 1024, true)
			switch dec {
			case "expire":
				if nApp > 0 || nSig > 0 {
					m.add("$.approval", "approvers et signatures doivent être vides quand decision vaut expire")
				}
			case "approuve":
				if nApp == 0 || nSig == 0 {
					m.add("$.approval", "approvers et signatures non vides attendus quand decision vaut approuve")
				}
			}
		}
	}
	// execution
	if x := ev.Get("execution"); m.clesExactes(x, "$.execution", []string{"tool", "arguments", "status", "result", "duration_ms", "is_error"}) {
		tool := ""
		if t := x.Get("tool"); t.Kind != KindString || !reNomOutil.MatchString(t.Str) {
			m.add("$.execution.tool", "nom d'outil attendu (motif de §5.3)")
		} else {
			tool = t.Str
			if strings.HasPrefix(tool, "noortrace.") && !dansEnum(tool, outilsReserves) {
				m.add("$.execution.tool", "nom réservé inconnu %q", tool)
			}
		}
		m.reference(x.Get("arguments"), "$.execution.arguments")
		status, _ := m.enumeration(x.Get("status"), "$.execution.status", enumStatus)
		res := x.Get("result")
		if res.Kind != KindNull {
			m.reference(res, "$.execution.result")
		}
		dur := x.Get("duration_ms")
		if dur.Kind != KindNull {
			m.entier(dur, "$.execution.duration_ms", 0, EntierSurMax)
		}
		ise := x.Get("is_error")
		if ise.Kind != KindNull && ise.Kind != KindBool {
			m.add("$.execution.is_error", "booléen ou null attendu")
		}
		// allOf de execution (table par sorte de §5.3) : result, duration_ms et
		// is_error obligatoires pour un appel d'outil exécuté et pour l'échange
		// avec le modèle ; nuls pour un appel retenu ou refusé et pour les trois
		// autres événements réservés.
		switch status {
		case "retenue", "refusee":
			if res.Kind != KindNull || dur.Kind != KindNull || ise.Kind != KindNull {
				m.add("$.execution", "result, duration_ms et is_error doivent être null quand status vaut %s", status)
			}
		case "executee":
			if tool != "" && (!strings.HasPrefix(tool, "noortrace.") || tool == OutilModele) {
				if res.Kind != KindObject {
					m.add("$.execution.result", "référence obligatoire pour un appel d'outil exécuté ou un échange avec le modèle")
				}
				if dur.Kind != KindNumber {
					m.add("$.execution.duration_ms", "entier obligatoire pour un appel d'outil exécuté ou un échange avec le modèle")
				}
				if ise.Kind != KindBool {
					m.add("$.execution.is_error", "booléen obligatoire pour un appel d'outil exécuté ou un échange avec le modèle")
				}
			}
		}
		if dansEnum(tool, []string{OutilApprobation, OutilRotation, OutilPolitique}) && (res.Kind != KindNull || dur.Kind != KindNull || ise.Kind != KindNull) {
			m.add("$.execution", "result, duration_ms et is_error doivent être null pour %s", tool)
		}
	}
	// effects
	if ef := ev.Get("effects"); ef.Kind != KindArray {
		m.add("$.effects", "tableau attendu")
	} else {
		if len(ef.Arr) > 1024 {
			m.add("$.effects", "plus de 1024 éléments")
		}
		for i, e := range ef.Arr {
			ch := fmt.Sprintf("$.effects[%d]", i)
			if !m.clesExactes(e, ch, []string{"system", "action", "object", "amount", "currency"}) {
				continue
			}
			m.chaine(e.Get("system"), ch+".system", 1, 128, false)
			m.enumeration(e.Get("action"), ch+".action", enumAction)
			m.chaine(e.Get("object"), ch+".object", 1, 512, false)
			am, cu := e.Get("amount"), e.Get("currency")
			if am.Kind == KindString && !reMontant.MatchString(am.Str) {
				m.add(ch+".amount", "montant décimal attendu")
			} else if am.Kind != KindString && am.Kind != KindNull {
				m.add(ch+".amount", "chaîne ou null attendu")
			}
			if cu.Kind == KindString && !reDevise.MatchString(cu.Str) {
				m.add(ch+".currency", "code ISO 4217 attendu")
			} else if cu.Kind != KindString && cu.Kind != KindNull {
				m.add(ch+".currency", "chaîne ou null attendu")
			}
			if (am.Kind == KindNull) != (cu.Kind == KindNull) {
				m.add(ch, "amount et currency doivent être tous deux null ou tous deux renseignés")
			}
		}
	}
	// context
	if cx := ev.Get("context"); cx.Kind != KindArray {
		m.add("$.context", "tableau attendu")
	} else {
		if len(cx.Arr) > 1024 {
			m.add("$.context", "plus de 1024 éléments")
		}
		for i, c := range cx.Arr {
			ch := fmt.Sprintf("$.context[%d]", i)
			if !m.clesExactes(c, ch, []string{"sha256", "length", "redacted", "kind"}, "media_type") {
				continue
			}
			m.hex(c.Get("sha256"), ch+".sha256", 32, false)
			m.entier(c.Get("length"), ch+".length", 0, EntierSurMax)
			if c.Get("redacted").Kind != KindBool {
				m.add(ch+".redacted", "booléen attendu")
			}
			m.enumeration(c.Get("kind"), ch+".kind", enumKind)
			if mt := c.Get("media_type"); mt != nil && (mt.Kind != KindString || !reTypeMime.MatchString(mt.Str)) {
				m.add(ch+".media_type", "type de média en minuscules attendu")
			}
		}
	}
	return m.liste
}

// SansHashNiSig rend E' : l'événement privé de hash et sig, ordre conservé.
func SansHashNiSig(ev *Value) *Value {
	out := &Value{Kind: KindObject}
	for _, mb := range ev.Obj {
		if mb.Key == "hash" || mb.Key == "sig" {
			continue
		}
		out.Obj = append(out.Obj, mb)
	}
	return out
}

// HashEvenement recalcule hash = SHA-256(P_H || JCS(E')) et rend aussi C.
func HashEvenement(ev *Value) (hash []byte, canonique []byte, err error) {
	c, err := Canonique(SansHashNiSig(ev))
	if err != nil {
		return nil, nil, err
	}
	return SHA256Prefixe(PrefixeEvenement, c), c, nil
}

// champs d'accès tolérants (l'événement peut être mal formé)

func chaineDe(v *Value, chemin ...string) string {
	for _, k := range chemin {
		if k == "" {
			continue
		}
		v = v.Get(k)
	}
	if v == nil || v.Kind != KindString {
		return ""
	}
	return v.Str
}

func entierDe(v *Value, chemin ...string) (int64, bool) {
	for _, k := range chemin {
		if k == "" {
			continue
		}
		v = v.Get(k)
	}
	if v == nil || v.Kind != KindNumber {
		return 0, false
	}
	n, ok := estEntierJSON(v.Num)
	if !ok || !n.IsInt64() {
		return 0, false
	}
	return n.Int64(), true
}

// Seq rend le seq d'un événement, ou -1.
func Seq(ev *Value) int64 {
	n, ok := entierDe(ev, "seq")
	if !ok {
		return -1
	}
	return n
}

// Ts rend l'horodatage d'un événement.
func Ts(ev *Value) (time.Time, bool) { return ParseHorodatage(chaineDe(ev, "ts")) }

// Outil rend execution.tool.
func Outil(ev *Value) string { return chaineDe(ev, "execution", "tool") }

// EstRotation dit si l'événement est une rotation de clé.
func EstRotation(ev *Value) bool { return Outil(ev) == OutilRotation }

// NouvelleCleRotation rend new_key_id d'une rotation, ou "".
func NouvelleCleRotation(ev *Value) string {
	return chaineDe(ev, "execution", "arguments", "value", "new_key_id")
}

// ControlerEvenement exécute E-1 à E-8, E-10 et E-11 sur un événement isolé.
// cles peut être nil : les contrôles qui en dépendent sont alors non exécutés.
// E-9 (EIP-191) est hors périmètre de ce vérificateur.
func ControlerEvenement(ev *Value, cles *JeuCles) *Resultats {
	r := NouveauxResultats()
	if ev == nil || ev.Kind != KindObject {
		r.Echec("E-1", "l'événement n'est pas un objet JSON")
		return r
	}
	// E-1
	for _, mq := range ValiderSchemaEvenement(ev) {
		r.Echec("E-1", "%s", mq)
	}
	r.Passe("E-1")
	// E-2
	if _, err := Canonique(ev); err != nil {
		r.Echec("E-2", "%v", err)
	}
	r.Passe("E-2")
	// E-3
	controlerSorte(r, ev)
	// E-4
	controlerRedaction(r, ev)
	// E-5
	controlerApprobationForme(r, ev)
	// E-6
	controlerReferencesEnLigne(r, ev)
	// E-7
	hash, c, err := HashEvenement(ev)
	if err != nil {
		r.NonExecute("E-7", "forme canonique impossible")
		r.NonExecute("E-8", "forme canonique impossible")
	} else {
		if got := Hex0x(hash); got != chaineDe(ev, "hash") {
			r.Echec("E-7", "hash recalculé %s ≠ hash porté %s", got, chaineDe(ev, "hash"))
		}
		r.Passe("E-7")
		// E-8
		controlerSignatureEvenement(r, ev, c, cles)
	}
	// E-10
	if EstRotation(ev) {
		controlerRotation(r, ev, cles)
	}
	// E-11
	controlerValiditeCle(r, ev, cles)
	return r
}

func controlerSorte(r *Resultats, ev *Value) {
	x := ev.Get("execution")
	tool := Outil(ev)
	sorte := SorteDe(tool)
	status := chaineDe(x, "status")
	res := x.Get("result")
	val := x.Get("arguments").Get("value")
	approval := ev.Get("approval")
	decisionPol := chaineDe(ev, "policy", "decision")
	switch sorte {
	case SorteReserveInconnue:
		r.Echec("E-3", "execution.tool %q dans l'espace réservé noortrace. sans être l'un des quatre noms", tool)
	case SorteApprobation, SorteRotation, SortePolitique:
		if val == nil {
			r.Echec("E-3", "%s : execution.arguments doit être une référence en ligne (value)", tool)
		}
		if res != nil && res.Kind != KindNull {
			r.Echec("E-3", "%s : execution.result doit être null", tool)
		}
		if d := x.Get("duration_ms"); d != nil && d.Kind != KindNull {
			r.Echec("E-3", "%s : execution.duration_ms doit être null", tool)
		}
		if e := x.Get("is_error"); e != nil && e.Kind != KindNull {
			r.Echec("E-3", "%s : execution.is_error doit être null", tool)
		}
		if status != "" && status != "executee" {
			r.Echec("E-3", "%s : execution.status doit valoir executee", tool)
		}
		if it := ev.Get("intent"); it != nil && it.Kind != KindNull {
			r.Echec("E-3", "%s : intent doit être null", tool)
		}
		if decisionPol != "" && decisionPol != "sans_objet" {
			r.Echec("E-3", "%s : policy.decision doit valoir sans_objet", tool)
		}
		if sorte == SorteApprobation {
			if approval == nil || approval.Kind == KindNull {
				r.Echec("E-3", "%s : approval ne peut pas être null", tool)
			} else if val != nil {
				controlerObjetSigneApprobation(r, ev, val)
			}
		} else {
			if approval != nil && approval.Kind != KindNull {
				r.Echec("E-3", "%s : approval doit être null", tool)
			}
			if lb := chaineDe(ev, "delegation", "launched_by"); lb != "" && lb != "noortrace-enregistreur" {
				r.Echec("E-3", "%s : delegation.launched_by doit valoir \"noortrace-enregistreur\", reçu %q", tool, lb)
			}
		}
		if sorte == SorteRotation && val != nil {
			controlerEffetsRotation(r, ev, val)
		}
		if sorte == SortePolitique && val != nil {
			if val.Kind != KindObject || !val.Has("policy_version") || !val.Has("policy_sha256") || len(val.Obj) != 2 {
				r.Echec("E-3", "%s : value doit porter exactement policy_version et policy_sha256", tool)
			} else if s := chaineDe(val, "policy_sha256"); !EstHex(s, 32) {
				r.Echec("E-3", "%s : policy_sha256 doit être 32 octets hexadécimaux", tool)
			}
		}
	case SorteModele:
		// Table 5.3 : l'échange avec le modèle est exécuté et porte la référence à
		// la réponse, la durée et le drapeau d'erreur.
		if decisionPol != "" && decisionPol != "sans_objet" {
			r.Echec("E-3", "%s : policy.decision doit valoir sans_objet", tool)
		}
		if approval != nil && approval.Kind != KindNull {
			r.Echec("E-3", "%s : approval doit être null", tool)
		}
		if status != "" && status != "executee" {
			r.Echec("E-3", "%s : execution.status doit valoir executee", tool)
		}
		if res == nil || res.Kind != KindObject {
			r.Echec("E-3", "%s : execution.result doit référencer la réponse", tool)
		}
		if d := x.Get("duration_ms"); d == nil || d.Kind != KindNumber {
			r.Echec("E-3", "%s : execution.duration_ms doit être un entier", tool)
		}
		if e := x.Get("is_error"); e == nil || e.Kind != KindBool {
			r.Echec("E-3", "%s : execution.is_error doit être un booléen", tool)
		}
	case SorteOutil:
		if decisionPol == "sans_objet" {
			r.Echec("E-3", "appel d'outil : policy.decision ne peut pas valoir sans_objet")
		}
		aApproval := approval != nil && approval.Kind != KindNull
		if aApproval && decisionPol != "" && decisionPol != "a_approuver" {
			r.Echec("E-3", "appel d'outil avec approval : policy.decision doit valoir a_approuver")
		}
		switch decisionPol {
		case "autorise":
			if status != "" && status != "executee" {
				r.Echec("E-3", "policy.decision autorise : status executee attendu, reçu %s", status)
			}
		case "refuse":
			if status != "" && status != "refusee" {
				r.Echec("E-3", "policy.decision refuse : status refusee attendu, reçu %s", status)
			}
		case "a_approuver":
			switch {
			case !aApproval && status != "" && status != "retenue":
				r.Echec("E-3", "a_approuver sans approval : status retenue attendu, reçu %s", status)
			case aApproval && chaineDe(approval, "decision") == "approuve" && status != "" && status != "executee":
				r.Echec("E-3", "approval approuve : status executee attendu, reçu %s", status)
			case aApproval && chaineDe(approval, "decision") != "approuve" && status != "" && status != "refusee":
				r.Echec("E-3", "approval %s : status refusee attendu, reçu %s", chaineDe(approval, "decision"), status)
			}
		}
	}
	r.Passe("E-3")
}

// ObjetSigneApprobation construit A = { decision, journal_id, org_id,
// request_hash, ticket } depuis l'événement (§6.3).
func ObjetSigneApprobation(ev *Value) *Value {
	a := ev.Get("approval")
	return &Value{Kind: KindObject, Obj: []Member{
		{Key: "decision", Val: &Value{Kind: KindString, Str: chaineDe(a, "decision")}},
		{Key: "journal_id", Val: &Value{Kind: KindString, Str: chaineDe(ev, "journal_id")}},
		{Key: "org_id", Val: &Value{Kind: KindString, Str: chaineDe(ev, "org_id")}},
		{Key: "request_hash", Val: &Value{Kind: KindString, Str: chaineDe(a, "request_hash")}},
		{Key: "ticket", Val: &Value{Kind: KindString, Str: chaineDe(a, "ticket")}},
	}}
}

// CondenseApprobation calcule D_A = SHA-256(P_A || JCS(A)).
func CondenseApprobation(a *Value) ([]byte, error) {
	c, err := Canonique(a)
	if err != nil {
		return nil, err
	}
	return SHA256Prefixe(PrefixeApprobation, c), nil
}

func controlerObjetSigneApprobation(r *Resultats, ev *Value, val *Value) {
	attendu, err1 := Canonique(ObjetSigneApprobation(ev))
	recu, err2 := Canonique(val)
	if err1 != nil || err2 != nil {
		r.Echec("E-3", "objet signé A non canonisable")
		return
	}
	if !bytes.Equal(attendu, recu) {
		r.Echec("E-3", "execution.arguments.value ≠ A construit depuis approval : %s ≠ %s", recu, attendu)
	}
}

func controlerEffetsRotation(r *Resultats, ev *Value, val *Value) {
	ef := ev.Get("effects")
	if ef == nil || ef.Kind != KindArray || len(ef.Arr) != 1 {
		r.Echec("E-3", "rotation : effects doit porter exactement un effet")
		return
	}
	e := ef.Arr[0]
	objet := "cle:" + chaineDe(val, "new_key_id")
	if chaineDe(e, "system") != "noortrace" || chaineDe(e, "action") != "ecriture" || chaineDe(e, "object") != objet ||
		!e.Get("amount").IsNull() || !e.Get("currency").IsNull() {
		r.Echec("E-3", "rotation : effets attendus {noortrace, ecriture, %q, null, null}", objet)
	}
}

// referenceSituee est une référence de charge utile et son chemin.
type referenceSituee struct {
	chemin string
	ref    *Value
}

// references rend les références de l'événement avec leur chemin.
func references(ev *Value) []referenceSituee {
	var out []referenceSituee
	ajouter := func(ch string, v *Value) {
		if v != nil && v.Kind == KindObject && v.Has("sha256") {
			out = append(out, referenceSituee{ch, v})
		}
	}
	ajouter("intent", ev.Get("intent"))
	ajouter("execution.arguments", ev.Get("execution").Get("arguments"))
	ajouter("execution.result", ev.Get("execution").Get("result"))
	if cx := ev.Get("context"); cx != nil && cx.Kind == KindArray {
		for i, c := range cx.Arr {
			ajouter(fmt.Sprintf("context[%d]", i), c)
		}
	}
	return out
}

func controlerRedaction(r *Resultats, ev *Value) {
	red := ev.Get("policy").Get("redaction")
	for _, rf := range references(ev) {
		if b := rf.ref.Get("redacted"); b != nil && b.Kind == KindBool && b.Bool {
			if red == nil || red.Kind != KindString {
				r.Echec("E-4", "%s rédigée sans policy.redaction", rf.chemin)
			}
		}
	}
	r.Passe("E-4")
}

func controlerApprobationForme(r *Resultats, ev *Value) {
	a := ev.Get("approval")
	if a == nil || a.Kind != KindObject {
		return
	}
	ap, sg := a.Get("approvers"), a.Get("signatures")
	if ap != nil && sg != nil && ap.Kind == KindArray && sg.Kind == KindArray && len(ap.Arr) != len(sg.Arr) {
		r.Echec("E-5", "approvers (%d) et signatures (%d) de longueurs différentes", len(ap.Arr), len(sg.Arr))
	}
	if t1, t2 := chaineDe(a, "ticket"), chaineDe(ev, "policy", "ticket"); t1 != t2 {
		r.Echec("E-5", "approval.ticket %q ≠ policy.ticket %q", t1, t2)
	}
	r.Passe("E-5")
	r.HorsPerimetre("E-9", "signatures EIP-191 (secp256k1, keccak256) hors périmètre de ce vérificateur ; structure contrôlée par E-1 et E-5")
}

func controlerReferencesEnLigne(r *Resultats, ev *Value) {
	for _, rf := range references(ev) {
		val := rf.ref.Get("value")
		if val == nil {
			continue
		}
		c, err := Canonique(val)
		if err != nil {
			r.Echec("E-6", "%s.value non canonisable : %v", rf.chemin, err)
			continue
		}
		if got := Hex0x(SHA256(c)); got != chaineDe(rf.ref, "sha256") {
			r.Echec("E-6", "%s : sha256 recalculé %s ≠ %s", rf.chemin, got, chaineDe(rf.ref, "sha256"))
		}
		if n, ok := entierDe(rf.ref, "length"); !ok || n != int64(len(c)) {
			r.Echec("E-6", "%s : length %d attendu", rf.chemin, len(c))
		}
	}
	r.Passe("E-6")
}

func controlerSignatureEvenement(r *Resultats, ev *Value, canonique []byte, cles *JeuCles) {
	keyID := chaineDe(ev, "recorder_key_id")
	sig, err := OctetsHex(chaineDe(ev, "sig"), 64)
	if err != nil {
		r.Echec("E-8", "sig : %v", err)
		return
	}
	if cles == nil {
		r.NonExecute("E-8", "aucun jeu de clés fourni")
		return
	}
	cle := cles.Trouver(keyID)
	if cle == nil {
		r.Echec("E-8", "clé %q absente de cles.json", keyID)
		return
	}
	msg := append(append([]byte{}, PrefixeSignatureEvenement...), canonique...)
	if err := VerifierEd25519(cle.PublicKey, msg, sig); err != nil {
		r.Echec("E-8", "clé %s : %v", keyID, err)
	}
	r.Passe("E-8")
}

func controlerRotation(r *Resultats, ev *Value, cles *JeuCles) {
	val := ev.Get("execution").Get("arguments").Get("value")
	if val == nil || val.Kind != KindObject {
		r.Echec("E-10", "rotation sans annonce en ligne (execution.arguments.value)")
		return
	}
	attendues := []string{"journal_id", "new_key_id", "new_public_key", "old_key_id", "org_id", "valid_from", "counter_sig"}
	for _, k := range attendues {
		if !val.Has(k) {
			r.Echec("E-10", "annonce de rotation : %s manquant", k)
		}
	}
	for _, k := range val.Keys() {
		if !dansEnum(k, attendues) {
			r.Echec("E-10", "annonce de rotation : clé inattendue %q", k)
		}
	}
	if a, b := chaineDe(val, "old_key_id"), chaineDe(ev, "recorder_key_id"); a != b {
		r.Echec("E-10", "old_key_id %q ≠ recorder_key_id %q", a, b)
	}
	if a, b := chaineDe(val, "valid_from"), chaineDe(ev, "ts"); a != b {
		r.Echec("E-10", "valid_from %q ≠ ts %q", a, b)
	}
	if a, b := chaineDe(val, "org_id"), chaineDe(ev, "org_id"); a != b {
		r.Echec("E-10", "org_id de l'annonce ≠ org_id de l'événement")
	}
	if a, b := chaineDe(val, "journal_id"), chaineDe(ev, "journal_id"); a != b {
		r.Echec("E-10", "journal_id de l'annonce ≠ journal_id de l'événement")
	}
	newID := chaineDe(val, "new_key_id")
	if !EstIdentifiantCle(newID) {
		r.Echec("E-10", "new_key_id %q n'est pas un identifiant de clé", newID)
	} else if newID == chaineDe(val, "old_key_id") {
		r.Echec("E-10", "new_key_id égal à old_key_id")
	}
	pub, err := OctetsHex(chaineDe(val, "new_public_key"), 32)
	if err != nil {
		r.Echec("E-10", "new_public_key : %v", err)
		return
	}
	cs, err := OctetsHex(chaineDe(val, "counter_sig"), 64)
	if err != nil {
		r.Echec("E-10", "counter_sig : %v", err)
		return
	}
	R := &Value{Kind: KindObject}
	for _, mb := range val.Obj {
		if mb.Key != "counter_sig" {
			R.Obj = append(R.Obj, mb)
		}
	}
	c, err := Canonique(R)
	if err != nil {
		r.Echec("E-10", "annonce de rotation non canonisable : %v", err)
		return
	}
	msg := append(append([]byte{}, PrefixeSignatureRotation...), c...)
	if err := VerifierEd25519(pub, msg, cs); err != nil {
		r.Echec("E-10", "contresignature de la nouvelle clé : %v", err)
	}
	// §8 règle 3 : cles.json annonce valid_from(nouvelle) = valid_to(ancienne) = ts de la rotation.
	ts, okTs := Ts(ev)
	if cles == nil {
		r.NonExecute("E-10", "new_public_key non confrontée à cles.json (aucun jeu de clés fourni)")
	} else {
		if cle := cles.Trouver(newID); cle == nil {
			r.Echec("E-10", "new_key_id %q absent de cles.json", newID)
		} else if !bytes.Equal(cle.PublicKey, pub) {
			r.Echec("E-10", "new_public_key ≠ clé publique de %q dans cles.json", newID)
		} else if okTs && !cle.ValidFrom.Equal(ts) {
			r.Echec("E-10", "valid_from de %s annoncé dans cles.json (%s) ≠ ts de la rotation (%s)", newID, FormaterHorodatage(cle.ValidFrom), FormaterHorodatage(ts))
		}
		if ancienne := cles.Trouver(chaineDe(val, "old_key_id")); ancienne != nil && okTs {
			if ancienne.ValidTo == nil {
				r.Echec("E-10", "valid_to de %s dans cles.json est null : attendu le ts de la rotation (%s)", ancienne.KeyID, FormaterHorodatage(ts))
			} else if !ancienne.ValidTo.Equal(ts) {
				r.Echec("E-10", "valid_to de %s annoncé dans cles.json (%s) ≠ ts de la rotation (%s)", ancienne.KeyID, FormaterHorodatage(*ancienne.ValidTo), FormaterHorodatage(ts))
			}
		}
	}
	r.Passe("E-10")
}

func controlerValiditeCle(r *Resultats, ev *Value, cles *JeuCles) {
	if cles == nil {
		r.NonExecute("E-11", "aucun jeu de clés fourni")
		return
	}
	keyID := chaineDe(ev, "recorder_key_id")
	cle := cles.Trouver(keyID)
	if cle == nil {
		r.NonExecute("E-11", fmt.Sprintf("clé %q absente de cles.json", keyID))
		return
	}
	ts, ok := Ts(ev)
	if !ok {
		r.NonExecute("E-11", "ts illisible")
		return
	}
	if !cle.Couvre(ts) {
		r.Echec("E-11", "ts %s hors de la validité annoncée %s de la clé %s", FormaterHorodatage(ts), cle.Intervalle(), keyID)
	}
	r.Passe("E-11")
}

// ControlerPaire exécute C-1, C-2 et C-3 entre deux événements consécutifs a
// (seq n) et b (seq n + 1). Les hachages sont recalculés, jamais lus.
func ControlerPaire(r *Resultats, a, b *Value, etiquette string) {
	sa, sb := Seq(a), Seq(b)
	if sa < 0 || sb < 0 || sb != sa+1 {
		r.Echec("C-1", "%s : seq %d puis %d, attendu %d", etiquette, sa, sb, sa+1)
	}
	ta, oka := Ts(a)
	tb, okb := Ts(b)
	if oka && okb && tb.Before(ta) {
		r.Echec("C-1", "%s : ts décroît (%s puis %s)", etiquette, FormaterHorodatage(ta), FormaterHorodatage(tb))
	}
	if chaineDe(a, "org_id") != chaineDe(b, "org_id") {
		r.Echec("C-1", "%s : org_id différents", etiquette)
	}
	if chaineDe(a, "journal_id") != chaineDe(b, "journal_id") {
		r.Echec("C-1", "%s : journal_id différents", etiquette)
	}
	r.Passe("C-1")
	if hash, _, err := HashEvenement(a); err != nil {
		r.NonExecute("C-2", etiquette+" : hash du précédent non calculable")
	} else if got := Hex0x(hash); got != chaineDe(b, "prev_hash") {
		r.Echec("C-2", "%s : prev_hash %s ≠ hash recalculé du précédent %s", etiquette, chaineDe(b, "prev_hash"), got)
	}
	if chaineDe(b, "prev_hash") == Zero32 {
		r.Echec("C-2", "%s : prev_hash nul pour seq %d", etiquette, sb)
	}
	r.Passe("C-2")
	attendu := chaineDe(a, "recorder_key_id")
	if EstRotation(a) {
		attendu = NouvelleCleRotation(a)
	}
	if got := chaineDe(b, "recorder_key_id"); got != attendu {
		r.Echec("C-3", "%s : recorder_key_id %q, attendu %q", etiquette, got, attendu)
	}
	r.Passe("C-3")
}

// ControlerPremier exécute la règle « prev_hash nul si et seulement si seq = 1 »
// (C-2) sur un événement dont on ne tient pas le précédent.
func ControlerPremier(r *Resultats, ev *Value, etiquette string) {
	seq := Seq(ev)
	nul := chaineDe(ev, "prev_hash") == Zero32
	if (seq == 1) != nul {
		r.Echec("C-2", "%s : prev_hash %s pour seq %d (nul si et seulement si seq = 1)", etiquette, chaineDe(ev, "prev_hash"), seq)
	}
	r.Passe("C-2")
}

// ControlerChaine exécute les contrôles d'événement sur chaque élément et les
// contrôles de paire sur chaque couple consécutif.
func ControlerChaine(evs []*Value, cles *JeuCles) *Resultats {
	r := NouveauxResultats()
	for i, ev := range evs {
		r.Fusionner(ControlerEvenement(ev, cles), fmt.Sprintf("événement %d (seq %d)", i, Seq(ev)))
	}
	if len(evs) > 0 {
		ControlerPremier(r, evs[0], fmt.Sprintf("événement 0 (seq %d)", Seq(evs[0])))
	}
	for i := 0; i+1 < len(evs); i++ {
		ControlerPaire(r, evs[i], evs[i+1], fmt.Sprintf("seq %d → %d", Seq(evs[i]), Seq(evs[i+1])))
	}
	return r
}
