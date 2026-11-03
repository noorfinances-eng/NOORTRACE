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
	"sort"
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

// ---------------------------------------------------------------- accès typés
//
// CT-1 §11.4 (révision 0.5) : une relation dont un terme est absent, n'a pas
// le type JSON que le schéma lui donne ou ne se calcule pas n'est pas tenue,
// et le contrôle qui l'évalue échoue. Les accès ci-dessous disent donc si le
// terme a le bon type, au lieu de rendre une valeur par défaut.

// valeurAu suit un chemin de membres d'objets ; nil si un maillon manque.
func valeurAu(v *Value, chemin ...string) *Value {
	for _, k := range chemin {
		v = v.Get(k)
	}
	return v
}

// chaineTypee rend la chaîne au chemin donné, et false si le terme est
// absent ou n'est pas une chaîne.
func chaineTypee(v *Value, chemin ...string) (string, bool) {
	v = valeurAu(v, chemin...)
	if v == nil || v.Kind != KindString {
		return "", false
	}
	return v.Str, true
}

// entierTypee rend la valeur d'un nombre entier (dans int64), et false sinon.
func entierTypee(v *Value, chemin ...string) (int64, bool) {
	v = valeurAu(v, chemin...)
	if v == nil || v.Kind != KindNumber {
		return 0, false
	}
	n, ok := estEntierJSON(v.Num)
	if !ok || !n.IsInt64() {
		return 0, false
	}
	return n.Int64(), true
}

// estObjet dit si la valeur est un objet JSON.
func estObjet(v *Value) bool { return v != nil && v.Kind == KindObject }

// estNul dit si la valeur est présente et vaut null.
func estNul(v *Value) bool { return v != nil && v.Kind == KindNull }

// SeqTypee rend le seq d'un événement s'il est un entier.
func SeqTypee(ev *Value) (int64, bool) { return entierTypee(ev, "seq") }

// TsTypee rend le ts d'un événement s'il est une date existante (§3).
func TsTypee(ev *Value) (time.Time, bool) {
	s, ok := chaineTypee(ev, "ts")
	if !ok {
		return time.Time{}, false
	}
	return ParseHorodatage(s)
}

// estBlanc dit si r est un blanc au sens de CT-1 §3 (révision 0.5) : les
// points de code de la propriété Unicode White_Space, et U+FEFF.
func estBlanc(r rune) bool {
	switch {
	case r >= 0x09 && r <= 0x0D, r == 0x20, r == 0x85, r == 0xA0, r == 0x1680,
		r >= 0x2000 && r <= 0x200A, r == 0x2028, r == 0x2029, r == 0x202F,
		r == 0x205F, r == 0x3000, r == 0xFEFF:
		return true
	}
	return false
}

// ChaineNonVide dit si s contient au moins un caractère qui n'est pas un
// blanc (CT-1 §3, révision 0.5) : la chaîne vide et une chaîne de blancs ne
// sont pas des chaînes non vides.
func ChaineNonVide(s string) bool {
	for _, r := range s {
		if !estBlanc(r) {
			return true
		}
	}
	return false
}

// HashCalculable recalcule le hash d'un événement qui est un objet dont la
// forme canonique se calcule ; false sinon (le hash d'un voisin qui n'est pas
// un objet ne se calcule pas, §11.4).
func HashCalculable(ev *Value) ([]byte, bool) {
	if !estObjet(ev) {
		return nil, false
	}
	h, _, err := HashEvenement(ev)
	if err != nil {
		return nil, false
	}
	return h, true
}

// ObjetA construit l'objet signé A = { decision, journal_id, org_id,
// request_hash, ticket } depuis l'événement (§6.3), avec les valeurs lues ;
// false si l'un des termes est absent ou n'est pas une chaîne.
func ObjetA(ev *Value) (*Value, bool) {
	a := ev.Get("approval")
	var obj []Member
	for _, k := range []struct{ cle, ou string }{{"decision", "approval"}, {"journal_id", ""}, {"org_id", ""}, {"request_hash", "approval"}, {"ticket", "approval"}} {
		src := ev
		if k.ou == "approval" {
			src = a
		}
		s, ok := chaineTypee(src, k.cle)
		if !ok {
			return nil, false
		}
		obj = append(obj, Member{Key: k.cle, Val: &Value{Kind: KindString, Str: s}})
	}
	return &Value{Kind: KindObject, Obj: obj}, true
}

// ControlerEvenement exécute E-1 à E-11 sur un événement isolé (E-9 :
// forme des signatures et recouvrement des adresses, révision 0.5). cles peut
// être nil : les contrôles qui en dépendent sont alors non exécutés. Un
// événement qui n'est pas un objet met E-1 en échec, et E-2 à E-11 ne s'y
// exécutent pas (§11.4).
func ControlerEvenement(ev *Value, cles *JeuCles) *Resultats {
	r := NouveauxResultats()
	if ev == nil || ev.Kind != KindObject {
		r.Echec("E-1", "l'événement n'est pas un objet JSON")
		for _, id := range []string{"E-2", "E-3", "E-4", "E-5", "E-6", "E-7", "E-8", "E-9", "E-10", "E-11"} {
			r.NonExecute(id, "l'événement n'est pas un objet JSON (prerequis_en_echec)")
		}
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
	// E-5 et E-9
	controlerApprobationForme(r, ev)
	// E-6
	controlerReferencesEnLigne(r, ev)
	// E-7
	hash, c, err := HashEvenement(ev)
	if err != nil {
		r.NonExecute("E-7", "forme canonique impossible")
		r.NonExecute("E-8", "forme canonique impossible")
	} else {
		if got, porte := Hex0x(hash), chaineDe(ev, "hash"); got != porte {
			r.Echec("E-7", "hash recalculé %s ≠ hash porté %s", got, porte)
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

// controlerSorte applique la règle exacte de E-3 (CT-1 §5.3, révision 0.5).
func controlerSorte(r *Resultats, ev *Value) {
	echec := func(format string, args ...any) { r.Echec("E-3", format, args...) }
	defer r.Passe("E-3")
	x := ev.Get("execution")
	tool, okTool := chaineTypee(x, "tool")
	if !okTool {
		// execution.tool qui n'est pas une chaîne : la sorte ne se lit pas
		// (§11.4, « Autres termes mal typés », révision 0.5).
		echec("execution.tool absent ou qui n'est pas une chaîne : sorte illisible")
		return
	}
	sorte := SorteDe(tool)
	if sorte == SorteReserveInconnue {
		// Aucune autre règle de E-3 ne s'applique à cet événement.
		echec("execution.tool %q dans l'espace réservé noortrace. sans être l'un des quatre noms", tool)
		return
	}
	quoi := "appel d'outil"
	if sorte != SorteOutil {
		quoi = tool
	}
	decision, okDec := chaineTypee(ev, "policy", "decision")
	approval := ev.Get("approval")
	status, okSt := chaineTypee(x, "status")
	res, dur, ise := valeurAu(x, "result"), valeurAu(x, "duration_ms"), valeurAu(x, "is_error")
	effets := ev.Get("effects")
	effetsVides := func() {
		if effets == nil || effets.Kind != KindArray || len(effets.Arr) != 0 {
			echec("%s : effects doit être un tableau vide", quoi)
		}
	}
	executee := func() {
		if !estObjet(res) {
			echec("%s : execution.result doit être une référence", quoi)
		}
		if n, ok := entierTypee(dur); !ok || n < 0 {
			echec("%s : execution.duration_ms doit être un entier ≥ 0", quoi)
		}
		if ise == nil || ise.Kind != KindBool {
			echec("%s : execution.is_error doit être un booléen", quoi)
		}
	}
	nuls := func() {
		if !estNul(res) || !estNul(dur) || !estNul(ise) {
			echec("%s : execution.result, duration_ms et is_error doivent être null", quoi)
		}
	}
	approvalNul := func() {
		if !estNul(approval) {
			echec("%s : approval doit être null", quoi)
		}
	}
	sansObjet := func() {
		if !okDec || decision != "sans_objet" {
			echec("%s : policy.decision doit valoir sans_objet", quoi)
		}
	}
	statutExecute := func() {
		if !okSt || status != "executee" {
			echec("%s : execution.status doit valoir executee", quoi)
		}
	}
	switch sorte {
	case SorteOutil:
		// Règle 1 : appel d'outil.
		if !okDec || !dansEnum(decision, []string{"autorise", "a_approuver", "refuse"}) {
			echec("appel d'outil : policy.decision doit valoir autorise, a_approuver ou refuse")
		}
		if approval == nil {
			echec("appel d'outil : approval absent")
		} else if !estNul(approval) && decision != "a_approuver" {
			echec("appel d'outil : approval non nul avec policy.decision %q (seulement avec a_approuver)", decision)
		}
		decApp, okDecApp := chaineTypee(approval, "decision")
		switch {
		case !okSt:
			echec("appel d'outil : execution.status absent ou mal typé")
		case status == "retenue":
			if decision != "a_approuver" || !estNul(approval) {
				echec("appel d'outil retenu : policy.decision a_approuver et approval nul attendus")
			}
			nuls()
			effetsVides()
		case status == "executee":
			if !(decision == "autorise" || (decision == "a_approuver" && estObjet(approval) && okDecApp && decApp == "approuve")) {
				echec("appel d'outil exécuté : policy.decision autorise, ou a_approuver avec approval.decision approuve, attendus")
			}
			executee()
		case status == "refusee":
			if !(decision == "refuse" || (decision == "a_approuver" && estObjet(approval) && okDecApp && (decApp == "refuse" || decApp == "expire"))) {
				echec("appel d'outil refusé : policy.decision refuse, ou a_approuver avec approval.decision refuse ou expire, attendus")
			}
			nuls()
			effetsVides()
		default:
			echec("appel d'outil : execution.status %q inconnu", status)
		}
	case SorteModele:
		// Règle 2 : échange avec le modèle ; intent et effects non contraints.
		sansObjet()
		approvalNul()
		statutExecute()
		executee()
	default:
		// Règle 3 : décision d'approbation, rotation de clé, changement de politique.
		sansObjet()
		statutExecute()
		nuls()
		if !estNul(ev.Get("intent")) {
			echec("%s : intent doit être null", quoi)
		}
		val := valeurAu(x, "arguments", "value")
		if val == nil {
			echec("%s : execution.arguments doit être une référence en ligne (membre value)", quoi)
		}
		lanceParEnregistreur := func() {
			if lb, ok := chaineTypee(ev, "delegation", "launched_by"); !ok || lb != "noortrace-enregistreur" {
				echec("%s : delegation.launched_by doit valoir \"noortrace-enregistreur\"", quoi)
			}
		}
		switch sorte {
		case SorteApprobation:
			if !estObjet(approval) {
				echec("%s : approval doit être un objet", quoi)
			}
			if val != nil {
				if a, ok := ObjetA(ev); !ok || !memeCanonique(val, a) {
					ca, _ := Canonique(val)
					echec("%s : execution.arguments.value (%s) n'a pas la forme canonique de A construit depuis approval", quoi, ca)
				}
			}
			effetsVides()
		case SorteRotation:
			approvalNul()
			lanceParEnregistreur()
			nouvelle, ok := chaineTypee(val, "new_key_id")
			attendu := &Value{Kind: KindArray, Arr: []*Value{{Kind: KindObject, Obj: []Member{
				{Key: "system", Val: &Value{Kind: KindString, Str: "noortrace"}},
				{Key: "action", Val: &Value{Kind: KindString, Str: "ecriture"}},
				{Key: "object", Val: &Value{Kind: KindString, Str: "cle:" + nouvelle}},
				{Key: "amount", Val: &Value{Kind: KindNull}},
				{Key: "currency", Val: &Value{Kind: KindNull}},
			}}}}
			if !ok || !memeCanonique(effets, attendu) {
				echec("rotation : effects doit être exactement [{noortrace, ecriture, \"cle:<new_key_id>\", null, null}] (§8, règle 4)")
			}
		case SortePolitique:
			approvalNul()
			lanceParEnregistreur()
			if val != nil {
				pv, okPv := chaineTypee(val, "policy_version")
				ps, okPs := chaineTypee(val, "policy_sha256")
				switch {
				case !estObjet(val) || len(val.Obj) != 2 || !okPv || !okPs:
					echec("%s : value doit être un objet de deux membres exactement, policy_version et policy_sha256 (chaînes)", quoi)
				case longueurChaine(pv) < 1 || longueurChaine(pv) > 128:
					echec("%s : policy_version de %d caractères, attendu de 1 à 128", quoi, longueurChaine(pv))
				case !EstHex(ps, 32):
					echec("%s : policy_sha256 doit être 32 octets en hexadécimal", quoi)
				}
			}
		}
	}
}

// ObjetSigneApprobation construit A = { decision, journal_id, org_id,
// request_hash, ticket } depuis l'événement (§6.3) ; un terme qui n'est pas
// une chaîne y devient la chaîne vide (pour l'affichage des valeurs des
// vecteurs ; les contrôles emploient ObjetA).
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

// controlerRedaction applique E-4 (révision 0.5) : toute référence
// redacted: true (intent, execution.arguments, execution.result, éléments de
// context) exige un policy.redaction qui est une chaîne non vide au sens de
// §3 ; null, "" et une chaîne de blancs mettent E-4 en échec.
func controlerRedaction(r *Resultats, ev *Value) {
	red, ok := chaineTypee(ev, "policy", "redaction")
	var objets []referenceSituee
	ajouter := func(ch string, v *Value) {
		if estObjet(v) {
			objets = append(objets, referenceSituee{ch, v})
		}
	}
	ajouter("intent", ev.Get("intent"))
	ajouter("execution.arguments", valeurAu(ev, "execution", "arguments"))
	ajouter("execution.result", valeurAu(ev, "execution", "result"))
	if cx := ev.Get("context"); cx != nil && cx.Kind == KindArray {
		for i, c := range cx.Arr {
			ajouter(fmt.Sprintf("context[%d]", i), c)
		}
	}
	for _, rf := range objets {
		if b := rf.ref.Get("redacted"); b != nil && b.Kind == KindBool && b.Bool && (!ok || !ChaineNonVide(red)) {
			r.Echec("E-4", "%s rédigée sans policy.redaction chaîne non vide (§3)", rf.chemin)
		}
	}
	r.Passe("E-4")
}

// controlerApprobationForme applique E-5 et E-9 à un événement dont approval
// n'est pas nul (CT-1 §6.3 et §11.4 révision 0.5, CT-6 EX-5.19) :
// approvers ou signatures qui n'est pas un tableau met E-5 et E-9 en échec ;
// E-9 parcourt les signatures : une signature sans approvers[i], non
// canonique (65 octets, s dans la moitié basse, v ∈ {27, 28}), ou dont
// l'adresse recouvrée sur M = keccak256("\x19Ethereum Signed Message:\n32" ‖
// D_A) n'est pas approvers[i], la met en échec ; un approbateur sans
// signature relève de E-5 seule.
func controlerApprobationForme(r *Resultats, ev *Value) {
	a := ev.Get("approval")
	if a == nil || a.Kind == KindNull {
		return
	}
	if a.Kind != KindObject {
		r.Echec("E-5", "approval n'est ni null ni un objet")
		r.Echec("E-9", "approval n'est ni null ni un objet : aucune signature lisible")
		return
	}
	ap, sg := a.Get("approvers"), a.Get("signatures")
	tableaux := ap != nil && sg != nil && ap.Kind == KindArray && sg.Kind == KindArray
	if !tableaux {
		r.Echec("E-5", "approval.approvers et approval.signatures doivent être des tableaux")
	} else if len(ap.Arr) != len(sg.Arr) {
		r.Echec("E-5", "approvers (%d) et signatures (%d) de longueurs différentes", len(ap.Arr), len(sg.Arr))
	}
	t1, ok1 := chaineTypee(a, "ticket")
	t2, ok2 := chaineTypee(ev, "policy", "ticket")
	if !ok1 || !ok2 || t1 != t2 {
		r.Echec("E-5", "approval.ticket %q ≠ policy.ticket %q", t1, t2)
	}
	r.Passe("E-5")

	// E-9 : signatures EIP-191 (§6.3).
	if !tableaux {
		r.Echec("E-9", "approval.approvers ou approval.signatures n'est pas un tableau (CT-6 EX-5.19)")
		return
	}
	var m []byte
	if obj, ok := ObjetA(ev); ok {
		if da, err := CondenseApprobation(obj); err == nil {
			m = MessageEIP191(da)
		}
	}
	for i, s := range sg.Arr {
		if i >= len(ap.Arr) {
			r.Echec("E-9", "signatures[%d] sans approvers[%d]", i, i)
			continue
		}
		hexsig, ok := chaineTypee(s)
		if !ok {
			r.Echec("E-9", "signatures[%d] : chaîne attendue", i)
			continue
		}
		if err := FormeSignatureEIP191(hexsig); err != nil {
			r.Echec("E-9", "signatures[%d] : %v", i, err)
			continue
		}
		if m == nil {
			r.Echec("E-9", "signatures[%d] : D_A non calculable (terme de A absent ou mal typé)", i)
			continue
		}
		rec, err := recouvrerSignatureEIP191(m, hexsig)
		if err != nil {
			r.Echec("E-9", "signatures[%d] : %v", i, err)
			continue
		}
		if ad, ok := chaineTypee(ap.Arr[i]); !ok || ad != rec {
			r.Echec("E-9", "signatures[%d] : adresse recouvrée %s ≠ approvers[%d] %s", i, rec, i, ad)
		}
	}
	r.Passe("E-9")
}

// FormeSignatureEIP191 contrôle la forme d'une signature d'approbateur (§6.3) :
// 65 octets, s dans la moitié basse de l'ordre de secp256k1, v de 27 ou 28.
func FormeSignatureEIP191(hexsig string) error {
	b, err := OctetsHex(hexsig, 65)
	if err != nil {
		return err
	}
	s, v := new(big.Int).SetBytes(b[32:64]), int(b[64])
	switch {
	case v != 27 && v != 28:
		return fmt.Errorf("v = %d hors de {27, 28}", v)
	case s.Cmp(secpDemiN) > 0:
		return fmt.Errorf("s dans la moitié haute de l'ordre : signature non canonique")
	}
	return nil
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
		if got, att := Hex0x(SHA256(c)), chaineDe(rf.ref, "sha256"); got != att {
			r.Echec("E-6", "%s : sha256 recalculé %s ≠ %s", rf.chemin, got, att)
		}
		if n, ok := entierDe(rf.ref, "length"); !ok || n != int64(len(c)) {
			r.Echec("E-6", "%s : length %d attendu", rf.chemin, len(c))
		}
	}
	r.Passe("E-6")
}

func controlerSignatureEvenement(r *Resultats, ev *Value, canonique []byte, cles *JeuCles) {
	keyID, okKey := chaineTypee(ev, "recorder_key_id")
	sig, err := OctetsHex(chaineDe(ev, "sig"), 64)
	if err != nil {
		r.Echec("E-8", "sig : %v", err)
		return
	}
	if cles == nil {
		r.NonExecute("E-8", "cles.json inexploitable ou non fourni")
		return
	}
	cle := cles.Trouver(keyID)
	if !okKey || cle == nil {
		r.Echec("E-8", "clé %q absente de cles.json", keyID)
		return
	}
	msg := append(append([]byte{}, PrefixeSignatureEvenement...), canonique...)
	if err := VerifierEd25519(cle.PublicKey, msg, sig); err != nil {
		r.Echec("E-8", "clé %s : %v", keyID, err)
	}
	r.Passe("E-8")
}

// controlerRotation applique E-10 ; chaque égalité porte sur les valeurs
// lues, et un terme absent ou mal typé la met en échec (§11.4).
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
	egal := func(a, b string, okA, okB bool) bool { return okA && okB && a == b }
	if a, okA := chaineTypee(val, "old_key_id"); !func() bool { b, okB := chaineTypee(ev, "recorder_key_id"); return egal(a, b, okA, okB) }() {
		r.Echec("E-10", "old_key_id %q ≠ recorder_key_id %q", a, chaineDe(ev, "recorder_key_id"))
	}
	if a, okA := chaineTypee(val, "valid_from"); !func() bool { b, okB := chaineTypee(ev, "ts"); return egal(a, b, okA, okB) }() {
		r.Echec("E-10", "valid_from %q ≠ ts %q", a, chaineDe(ev, "ts"))
	}
	for _, k := range []string{"org_id", "journal_id"} {
		a, okA := chaineTypee(val, k)
		b, okB := chaineTypee(ev, k)
		if !egal(a, b, okA, okB) {
			r.Echec("E-10", "%s de l'annonce ≠ %s de l'événement", k, k)
		}
	}
	newID, _ := chaineTypee(val, "new_key_id")
	oldID, _ := chaineTypee(val, "old_key_id")
	if !EstIdentifiantCle(newID) {
		r.Echec("E-10", "new_key_id %q n'est pas un identifiant de clé", newID)
	} else if newID == oldID {
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
	if cles == nil {
		r.NonExecute("E-10", "new_public_key non confrontée à cles.json (cles.json inexploitable ou non fourni)")
	} else {
		ts, okTs := TsTypee(ev)
		if cle := cles.Trouver(newID); cle == nil {
			r.Echec("E-10", "new_key_id %q absent de cles.json", newID)
		} else if !bytes.Equal(cle.PublicKey, pub) {
			r.Echec("E-10", "new_public_key ≠ clé publique de %q dans cles.json", newID)
		} else if !okTs {
			r.Echec("E-10", "ts de la rotation n'est pas une date existante : valid_from de %s non comparable", newID)
		} else if !cle.ValidFrom.Equal(ts) {
			r.Echec("E-10", "valid_from de %s annoncé dans cles.json (%s) ≠ ts de la rotation (%s)", newID, FormaterHorodatage(cle.ValidFrom), FormaterHorodatage(ts))
		}
		if ancienne := cles.Trouver(oldID); ancienne != nil {
			switch {
			case !okTs:
				r.Echec("E-10", "ts de la rotation n'est pas une date existante : valid_to de %s non comparable", ancienne.KeyID)
			case ancienne.ValidTo == nil:
				r.Echec("E-10", "valid_to de %s dans cles.json est null : attendu le ts de la rotation (%s)", ancienne.KeyID, FormaterHorodatage(ts))
			case !ancienne.ValidTo.Equal(ts):
				r.Echec("E-10", "valid_to de %s annoncé dans cles.json (%s) ≠ ts de la rotation (%s)", ancienne.KeyID, FormaterHorodatage(*ancienne.ValidTo), FormaterHorodatage(ts))
			}
		}
	}
	r.Passe("E-10")
}

// controlerValiditeCle applique E-11 : un ts qui n'est pas une date
// existante met E-11 en échec (relation incalculable, §11.4, révision 0.5) ;
// clé absente de cles.json : non exécuté, l'échec est porté par E-8.
func controlerValiditeCle(r *Resultats, ev *Value, cles *JeuCles) {
	if cles == nil {
		r.NonExecute("E-11", "cles.json inexploitable ou non fourni")
		return
	}
	keyID, _ := chaineTypee(ev, "recorder_key_id")
	cle := cles.Trouver(keyID)
	if cle == nil {
		r.NonExecute("E-11", fmt.Sprintf("clé %q absente de cles.json (échec porté par E-8)", keyID))
		return
	}
	ts, ok := TsTypee(ev)
	if !ok {
		r.Echec("E-11", "ts n'est pas une date existante : validité de la clé %s non comparable", keyID)
	} else if !cle.Couvre(ts) {
		r.Echec("E-11", "ts %s hors de la validité annoncée %s de la clé %s", FormaterHorodatage(ts), cle.Intervalle(), keyID)
	}
	r.Passe("E-11")
}

// cleAttendueApres rend la clé qui doit signer l'événement suivant a : le
// new_key_id de a s'il est une rotation, sinon son recorder_key_id (C-3).
func cleAttendueApres(a *Value) (string, bool) {
	if EstRotation(a) {
		return chaineTypee(a, "execution", "arguments", "value", "new_key_id")
	}
	return chaineTypee(a, "recorder_key_id")
}

// ControlerPaire exécute C-1, C-2 et C-3 entre deux événements consécutifs a
// (seq n) et b (seq n + 1) d'un dossier (voisins, §11.4). Les hachages sont
// recalculés, jamais lus ; un terme absent, mal typé ou incalculable (seq
// qui n'est pas un entier, ts qui n'est pas une date existante, hash d'un
// voisin qui n'est pas un objet) met le contrôle qui l'évalue en échec
// (révision 0.5).
func ControlerPaire(r *Resultats, a, b *Value, etiquette string) {
	sa, okA := SeqTypee(a)
	sb, okB := SeqTypee(b)
	if !okA || !okB || sb != sa+1 {
		r.Echec("C-1", "%s : seq %s puis %s, attendus consécutifs", etiquette, texteTerme(a, "seq"), texteTerme(b, "seq"))
	}
	ta, oka := TsTypee(a)
	tb, okb := TsTypee(b)
	if !oka || !okb {
		r.Echec("C-1", "%s : ts qui n'est pas une date existante, ordre non comparable", etiquette)
	} else if tb.Before(ta) {
		r.Echec("C-1", "%s : ts décroît (%s puis %s)", etiquette, FormaterHorodatage(ta), FormaterHorodatage(tb))
	}
	for _, k := range []string{"org_id", "journal_id"} {
		x, okx := chaineTypee(a, k)
		y, oky := chaineTypee(b, k)
		if !okx || !oky || x != y {
			r.Echec("C-1", "%s : %s différents", etiquette, k)
		}
	}
	r.Passe("C-1")
	ph, okPh := chaineTypee(b, "prev_hash")
	if hash, ok := HashCalculable(a); !ok {
		r.Echec("C-2", "%s : hash du précédent non calculable", etiquette)
	} else if got := Hex0x(hash); !okPh || got != ph {
		r.Echec("C-2", "%s : prev_hash %s ≠ hash recalculé du précédent %s", etiquette, ph, got)
	}
	if ph == Zero32 {
		r.Echec("C-2", "%s : prev_hash nul pour seq %s", etiquette, texteTerme(b, "seq"))
	}
	r.Passe("C-2")
	attendu, okAtt := cleAttendueApres(a)
	if got, ok := chaineTypee(b, "recorder_key_id"); !ok || !okAtt || got != attendu {
		r.Echec("C-3", "%s : recorder_key_id %q, attendu %q", etiquette, got, attendu)
	}
	r.Passe("C-3")
}

// texteTerme rend le texte d'un terme pour les messages (canonique, ou
// « absent »).
func texteTerme(v *Value, cle string) string {
	x := v.Get(cle)
	if x == nil {
		return "absent"
	}
	c, err := Canonique(x)
	if err != nil {
		return "?"
	}
	return string(c)
}

// ControlerPremier exécute la règle « prev_hash nul si et seulement si seq = 1 »
// (C-2) sur un événement dont on ne tient pas le précédent.
func ControlerPremier(r *Resultats, ev *Value, etiquette string) {
	if m, ok := origineFausse(ev); ok {
		r.Echec("C-2", "%s : %s", etiquette, m)
	}
	r.Passe("C-2")
}

// origineFausse applique « prev_hash nul si et seulement si seq = 1 » ; rend
// le message et true quand la règle n'est pas tenue (terme absent, mal typé,
// ou équivalence fausse).
//
// Exception (CT-1 §7.2 temps 1 et §11.4 « Autres termes mal typés », CT-6
// EX-5.13, révision 0.5) : la règle n'est évaluée que pour un événement dont
// seq est un entier ; sinon elle n'est ni tenue ni violée, et E-1 seule porte
// le défaut. Même règle dans un journal et dans un dossier.
func origineFausse(ev *Value) (string, bool) {
	seq, okSeq := SeqTypee(ev)
	if !okSeq {
		return "", false
	}
	ph, okPh := chaineTypee(ev, "prev_hash")
	if !okPh {
		return fmt.Sprintf("seq %d, prev_hash %s : règle d'origine non tenue (terme absent ou mal typé)", seq, texteTerme(ev, "prev_hash")), true
	}
	if (seq == 1) != (ph == Zero32) {
		return fmt.Sprintf("prev_hash %s pour seq %d (nul si et seulement si seq = 1)", ph, seq), true
	}
	return "", false
}

// ---------------------------------------------------------------- journal

// Symptome est un symptôme rapporté par la vérification d'un journal (CT-1
// §7.2, règle exacte de la révision 0.5) : un type, un contrôle et le seq de
// l'événement désigné (nil quand aucun).
type Symptome struct {
	Type     string
	Controle string
	Seq      *int64
	Message  string
}

// Texte rend « type/contrôle/seq » (seq « null » quand aucun).
func (s Symptome) Texte() string {
	seq := "null"
	if s.Seq != nil {
		seq = fmt.Sprint(*s.Seq)
	}
	return s.Type + "/" + s.Controle + "/" + seq
}

// typesSymptomes associe à E-1 à E-11 le type de leurs symptômes (§7.2).
var typesSymptomes = map[string]string{
	"E-1": "schema", "E-2": "format", "E-3": "sorte", "E-4": "redaction", "E-5": "approbation",
	"E-6": "reference", "E-7": "modification", "E-8": "signature", "E-9": "approbateur",
	"E-10": "rotation", "E-11": "validite_cle",
}

// ControlerChaine vérifie un journal (CT-1 §7.2) et rend les contrôles ; cles
// est le cles.json du journal, réputé conforme (voir ControlerJournal).
func ControlerChaine(evs []*Value, cles *JeuCles) *Resultats {
	r, _ := ControlerJournal(evs, cles, nil)
	return r
}

// ControlerJournal applique la règle exacte de la vérification d'un journal
// (CT-1 §7.2, révision 0.5), en trois temps, et rend les contrôles et les
// symptômes dans l'ordre de la règle :
//
//  1. chaque événement pour lui-même, dans l'ordre du fichier : E-1 à E-11
//     (profondeur d'au plus 128 comptée depuis l'objet de l'événement, E-1),
//     puis l'origine (C-2, type origine). cles.json est lu d'abord :
//     defautsCles porte ses manquements (schéma, dates, unicité, validités) ;
//     s'il en a, un symptôme E-8 de type cles et de seq nul est rapporté en
//     tête et E-8 n'est rapporté pour aucun événement (le jeu n'est pas
//     employé). Sinon son org_id et son journal_id sont comparés à ceux de
//     chaque événement (E-8, type signature) ;
//  2. la suite des seq sur tout le fichier (C-1) : insertion, suppression,
//     réordonnancement ;
//  3. chaque couple consécutif dans l'ordre du fichier : rupture (C-2),
//     horodatage, journal (C-1), cle (C-3).
func ControlerJournal(evs []*Value, cles *JeuCles, defautsCles []string) (*Resultats, []Symptome) {
	r := NouveauxResultats()
	var symptomes []Symptome
	ajouter := func(typ, ctrl string, ev *Value, format string, args ...any) {
		var seq *int64
		if ev != nil {
			if s, ok := SeqTypee(ev); ok {
				seq = &s
			}
		}
		msg := fmt.Sprintf(format, args...)
		symptomes = append(symptomes, Symptome{Type: typ, Controle: ctrl, Seq: seq, Message: msg})
		r.Echec(ctrl, "%s", msg)
	}
	etiq := func(i int, ev *Value) string { return fmt.Sprintf("position %d (seq %s)", i, texteTerme(ev, "seq")) }

	// Temps 1.
	if len(defautsCles) > 0 {
		ajouter("cles", "E-8", nil, "cles.json : %s", strings.Join(defautsCles, " ; "))
		cles = nil
	}
	for i, ev := range evs {
		res := ControlerEvenement(ev, cles)
		if estObjet(ev) {
			if p := Profondeur(ev); p > ProfondeurV0 {
				res.Echec("E-1", "profondeur %d de l'événement au-delà de %d (§4, règle 7)", p, ProfondeurV0)
			}
			if cles != nil {
				for _, k := range []string{"org_id", "journal_id"} {
					attendu := cles.OrgID
					if k == "journal_id" {
						attendu = cles.JournalID
					}
					if s, ok := chaineTypee(ev, k); !ok || s != attendu {
						res.Echec("E-8", "%s de l'événement différent de celui de cles.json", k)
					}
				}
			}
		}
		for _, id := range []string{"E-1", "E-2", "E-3", "E-4", "E-5", "E-6", "E-7", "E-8", "E-9", "E-10", "E-11"} {
			c := res.parID[id]
			if c == nil {
				continue
			}
			if c.Etat == EtatEchoue {
				ajouter(typesSymptomes[id], id, ev, "%s : %s", etiq(i, ev), strings.Join(c.Details, " ; "))
				continue
			}
			sous := NouveauxResultats()
			sous.parID[id], sous.ordre = c, []string{id}
			r.Fusionner(sous, etiq(i, ev))
		}
		if estObjet(ev) {
			if m, faux := origineFausse(ev); faux {
				ajouter("origine", "C-2", ev, "%s : %s", etiq(i, ev), m)
			}
		}
	}

	// Temps 2 : la suite des seq sur tout le fichier, parmi les seq entiers.
	type pos struct {
		i   int
		seq int64
		ev  *Value
	}
	var entiers []pos
	for i, ev := range evs {
		if s, ok := SeqTypee(ev); ok {
			entiers = append(entiers, pos{i, s, ev})
		}
	}
	occurrences := map[int64][]int{}
	var ordre []int64
	for _, p := range entiers {
		if len(occurrences[p.seq]) == 0 {
			ordre = append(ordre, p.seq)
		}
		occurrences[p.seq] = append(occurrences[p.seq], p.i)
	}
	for _, s := range ordre {
		if o := occurrences[s]; len(o) > 1 {
			var positions []string
			for _, i := range o {
				positions = append(positions, fmt.Sprint(i))
			}
			ajouter("insertion", "C-1", evs[o[0]], "seq %d présent %d fois (positions %s) : événement inséré", s, len(o), strings.Join(positions, ", "))
		}
	}
	tries := append([]int64{}, ordre...)
	sort.Slice(tries, func(i, j int) bool { return tries[i] < tries[j] })
	for k := 1; k < len(tries); k++ {
		if tries[k] != tries[k-1]+1 {
			ajouter("suppression", "C-1", evs[occurrences[tries[k]][0]], "seq %d à %d absents avant seq %d : événement supprimé", tries[k-1]+1, tries[k]-1, tries[k])
		}
	}
	for k := 1; k < len(entiers); k++ {
		if entiers[k].seq < entiers[k-1].seq {
			ajouter("reordonnancement", "C-1", entiers[k].ev, "seq %d (position %d) après seq %d (position %d) : ordre du journal non respecté", entiers[k].seq, entiers[k].i, entiers[k-1].seq, entiers[k-1].i)
		}
	}
	r.Passe("C-1")

	// Temps 3 : chaque couple consécutif dans l'ordre du fichier.
	for i := 0; i+1 < len(evs); i++ {
		a, b := evs[i], evs[i+1]
		ph, okPh := chaineTypee(b, "prev_hash")
		if h, ok := HashCalculable(a); !ok {
			ajouter("rupture", "C-2", b, "%s : hash de l'événement précédent dans le fichier non calculable", etiq(i+1, b))
		} else if got := Hex0x(h); !okPh || got != ph {
			ajouter("rupture", "C-2", b, "%s : prev_hash %s différent du hash recalculé de l'événement précédent dans le fichier, %s (%s)", etiq(i+1, b), ph, etiq(i, a), got)
		}
		ta, oka := TsTypee(a)
		tb, okb := TsTypee(b)
		if !oka || !okb {
			ajouter("horodatage", "C-1", b, "%s : ts qui n'est pas une date existante, ordre non comparable avec %s", etiq(i+1, b), etiq(i, a))
		} else if tb.Before(ta) {
			ajouter("horodatage", "C-1", b, "%s : ts %s antérieur à celui de %s (%s)", etiq(i+1, b), FormaterHorodatage(tb), etiq(i, a), FormaterHorodatage(ta))
		}
		for _, k := range []string{"org_id", "journal_id"} {
			x, okx := chaineTypee(a, k)
			y, oky := chaineTypee(b, k)
			if !okx || !oky || x != y {
				ajouter("journal", "C-1", b, "%s : org_id ou journal_id différent de celui de %s", etiq(i+1, b), etiq(i, a))
				break
			}
		}
		attendu, okAtt := cleAttendueApres(a)
		if got, ok := chaineTypee(b, "recorder_key_id"); !ok || !okAtt || got != attendu {
			ajouter("cle", "C-3", b, "%s : recorder_key_id %q, attendu %q", etiq(i+1, b), got, attendu)
		}
	}
	r.Passe("C-2")
	r.Passe("C-3")
	return r, symptomes
}
