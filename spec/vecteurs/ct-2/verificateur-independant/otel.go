// Ingestion OpenTelemetry (CT-2 révision 0.5, 6.8) : décodage OTLP/HTTP en
// JSON (EX-6.29) et en protobuf (EX-6.30) vers un même modèle, forme
// normalisée d'un span (EX-6.31) et corps des réponses (EX-6.27). Écrit
// depuis le seul texte de 6.8 ; aucune bibliothèque protobuf.

package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Textes des refus d'EX-6.27 (ASCII, fixes).
var TextesRefusOTel = map[int]string{
	400: "noortrace: corps OTLP non decodable",
	401: "noortrace: source OpenTelemetry non authentifiee",
	404: "noortrace: chemin inconnu",
	405: "noortrace: methode non admise",
	413: "noortrace: corps OTLP trop grand",
	415: "noortrace: type de contenu ou codage non admis",
	429: "noortrace: quota de la source atteint",
	503: "noortrace: enregistreur en mode degrade",
}

// Types de contenu d'OTLP/HTTP (EX-6.27).
const (
	MediaProtobuf = "application/x-protobuf"
	CheminOTel    = "/v1/traces"
)

// ---------------------------------------------------------------- modèle

// Sortes d'AnyValue.
const (
	avAucune = iota
	avChaine
	avBooleen
	avEntier
	avDouble
	avTableau
	avListe
	avOctets
)

type otAnyValue struct {
	sorte  int
	s      string
	b      bool
	i      int64
	d      float64
	arr    []*otAnyValue
	kv     []otKeyValue
	octets []byte
}

type otKeyValue struct {
	cle     string
	ignorer bool // keyStrindex sans key (EX-6.29)
	val     *otAnyValue
}

type otEvent struct {
	temps   string
	nom     string
	attrs   []otKeyValue
	ignores uint32
}

type otSpan struct {
	traceID, spanID, parentID string
	traceState, nom           string
	sorte                     int64
	debut, fin                string // décimal, sans zéro de tête
	attrs                     []otKeyValue
	attrsIgnores              uint32
	events                    []otEvent
	eventsIgnores             uint32
	liens                     int
	liensIgnores              uint32
	statutCode                int64
	statutMessage             string
	flags                     uint32
}

type otScopeSpans struct {
	scopeNom, scopeVersion string
	scopeAttrs             []otKeyValue
	spans                  []otSpan
	schemaURL              string
}

type otResourceSpans struct {
	resAttrs   []otKeyValue
	resIgnores uint32
	scopeSpans []otScopeSpans
	schemaURL  string
}

// ErreurOTLP : corps non décodable (400).
type ErreurOTLP struct{ Msg string }

func (e *ErreurOTLP) Error() string { return e.Msg }

func errOTLP(format string, args ...any) error {
	return &ErreurOTLP{Msg: fmt.Sprintf(format, args...)}
}

// ---------------------------------------------------------------- JSON (EX-6.29)

var (
	reHexPair    = regexp.MustCompile(`^([0-9A-Fa-f]{2})*$`)
	reFixed64    = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	reInt64      = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)
	maxUint64Big = new(big.Int).SetUint64(math.MaxUint64)
)

type decodeurJSON struct {
	profMax, membresMax int
}

// membre rend la valeur d'un champ, nil si absent ou null (null vaut absent).
func membre(o *Value, cle string) *Value {
	v := o.Get(cle)
	if v == nil || v.IsNull() {
		return nil
	}
	return v
}

func (d *decodeurJSON) bornes(v *Value, prof int) error {
	if v == nil {
		return nil
	}
	switch v.Kind {
	case KindObject:
		if prof+1 > d.profMax {
			return errOTLP("profondeur au-delà de json_max_depth")
		}
		if len(v.Obj) > d.membresMax {
			return errOTLP("membres au-delà de json_max_members")
		}
		for _, m := range v.Obj {
			if err := d.bornes(m.Val, prof+1); err != nil {
				return err
			}
		}
	case KindArray:
		if prof+1 > d.profMax {
			return errOTLP("profondeur au-delà de json_max_depth")
		}
		if len(v.Arr) > d.membresMax {
			return errOTLP("éléments au-delà de json_max_members")
		}
		for _, e := range v.Arr {
			if err := d.bornes(e, prof+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func objetJ(v *Value, champ string) (*Value, error) {
	if v == nil {
		return nil, nil
	}
	if !EstObjet(v) {
		return nil, errOTLP("%s : un objet est attendu", champ)
	}
	return v, nil
}

func tableauJ(v *Value, champ string) ([]*Value, error) {
	if v == nil {
		return nil, nil
	}
	if !EstTableau(v) {
		return nil, errOTLP("%s : un tableau est attendu", champ)
	}
	return v.Arr, nil
}

func chaineJ(v *Value, champ string) (string, error) {
	if v == nil {
		return "", nil
	}
	if !EstChaine(v) {
		return "", errOTLP("%s : une chaîne est attendue", champ)
	}
	return v.Str, nil
}

func idJ(v *Value, champ string) (string, error) {
	s, err := chaineJ(v, champ)
	if err != nil {
		return "", err
	}
	if !reHexPair.MatchString(s) {
		return "", errOTLP("%s : chiffres hexadécimaux de longueur paire attendus", champ)
	}
	return strings.ToLower(s), nil
}

// enumJ : nombre JSON entier (une chaîne est refusée), dans les bornes d'int32.
func enumJ(v *Value, champ string) (int64, error) {
	if v == nil {
		return 0, nil
	}
	if v.Kind != KindNumber || !reInt64.MatchString(v.Num) {
		return 0, errOTLP("%s : nombre entier attendu (nom d'énumération refusé)", champ)
	}
	n, err := strconv.ParseInt(v.Num, 10, 32)
	if err != nil {
		return 0, errOTLP("%s : hors des bornes", champ)
	}
	return n, nil
}

// u32J : entier 32 bits non signé, nombre entier ou chaîne décimale.
func u32J(v *Value, champ string) (uint32, error) {
	if v == nil {
		return 0, nil
	}
	var t string
	switch v.Kind {
	case KindNumber:
		t = v.Num
	case KindString:
		t = v.Str
	default:
		return 0, errOTLP("%s : entier attendu", champ)
	}
	if !reFixed64.MatchString(t) {
		return 0, errOTLP("%s : entier attendu", champ)
	}
	n, err := strconv.ParseUint(t, 10, 32)
	if err != nil {
		return 0, errOTLP("%s : hors des bornes", champ)
	}
	return uint32(n), nil
}

// i32J : entier 32 bits signé (keyStrindex, stringValueStrindex).
func i32J(v *Value, champ string) (int64, error) {
	if v == nil {
		return 0, nil
	}
	var t string
	switch v.Kind {
	case KindNumber:
		t = v.Num
	case KindString:
		t = v.Str
	default:
		return 0, errOTLP("%s : entier attendu", champ)
	}
	if !reInt64.MatchString(t) {
		return 0, errOTLP("%s : entier attendu", champ)
	}
	n, err := strconv.ParseInt(t, 10, 32)
	if err != nil {
		return 0, errOTLP("%s : hors des bornes", champ)
	}
	return n, nil
}

// fixed64J : chaîne ou nombre de texte ^(0|[1-9][0-9]*)$, au plus 2^64 − 1.
func fixed64J(v *Value, champ string) (string, error) {
	if v == nil {
		return "0", nil
	}
	var t string
	switch v.Kind {
	case KindNumber:
		t = v.Num
	case KindString:
		t = v.Str
	default:
		return "", errOTLP("%s : entier 64 bits attendu", champ)
	}
	if !reFixed64.MatchString(t) {
		return "", errOTLP("%s : entier 64 bits attendu", champ)
	}
	b, _ := new(big.Int).SetString(t, 10)
	if b.Cmp(maxUint64Big) > 0 {
		return "", errOTLP("%s : au-delà de 2^64 − 1", champ)
	}
	return t, nil
}

func (d *decodeurJSON) keyValues(v *Value, champ string, prof int) ([]otKeyValue, error) {
	arr, err := tableauJ(v, champ)
	if err != nil {
		return nil, err
	}
	out := []otKeyValue{}
	for _, e := range arr {
		o, err := objetJ(e, champ+"[]")
		if err != nil {
			return nil, err
		}
		if o == nil {
			o = ObjetVide()
		}
		var kv otKeyValue
		cle := membre(o, "key")
		if cle == nil && membre(o, "keyStrindex") != nil {
			if _, err := i32J(membre(o, "keyStrindex"), "keyStrindex"); err != nil {
				return nil, err
			}
			kv.ignorer = true
		}
		if kv.cle, err = chaineJ(cle, "key"); err != nil {
			return nil, err
		}
		vo, err := objetJ(membre(o, "value"), "value")
		if err != nil {
			return nil, err
		}
		if kv.val, err = d.anyValue(vo, prof+1); err != nil {
			return nil, err
		}
		out = append(out, kv)
	}
	return out, nil
}

func (d *decodeurJSON) anyValue(o *Value, prof int) (*otAnyValue, error) {
	av := &otAnyValue{}
	if o == nil {
		return av, nil
	}
	if prof > d.profMax {
		return nil, errOTLP("AnyValue : imbrication au-delà de json_max_depth")
	}
	n := 0
	for _, k := range []string{"stringValue", "boolValue", "intValue", "doubleValue", "arrayValue", "kvlistValue", "bytesValue", "stringValueStrindex"} {
		if membre(o, k) != nil {
			n++
		}
	}
	if n > 1 {
		return nil, errOTLP("AnyValue : deux membres ou plus")
	}
	switch {
	case membre(o, "stringValue") != nil:
		s, err := chaineJ(membre(o, "stringValue"), "stringValue")
		if err != nil {
			return nil, err
		}
		av.sorte, av.s = avChaine, s
	case membre(o, "boolValue") != nil:
		b := membre(o, "boolValue")
		if b.Kind != KindBool {
			return nil, errOTLP("boolValue : booléen attendu")
		}
		av.sorte, av.b = avBooleen, b.Bool
	case membre(o, "intValue") != nil:
		x := membre(o, "intValue")
		var t string
		switch x.Kind {
		case KindNumber:
			t = x.Num
		case KindString:
			t = x.Str
		default:
			return nil, errOTLP("intValue : entier attendu")
		}
		if !reInt64.MatchString(t) {
			return nil, errOTLP("intValue : entier attendu")
		}
		i, err := strconv.ParseInt(t, 10, 64)
		if err != nil {
			return nil, errOTLP("intValue : hors de l'intervalle d'int64")
		}
		av.sorte, av.i = avEntier, i
	case membre(o, "doubleValue") != nil:
		x := membre(o, "doubleValue")
		switch {
		case x.Kind == KindNumber:
			f, err := NombreDouble(x.Num)
			if err != nil {
				return nil, errOTLP("doubleValue : %v", err)
			}
			av.sorte, av.d = avDouble, f
		case EstChaine(x) && x.Str == "NaN":
			av.sorte, av.d = avDouble, math.NaN()
		case EstChaine(x) && x.Str == "Infinity":
			av.sorte, av.d = avDouble, math.Inf(1)
		case EstChaine(x) && x.Str == "-Infinity":
			av.sorte, av.d = avDouble, math.Inf(-1)
		default:
			return nil, errOTLP("doubleValue : nombre attendu")
		}
	case membre(o, "arrayValue") != nil:
		a, err := objetJ(membre(o, "arrayValue"), "arrayValue")
		if err != nil {
			return nil, err
		}
		vals, err := tableauJ(membre(a, "values"), "values")
		if err != nil {
			return nil, err
		}
		if len(vals) > d.membresMax {
			return nil, errOTLP("arrayValue : éléments au-delà de json_max_members")
		}
		av.sorte, av.arr = avTableau, []*otAnyValue{}
		for _, e := range vals {
			eo, err := objetJ(e, "values[]")
			if err != nil {
				return nil, err
			}
			x, err := d.anyValue(eo, prof+1)
			if err != nil {
				return nil, err
			}
			av.arr = append(av.arr, x)
		}
	case membre(o, "kvlistValue") != nil:
		a, err := objetJ(membre(o, "kvlistValue"), "kvlistValue")
		if err != nil {
			return nil, err
		}
		vals := membre(a, "values")
		if vals != nil && EstTableau(vals) && len(vals.Arr) > d.membresMax {
			return nil, errOTLP("kvlistValue : éléments au-delà de json_max_members")
		}
		kv, err := d.keyValues(vals, "values", prof+1)
		if err != nil {
			return nil, err
		}
		av.sorte, av.kv = avListe, kv
	case membre(o, "bytesValue") != nil:
		s, err := chaineJ(membre(o, "bytesValue"), "bytesValue")
		if err != nil {
			return nil, err
		}
		b, err := decoderBase64OTel(s)
		if err != nil {
			return nil, errOTLP("bytesValue : base64 invalide")
		}
		av.sorte, av.octets = avOctets, b
	case membre(o, "stringValueStrindex") != nil:
		if _, err := i32J(membre(o, "stringValueStrindex"), "stringValueStrindex"); err != nil {
			return nil, err
		}
		// valeur absente (L5-2, EX-6.29)
	}
	return av, nil
}

// decoderBase64OTel : RFC 4648 § 4 ou § 5, avec ou sans remplissage.
func decoderBase64OTel(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.Strict().DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("base64 invalide")
}

// DecoderOTLPJSON applique EX-6.29 au corps (octets décomprimés).
func DecoderOTLPJSON(corps []byte, profMax, membresMax int) ([]otResourceSpans, error) {
	v, err := ParseJSON(corps)
	if err != nil {
		return nil, errOTLP("JSON non strict : %v", err)
	}
	d := &decodeurJSON{profMax: profMax, membresMax: membresMax}
	if err := d.bornes(v, 0); err != nil {
		return nil, err
	}
	racine, err := objetJ(v, "racine")
	if err != nil {
		return nil, err
	}
	if racine == nil {
		return nil, errOTLP("racine : un objet est attendu")
	}
	rsArr, err := tableauJ(membre(racine, "resourceSpans"), "resourceSpans")
	if err != nil {
		return nil, err
	}
	var out []otResourceSpans
	for _, rsv := range rsArr {
		rso, err := objetJ(rsv, "resourceSpans[]")
		if err != nil {
			return nil, err
		}
		if rso == nil {
			rso = ObjetVide()
		}
		var rs otResourceSpans
		res, err := objetJ(membre(rso, "resource"), "resource")
		if err != nil {
			return nil, err
		}
		if res != nil {
			if rs.resAttrs, err = d.keyValues(membre(res, "attributes"), "attributes", 2); err != nil {
				return nil, err
			}
			if rs.resIgnores, err = u32J(membre(res, "droppedAttributesCount"), "droppedAttributesCount"); err != nil {
				return nil, err
			}
		}
		if rs.schemaURL, err = chaineJ(membre(rso, "schemaUrl"), "schemaUrl"); err != nil {
			return nil, err
		}
		ssArr, err := tableauJ(membre(rso, "scopeSpans"), "scopeSpans")
		if err != nil {
			return nil, err
		}
		for _, ssv := range ssArr {
			sso, err := objetJ(ssv, "scopeSpans[]")
			if err != nil {
				return nil, err
			}
			if sso == nil {
				sso = ObjetVide()
			}
			var ss otScopeSpans
			sc, err := objetJ(membre(sso, "scope"), "scope")
			if err != nil {
				return nil, err
			}
			if sc != nil {
				if ss.scopeNom, err = chaineJ(membre(sc, "name"), "name"); err != nil {
					return nil, err
				}
				if ss.scopeVersion, err = chaineJ(membre(sc, "version"), "version"); err != nil {
					return nil, err
				}
				if ss.scopeAttrs, err = d.keyValues(membre(sc, "attributes"), "attributes", 3); err != nil {
					return nil, err
				}
				if _, err = u32J(membre(sc, "droppedAttributesCount"), "droppedAttributesCount"); err != nil {
					return nil, err
				}
			}
			if ss.schemaURL, err = chaineJ(membre(sso, "schemaUrl"), "schemaUrl"); err != nil {
				return nil, err
			}
			spArr, err := tableauJ(membre(sso, "spans"), "spans")
			if err != nil {
				return nil, err
			}
			for _, spv := range spArr {
				spo, err := objetJ(spv, "spans[]")
				if err != nil {
					return nil, err
				}
				if spo == nil {
					spo = ObjetVide()
				}
				sp, err := d.span(spo)
				if err != nil {
					return nil, err
				}
				ss.spans = append(ss.spans, sp)
			}
			rs.scopeSpans = append(rs.scopeSpans, ss)
		}
		out = append(out, rs)
	}
	return out, nil
}

func (d *decodeurJSON) span(o *Value) (otSpan, error) {
	var s otSpan
	var err error
	if s.traceID, err = idJ(membre(o, "traceId"), "traceId"); err != nil {
		return s, err
	}
	if s.spanID, err = idJ(membre(o, "spanId"), "spanId"); err != nil {
		return s, err
	}
	if s.parentID, err = idJ(membre(o, "parentSpanId"), "parentSpanId"); err != nil {
		return s, err
	}
	if s.traceState, err = chaineJ(membre(o, "traceState"), "traceState"); err != nil {
		return s, err
	}
	if s.nom, err = chaineJ(membre(o, "name"), "name"); err != nil {
		return s, err
	}
	if s.sorte, err = enumJ(membre(o, "kind"), "kind"); err != nil {
		return s, err
	}
	if s.debut, err = fixed64J(membre(o, "startTimeUnixNano"), "startTimeUnixNano"); err != nil {
		return s, err
	}
	if s.fin, err = fixed64J(membre(o, "endTimeUnixNano"), "endTimeUnixNano"); err != nil {
		return s, err
	}
	if s.attrs, err = d.keyValues(membre(o, "attributes"), "attributes", 5); err != nil {
		return s, err
	}
	if s.attrsIgnores, err = u32J(membre(o, "droppedAttributesCount"), "droppedAttributesCount"); err != nil {
		return s, err
	}
	evs, err := tableauJ(membre(o, "events"), "events")
	if err != nil {
		return s, err
	}
	s.events = []otEvent{}
	for _, ev := range evs {
		eo, err := objetJ(ev, "events[]")
		if err != nil {
			return s, err
		}
		if eo == nil {
			eo = ObjetVide()
		}
		var e otEvent
		if e.temps, err = fixed64J(membre(eo, "timeUnixNano"), "timeUnixNano"); err != nil {
			return s, err
		}
		if e.nom, err = chaineJ(membre(eo, "name"), "name"); err != nil {
			return s, err
		}
		if e.attrs, err = d.keyValues(membre(eo, "attributes"), "attributes", 6); err != nil {
			return s, err
		}
		if e.ignores, err = u32J(membre(eo, "droppedAttributesCount"), "droppedAttributesCount"); err != nil {
			return s, err
		}
		s.events = append(s.events, e)
	}
	if s.eventsIgnores, err = u32J(membre(o, "droppedEventsCount"), "droppedEventsCount"); err != nil {
		return s, err
	}
	liens, err := tableauJ(membre(o, "links"), "links")
	if err != nil {
		return s, err
	}
	for _, l := range liens {
		if _, err := objetJ(l, "links[]"); err != nil {
			return s, err
		}
	}
	s.liens = len(liens)
	if s.liensIgnores, err = u32J(membre(o, "droppedLinksCount"), "droppedLinksCount"); err != nil {
		return s, err
	}
	st, err := objetJ(membre(o, "status"), "status")
	if err != nil {
		return s, err
	}
	if st != nil {
		if s.statutMessage, err = chaineJ(membre(st, "message"), "message"); err != nil {
			return s, err
		}
		if s.statutCode, err = enumJ(membre(st, "code"), "status.code"); err != nil {
			return s, err
		}
	}
	if s.flags, err = u32J(membre(o, "flags"), "flags"); err != nil {
		return s, err
	}
	return s, nil
}

// ---------------------------------------------------------------- protobuf (EX-6.30)

type lecteurPB struct {
	b   []byte
	pos int
}

func (l *lecteurPB) fin() bool { return l.pos >= len(l.b) }

func (l *lecteurPB) varint() (uint64, error) {
	var v uint64
	for i := 0; i < 10; i++ {
		if l.pos >= len(l.b) {
			return 0, errOTLP("varint tronqué")
		}
		c := l.b[l.pos]
		l.pos++
		v |= uint64(c&0x7f) << (7 * uint(i))
		if c < 0x80 {
			return v, nil
		}
	}
	return 0, errOTLP("varint de plus de dix octets")
}

func (l *lecteurPB) etiquette() (int, int, error) {
	t, err := l.varint()
	if err != nil {
		return 0, 0, err
	}
	num, wt := int(t>>3), int(t&7)
	if num == 0 {
		return 0, 0, errOTLP("étiquette de champ 0")
	}
	if wt == 3 || wt == 4 || wt == 6 || wt == 7 {
		return 0, 0, errOTLP("type de fil %d refusé", wt)
	}
	return num, wt, nil
}

func (l *lecteurPB) octetsLEN() ([]byte, error) {
	n, err := l.varint()
	if err != nil {
		return nil, err
	}
	if n > uint64(len(l.b)-l.pos) {
		return nil, errOTLP("longueur au-delà du message englobant")
	}
	b := l.b[l.pos : l.pos+int(n)]
	l.pos += int(n)
	return b, nil
}

func (l *lecteurPB) fixe(n int) ([]byte, error) {
	if len(l.b)-l.pos < n {
		return nil, errOTLP("corps tronqué")
	}
	b := l.b[l.pos : l.pos+n]
	l.pos += n
	return b, nil
}

// sauter saute un champ inconnu selon son type de fil (0, 1, 2, 5).
func (l *lecteurPB) sauter(wt int) error {
	var err error
	switch wt {
	case 0:
		_, err = l.varint()
	case 1:
		_, err = l.fixe(8)
	case 2:
		_, err = l.octetsLEN()
	case 5:
		_, err = l.fixe(4)
	}
	return err
}

// champsPB parcourt un message : pour chaque champ connu (table numéro →
// type de fil attendu, répété ou non), appelle f ; saute les inconnus.
type defChamp struct {
	wt      int
	repete  bool
	ignorer bool // champ connu ignoré (entity_refs)
}

func champsPB(b []byte, defs map[int]defChamp, f func(num int, l *lecteurPB) error) error {
	l := &lecteurPB{b: b}
	vus := map[int]bool{}
	for !l.fin() {
		num, wt, err := l.etiquette()
		if err != nil {
			return err
		}
		def, connu := defs[num]
		if !connu || def.ignorer {
			if err := l.sauter(wt); err != nil {
				return err
			}
			continue
		}
		if wt != def.wt {
			return errOTLP("champ %d : type de fil %d au lieu de %d", num, wt, def.wt)
		}
		if !def.repete && vus[num] {
			return errOTLP("champ %d non répété présent deux fois", num)
		}
		vus[num] = true
		if err := f(num, l); err != nil {
			return err
		}
	}
	return nil
}

func chainePB(l *lecteurPB) (string, error) {
	b, err := l.octetsLEN()
	if err != nil {
		return "", err
	}
	if !utf8.Valid(b) {
		return "", errOTLP("chaîne qui n'est pas de l'UTF-8 valide")
	}
	return string(b), nil
}

func u32PB(l *lecteurPB) (uint32, error) {
	v, err := l.varint()
	if err != nil {
		return 0, err
	}
	if v > math.MaxUint32 {
		return 0, errOTLP("entier 32 bits hors des bornes")
	}
	return uint32(v), nil
}

type decodeurPB struct {
	profMax, membresMax int
}

func (d *decodeurPB) keyValue(b []byte, prof int) (otKeyValue, error) {
	var kv otKeyValue
	aCle, aStrindex := false, false
	err := champsPB(b, map[int]defChamp{1: {wt: 2}, 2: {wt: 2}, 3: {wt: 0}}, func(num int, l *lecteurPB) error {
		switch num {
		case 1:
			s, err := chainePB(l)
			kv.cle, aCle = s, true
			return err
		case 2:
			v, err := l.octetsLEN()
			if err != nil {
				return err
			}
			kv.val, err = d.anyValue(v, prof+1)
			return err
		case 3:
			aStrindex = true
			_, err := l.varint()
			return err
		}
		return nil
	})
	if err != nil {
		return kv, err
	}
	if kv.val == nil {
		kv.val = &otAnyValue{}
	}
	if !aCle && aStrindex {
		kv.ignorer = true
	}
	return kv, nil
}

func (d *decodeurPB) keyValues(liste [][]byte, prof int) ([]otKeyValue, error) {
	out := []otKeyValue{}
	for _, b := range liste {
		kv, err := d.keyValue(b, prof)
		if err != nil {
			return nil, err
		}
		out = append(out, kv)
	}
	return out, nil
}

func (d *decodeurPB) anyValue(b []byte, prof int) (*otAnyValue, error) {
	if prof > d.profMax {
		return nil, errOTLP("AnyValue : imbrication au-delà de json_max_depth")
	}
	av := &otAnyValue{}
	n := 0
	err := champsPB(b, map[int]defChamp{1: {wt: 2}, 2: {wt: 0}, 3: {wt: 0}, 4: {wt: 1}, 5: {wt: 2}, 6: {wt: 2}, 7: {wt: 2}, 8: {wt: 0}}, func(num int, l *lecteurPB) error {
		n++
		if n > 1 {
			return errOTLP("AnyValue : deux membres du oneof")
		}
		switch num {
		case 1:
			s, err := chainePB(l)
			av.sorte, av.s = avChaine, s
			return err
		case 2:
			v, err := l.varint()
			if err != nil {
				return err
			}
			if v > 1 {
				return errOTLP("bool_value autre que 0 ou 1")
			}
			av.sorte, av.b = avBooleen, v == 1
		case 3:
			v, err := l.varint()
			av.sorte, av.i = avEntier, int64(v)
			return err
		case 4:
			x, err := l.fixe(8)
			if err != nil {
				return err
			}
			av.sorte, av.d = avDouble, math.Float64frombits(binary.LittleEndian.Uint64(x))
		case 5, 6:
			x, err := l.octetsLEN()
			if err != nil {
				return err
			}
			var vals [][]byte
			if err := champsPB(x, map[int]defChamp{1: {wt: 2, repete: true}}, func(_ int, l2 *lecteurPB) error {
				e, err := l2.octetsLEN()
				vals = append(vals, e)
				return err
			}); err != nil {
				return err
			}
			if len(vals) > d.membresMax {
				return errOTLP("éléments au-delà de json_max_members")
			}
			if num == 5 {
				av.sorte, av.arr = avTableau, []*otAnyValue{}
				for _, e := range vals {
					x, err := d.anyValue(e, prof+1)
					if err != nil {
						return err
					}
					av.arr = append(av.arr, x)
				}
			} else {
				kv, err := d.keyValues(vals, prof+1)
				if err != nil {
					return err
				}
				av.sorte, av.kv = avListe, kv
			}
		case 7:
			x, err := l.octetsLEN()
			av.sorte, av.octets = avOctets, append([]byte{}, x...)
			return err
		case 8:
			_, err := l.varint() // valeur absente
			return err
		}
		return nil
	})
	return av, err
}

// DecoderOTLPProtobuf applique EX-6.30 au corps (octets décomprimés).
func DecoderOTLPProtobuf(corps []byte, profMax, membresMax int) ([]otResourceSpans, error) {
	d := &decodeurPB{profMax: profMax, membresMax: membresMax}
	var out []otResourceSpans
	err := champsPB(corps, map[int]defChamp{1: {wt: 2, repete: true}}, func(_ int, l *lecteurPB) error {
		b, err := l.octetsLEN()
		if err != nil {
			return err
		}
		rs, err := d.resourceSpans(b)
		out = append(out, rs)
		return err
	})
	return out, err
}

func (d *decodeurPB) resourceSpans(b []byte) (otResourceSpans, error) {
	var rs otResourceSpans
	err := champsPB(b, map[int]defChamp{1: {wt: 2}, 2: {wt: 2, repete: true}, 3: {wt: 2}}, func(num int, l *lecteurPB) error {
		switch num {
		case 1:
			x, err := l.octetsLEN()
			if err != nil {
				return err
			}
			var attrs [][]byte
			err = champsPB(x, map[int]defChamp{1: {wt: 2, repete: true}, 2: {wt: 0}, 3: {wt: 2, repete: true, ignorer: true}}, func(n2 int, l2 *lecteurPB) error {
				switch n2 {
				case 1:
					e, err := l2.octetsLEN()
					attrs = append(attrs, e)
					return err
				case 2:
					v, err := u32PB(l2)
					rs.resIgnores = v
					return err
				}
				return nil
			})
			if err != nil {
				return err
			}
			rs.resAttrs, err = d.keyValues(attrs, 2)
			return err
		case 2:
			x, err := l.octetsLEN()
			if err != nil {
				return err
			}
			ss, err := d.scopeSpans(x)
			rs.scopeSpans = append(rs.scopeSpans, ss)
			return err
		case 3:
			s, err := chainePB(l)
			rs.schemaURL = s
			return err
		}
		return nil
	})
	return rs, err
}

func (d *decodeurPB) scopeSpans(b []byte) (otScopeSpans, error) {
	var ss otScopeSpans
	err := champsPB(b, map[int]defChamp{1: {wt: 2}, 2: {wt: 2, repete: true}, 3: {wt: 2}}, func(num int, l *lecteurPB) error {
		switch num {
		case 1:
			x, err := l.octetsLEN()
			if err != nil {
				return err
			}
			var attrs [][]byte
			err = champsPB(x, map[int]defChamp{1: {wt: 2}, 2: {wt: 2}, 3: {wt: 2, repete: true}, 4: {wt: 0}}, func(n2 int, l2 *lecteurPB) error {
				switch n2 {
				case 1:
					s, err := chainePB(l2)
					ss.scopeNom = s
					return err
				case 2:
					s, err := chainePB(l2)
					ss.scopeVersion = s
					return err
				case 3:
					e, err := l2.octetsLEN()
					attrs = append(attrs, e)
					return err
				case 4:
					_, err := u32PB(l2)
					return err
				}
				return nil
			})
			if err != nil {
				return err
			}
			ss.scopeAttrs, err = d.keyValues(attrs, 3)
			return err
		case 2:
			x, err := l.octetsLEN()
			if err != nil {
				return err
			}
			sp, err := d.span(x)
			ss.spans = append(ss.spans, sp)
			return err
		case 3:
			s, err := chainePB(l)
			ss.schemaURL = s
			return err
		}
		return nil
	})
	return ss, err
}

func (d *decodeurPB) span(b []byte) (otSpan, error) {
	s := otSpan{debut: "0", fin: "0", events: []otEvent{}}
	var attrs [][]byte
	defs := map[int]defChamp{1: {wt: 2}, 2: {wt: 2}, 3: {wt: 2}, 4: {wt: 2}, 5: {wt: 2}, 6: {wt: 0}, 7: {wt: 1}, 8: {wt: 1},
		9: {wt: 2, repete: true}, 10: {wt: 0}, 11: {wt: 2, repete: true}, 12: {wt: 0}, 13: {wt: 2, repete: true}, 14: {wt: 0}, 15: {wt: 2}, 16: {wt: 5}}
	err := champsPB(b, defs, func(num int, l *lecteurPB) error {
		var err error
		switch num {
		case 1, 2, 4:
			x, e := l.octetsLEN()
			if e != nil {
				return e
			}
			h := hex.EncodeToString(x)
			switch num {
			case 1:
				s.traceID = h
			case 2:
				s.spanID = h
			case 4:
				s.parentID = h
			}
		case 3:
			s.traceState, err = chainePB(l)
		case 5:
			s.nom, err = chainePB(l)
		case 6:
			var v uint64
			v, err = l.varint()
			s.sorte = int64(int32(v))
		case 7, 8:
			x, e := l.fixe(8)
			if e != nil {
				return e
			}
			t := strconv.FormatUint(binary.LittleEndian.Uint64(x), 10)
			if num == 7 {
				s.debut = t
			} else {
				s.fin = t
			}
		case 9:
			x, e := l.octetsLEN()
			attrs = append(attrs, x)
			err = e
		case 10:
			s.attrsIgnores, err = u32PB(l)
		case 11:
			x, e := l.octetsLEN()
			if e != nil {
				return e
			}
			ev, e := d.event(x)
			s.events = append(s.events, ev)
			err = e
		case 12:
			s.eventsIgnores, err = u32PB(l)
		case 13:
			_, err = l.octetsLEN()
			s.liens++
		case 14:
			s.liensIgnores, err = u32PB(l)
		case 15:
			x, e := l.octetsLEN()
			if e != nil {
				return e
			}
			err = champsPB(x, map[int]defChamp{2: {wt: 2}, 3: {wt: 0}}, func(n2 int, l2 *lecteurPB) error {
				switch n2 {
				case 2:
					m, e := chainePB(l2)
					s.statutMessage = m
					return e
				case 3:
					v, e := l2.varint()
					s.statutCode = int64(int32(v))
					return e
				}
				return nil
			})
		case 16:
			x, e := l.fixe(4)
			if e != nil {
				return e
			}
			s.flags = binary.LittleEndian.Uint32(x)
		}
		return err
	})
	if err != nil {
		return s, err
	}
	s.attrs, err = d.keyValues(attrs, 5)
	return s, err
}

func (d *decodeurPB) event(b []byte) (otEvent, error) {
	e := otEvent{temps: "0"}
	var attrs [][]byte
	err := champsPB(b, map[int]defChamp{1: {wt: 1}, 2: {wt: 2}, 3: {wt: 2, repete: true}, 4: {wt: 0}}, func(num int, l *lecteurPB) error {
		switch num {
		case 1:
			x, err := l.fixe(8)
			if err != nil {
				return err
			}
			e.temps = strconv.FormatUint(binary.LittleEndian.Uint64(x), 10)
		case 2:
			s, err := chainePB(l)
			e.nom = s
			return err
		case 3:
			x, err := l.octetsLEN()
			attrs = append(attrs, x)
			return err
		case 4:
			v, err := u32PB(l)
			e.ignores = v
			return err
		}
		return nil
	})
	if err != nil {
		return e, err
	}
	e.attrs, err = d.keyValues(attrs, 6)
	return e, err
}

// ---------------------------------------------------------------- forme normalisée (EX-6.31)

// ClesContenuOTel : attributs de contenu dont une chaîne JSON est analysée.
var ClesContenuOTel = map[string]bool{
	"gen_ai.input.messages": true, "gen_ai.output.messages": true, "gen_ai.system_instructions": true,
	"gen_ai.tool.definitions": true, "gen_ai.tool.call.arguments": true, "gen_ai.tool.call.result": true,
}

const max53 = 9007199254740991

// valeurV : V(AnyValue) d'EX-6.31.
func valeurV(av *otAnyValue, doubles *int) *Value {
	if av == nil {
		return Nul()
	}
	switch av.sorte {
	case avChaine:
		return Chaine(av.s)
	case avBooleen:
		return Booleen(av.b)
	case avEntier:
		if av.i >= -max53 && av.i <= max53 {
			return Entier(av.i)
		}
		return Chaine(strconv.FormatInt(av.i, 10))
	case avDouble:
		switch {
		case math.IsNaN(av.d):
			return Chaine("NaN")
		case math.IsInf(av.d, 1):
			return Chaine("Infinity")
		case math.IsInf(av.d, -1):
			return Chaine("-Infinity")
		}
		return &Value{Kind: KindNumber, Num: NombreES6(av.d)}
	case avTableau:
		t := TableauVide()
		for _, e := range av.arr {
			t.Arr = append(t.Arr, valeurV(e, doubles))
		}
		return t
	case avListe:
		return attributsA(av.kv, doubles, false)
	case avOctets:
		return Chaine(base64.StdEncoding.EncodeToString(av.octets))
	}
	return Nul()
}

// attributsA : A(liste), première occurrence gardée (doubles comptés).
func attributsA(kvs []otKeyValue, doubles *int, contenu bool) *Value {
	o := ObjetVide()
	for _, kv := range kvs {
		if kv.ignorer {
			continue
		}
		if o.Has(kv.cle) {
			*doubles++
			continue
		}
		v := valeurV(kv.val, doubles)
		if contenu && ClesContenuOTel[kv.cle] && EstChaine(v) {
			if p, err := ParseJSON([]byte(v.Str)); err == nil {
				if _, err := CanoniqueIntegral(p); err == nil {
					v = p
				}
			}
		}
		o.Obj = append(o.Obj, Member{Key: kv.cle, Val: v})
	}
	return o
}

// SpanNormalise est un span et sa forme normalisée N(S).
type SpanNormalise struct {
	Chemin     [3]int
	N          *Value
	ClesDouble int
}

// NormaliserSpans applique EX-6.31 dans l'ordre du document.
func NormaliserSpans(rss []otResourceSpans) []SpanNormalise {
	var out []SpanNormalise
	for r, rs := range rss {
		for s, ss := range rs.scopeSpans {
			for p, sp := range ss.spans {
				doubles := 0
				parent := Nul()
				if sp.parentID != "" {
					parent = Chaine(sp.parentID)
				}
				evs := TableauVide()
				for _, e := range sp.events {
					evs.Arr = append(evs.Arr, Objet("name", Chaine(e.nom), "time_unix_nano", Chaine(e.temps),
						"attributes", attributsA(e.attrs, &doubles, false), "dropped_attributes_count", Entier(int64(e.ignores))))
				}
				schema := Nul()
				switch {
				case ss.schemaURL != "":
					schema = Chaine(ss.schemaURL)
				case rs.schemaURL != "":
					schema = Chaine(rs.schemaURL)
				}
				n := Objet(
					"trace_id", Chaine(sp.traceID),
					"span_id", Chaine(sp.spanID),
					"parent_span_id", parent,
					"trace_state", Chaine(sp.traceState),
					"name", Chaine(sp.nom),
					"flags", Entier(int64(sp.flags)),
					"kind", Entier(sp.sorte),
					"start_time_unix_nano", Chaine(sp.debut),
					"end_time_unix_nano", Chaine(sp.fin),
					"attributes", attributsA(sp.attrs, &doubles, true),
					"dropped_attributes_count", Entier(int64(sp.attrsIgnores)),
					"dropped_events_count", Entier(int64(sp.eventsIgnores)),
					"dropped_links_count", Entier(int64(sp.liensIgnores)),
					"events", evs,
					"links_count", Entier(int64(sp.liens)),
					"status", Objet("code", Entier(sp.statutCode), "message", Chaine(sp.statutMessage)),
					"resource", Objet("attributes", attributsA(rs.resAttrs, &doubles, false), "dropped_attributes_count", Entier(int64(rs.resIgnores))),
					"scope", Objet("name", Chaine(ss.scopeNom), "version", Chaine(ss.scopeVersion), "attributes", attributsA(ss.scopeAttrs, &doubles, false)),
					"schema_url", schema,
				)
				out = append(out, SpanNormalise{Chemin: [3]int{r, s, p}, N: n, ClesDouble: doubles})
			}
		}
	}
	return out
}

// ---------------------------------------------------------------- réponses (EX-6.27)

func varintPB(v uint64) []byte {
	var b []byte
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

// ReponseOTel rend le corps de la réponse : JSON (valeur) ou protobuf (octets).
func ReponseOTel(statut int, rejetes int, protobuf bool) (*Value, []byte) {
	switch {
	case statut == 200 && rejetes == 0:
		return ObjetVide(), []byte{}
	case statut == 200:
		msg := fmt.Sprintf("noortrace: %d span(s) rejete(s), identifiants invalides", rejetes)
		j := Objet("partialSuccess", Objet("rejectedSpans", Chaine(strconv.Itoa(rejetes)), "errorMessage", Chaine(msg)))
		inner := append([]byte{0x08}, varintPB(uint64(rejetes))...)
		inner = append(inner, 0x12)
		inner = append(inner, varintPB(uint64(len(msg)))...)
		inner = append(inner, msg...)
		pb := append([]byte{0x0a}, varintPB(uint64(len(inner)))...)
		return j, append(pb, inner...)
	}
	t := TextesRefusOTel[statut]
	pb := append([]byte{0x12}, varintPB(uint64(len(t)))...)
	return Objet("message", Chaine(t)), append(pb, t...)
}
