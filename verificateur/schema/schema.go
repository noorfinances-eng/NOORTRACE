// Paquet schema : les dix schémas que le binaire embarque (CT-6 EX-8.1,
// EX-8.11) et un validateur JSON Schema 2020-12 limité aux mots-clés qu'ils
// emploient. Le binaire ne lit aucun schéma sur le disque.
//
// Les fichiers de schemas/ sont des copies octet pour octet de spec/schemas ;
// un test le vérifie.
package schema

import (
	"embed"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/noorfinances-eng/noortrace/verificateur/cryptographie"
	"github.com/noorfinances-eng/noortrace/verificateur/jsonv"
)

//go:embed schemas/*.json
var fichiers embed.FS

// Embarque : un schéma embarqué, son identifiant et le SHA-256 de ses octets.
type Embarque struct {
	Nom     string
	Fichier string
	ID      string
	Sha256  string
	racine  *jsonv.Valeur
}

// Ordre d'EX-8.11.
var ordre = []string{"evenement", "manifeste", "dossier", "point-de-controle", "attestation-perimetre", "registre", "validateurs", "ancres-confiance", "entetes-bitcoin", "rapport-verification"}

var (
	charge     sync.Once
	erreurInit error
	schemas    []*Embarque
	parID      = map[string]*Embarque{}
	motifs     sync.Map
)

func charger() {
	for _, nom := range ordre {
		f := "schemas/" + nom + "-v0.schema.json"
		b, err := fichiers.ReadFile(f)
		if err != nil {
			erreurInit = err
			return
		}
		v, err := jsonv.Analyser(b)
		if err != nil {
			erreurInit = fmt.Errorf("%s : %v", f, err)
			return
		}
		id := v.Membre("$id").S()
		e := &Embarque{Nom: nom, Fichier: nom + "-v0.schema.json", ID: id, Sha256: cryptographie.Hex32(cryptographie.Sha256(b)), racine: v}
		schemas = append(schemas, e)
		parID[id] = e
	}
}

// Liste rend les schémas embarqués dans l'ordre d'EX-8.11.
func Liste() ([]*Embarque, error) {
	charge.Do(charger)
	return schemas, erreurInit
}

// Octets rend les octets d'un schéma embarqué (pour les tests).
func Octets(fichier string) ([]byte, error) { return fichiers.ReadFile("schemas/" + fichier) }

// Erreur de validation : chemin de l'instance (pointeur JSON) et motif.
type Erreur struct {
	Chemin string
	Motif  string
}

func (e *Erreur) Error() string {
	c := e.Chemin
	if c == "" {
		c = "/"
	}
	return c + " : " + e.Motif
}

// Valider valide une instance contre un schéma désigné par son URI
// (identifiant du schéma suivi éventuellement d'un fragment
// « #/$defs/… »). Elle rend nil si l'instance est conforme, sinon la
// première erreur trouvée.
func Valider(uri string, instance *jsonv.Valeur) error {
	if _, err := Liste(); err != nil {
		return err
	}
	base, frag, _ := strings.Cut(uri, "#")
	e, ok := parID[base]
	if !ok {
		return fmt.Errorf("schéma inconnu : %s", base)
	}
	s, err := resoudre(e.racine, frag)
	if err != nil {
		return err
	}
	v := &validateur{base: e}
	return v.valider(s, instance, "", 0)
}

// URI des schémas, par nom court.
const (
	Evenement            = "https://noortrace.example/schemas/v0/evenement.schema.json"
	Manifeste            = "https://noortrace.example/schemas/v0/manifeste.schema.json"
	Dossier              = "https://noortrace.example/schemas/v0/dossier.schema.json"
	PointDeControle      = "https://noortrace.example/schemas/v0/point-de-controle.schema.json"
	AttestationPerimetre = "https://noortrace.example/schemas/v0/attestation-perimetre.schema.json"
	Registre             = "https://noortrace.example/schemas/v0/registre.schema.json"
	Validateurs          = "https://noortrace.example/schemas/v0/validateurs.schema.json"
	AncresConfiance      = "https://noortrace.example/schemas/v0/ancres-confiance.schema.json"
	EntetesBitcoin       = "https://noortrace.example/schemas/v0/entetes-bitcoin.schema.json"
	RapportVerification  = "https://noortrace.example/schemas/v0/rapport-verification.schema.json"
)

func resoudre(racine *jsonv.Valeur, frag string) (*jsonv.Valeur, error) {
	if frag == "" {
		return racine, nil
	}
	if !strings.HasPrefix(frag, "/") {
		return nil, fmt.Errorf("fragment non pris en charge : #%s", frag)
	}
	c := racine
	for _, seg := range strings.Split(frag[1:], "/") {
		seg = strings.ReplaceAll(strings.ReplaceAll(seg, "~1", "/"), "~0", "~")
		switch {
		case c.EstObjet():
			c = c.Membre(seg)
		case c.EstTableau():
			k, err := strconv.Atoi(seg)
			if err != nil || k < 0 || k >= len(c.Elements) {
				return nil, fmt.Errorf("pointeur invalide : #%s", frag)
			}
			c = c.Elements[k]
		default:
			c = nil
		}
		if c == nil {
			return nil, fmt.Errorf("pointeur invalide : #%s", frag)
		}
	}
	return c, nil
}

type validateur struct {
	base *Embarque
}

const profondeurSchemaMax = 256

func echec(chemin, motif string, args ...any) error {
	return &Erreur{Chemin: chemin, Motif: fmt.Sprintf(motif, args...)}
}

func genreCorrespond(t string, v *jsonv.Valeur) bool {
	switch t {
	case "null":
		return v.Genre == jsonv.Nul
	case "boolean":
		return v.Genre == jsonv.Booleen
	case "object":
		return v.Genre == jsonv.Objet
	case "array":
		return v.Genre == jsonv.Tableau
	case "string":
		return v.Genre == jsonv.Chaine
	case "number":
		return v.Genre == jsonv.Nombre && !math.IsInf(v.Num, 0) && !math.IsNaN(v.Num)
	case "integer":
		return v.Genre == jsonv.Nombre && !math.IsInf(v.Num, 0) && math.Trunc(v.Num) == v.Num
	}
	return false
}

// longueur compte les points de code (un substitut isolé codé en WTF-8
// compte pour un).
func longueur(s string) int {
	n := 0
	for i := 0; i < len(s); {
		if i+2 < len(s) && s[i] == 0xED && s[i+1] >= 0xA0 {
			i += 3
			n++
			continue
		}
		_, l := utf8.DecodeRuneInString(s[i:])
		i += l
		n++
	}
	return n
}

// traduireMotif adapte un motif ECMAScript (drapeau « u ») à la syntaxe RE2
// de Go pour les deux constructions que les schémas embarqués emploient et
// que RE2 écrit autrement : l'échappement `\uXXXX` (écrit `\x{XXXX}`) et une
// répétition `[…]{m,n}` de plus de 1000 (découpée en répétitions
// consécutives de la même classe, dont les nombres s'additionnent).
func traduireMotif(p string) string {
	var sb strings.Builder
	for i := 0; i < len(p); i++ {
		if p[i] == '\\' && i+6 <= len(p) && p[i+1] == 'u' {
			sb.WriteString(`\x{` + p[i+2:i+6] + `}`)
			i += 5
			continue
		}
		if p[i] == '\\' && i+1 < len(p) {
			sb.WriteByte(p[i])
			sb.WriteByte(p[i+1])
			i++
			continue
		}
		sb.WriteByte(p[i])
	}
	q := sb.String()
	grand := regexp.MustCompile(`(\[(?:\\.|[^\]\\])*\])\{(\d+),(\d+)\}`)
	return grand.ReplaceAllStringFunc(q, func(m string) string {
		s := grand.FindStringSubmatch(m)
		classe := s[1]
		min, _ := strconv.Atoi(s[2])
		max, _ := strconv.Atoi(s[3])
		if max <= 1000 {
			return m
		}
		var out strings.Builder
		for min > 0 || max > 0 {
			a, b := min, max
			if b > 1000 {
				b = 1000
			}
			if a > b {
				a = b
			}
			fmt.Fprintf(&out, "%s{%d,%d}", classe, a, b)
			min -= a
			max -= b
		}
		return out.String()
	})
}

func motif(p string) (*regexp.Regexp, error) {
	if r, ok := motifs.Load(p); ok {
		return r.(*regexp.Regexp), nil
	}
	r, err := regexp.Compile(traduireMotif(p))
	if err != nil {
		return nil, err
	}
	motifs.Store(p, r)
	return r, nil
}

func (v *validateur) valider(s, x *jsonv.Valeur, chemin string, prof int) error {
	if prof > profondeurSchemaMax {
		return echec(chemin, "schéma trop profond")
	}
	if s.Genre == jsonv.Booleen {
		if s.Bool {
			return nil
		}
		return echec(chemin, "valeur interdite par le schéma")
	}
	if !s.EstObjet() {
		return echec(chemin, "schéma illisible")
	}
	if r := s.Membre("$ref"); r != nil {
		cible, base, err := v.ref(r.S())
		if err != nil {
			return err
		}
		sous := &validateur{base: base}
		if err := sous.valider(cible, x, chemin, prof+1); err != nil {
			return err
		}
	}
	if t := s.Membre("type"); t != nil {
		ok := false
		if t.EstChaine() {
			ok = genreCorrespond(t.Chaine, x)
		} else {
			for _, e := range t.Elements {
				if genreCorrespond(e.S(), x) {
					ok = true
					break
				}
			}
		}
		if !ok {
			return echec(chemin, "type inattendu")
		}
	}
	if c := s.Membre("const"); c != nil && !jsonv.Egales(c, x) {
		return echec(chemin, "valeur différente de la constante du schéma")
	}
	if e := s.Membre("enum"); e != nil {
		ok := false
		for _, c := range e.Elements {
			if jsonv.Egales(c, x) {
				ok = true
				break
			}
		}
		if !ok {
			return echec(chemin, "valeur hors de l'énumération du schéma")
		}
	}
	switch x.Genre {
	case jsonv.Nombre:
		if m := s.Membre("minimum"); m != nil && x.Num < m.Num {
			return echec(chemin, "nombre inférieur au minimum %s", m.Texte)
		}
		if m := s.Membre("maximum"); m != nil && x.Num > m.Num {
			return echec(chemin, "nombre supérieur au maximum %s", m.Texte)
		}
		if m := s.Membre("multipleOf"); m != nil {
			q := x.Num / m.Num
			if math.Trunc(q) != q {
				return echec(chemin, "nombre non multiple de %s", m.Texte)
			}
		}
	case jsonv.Chaine:
		n := -1
		if m := s.Membre("minLength"); m != nil {
			n = longueur(x.Chaine)
			if float64(n) < m.Num {
				return echec(chemin, "chaîne plus courte que %s", m.Texte)
			}
		}
		if m := s.Membre("maxLength"); m != nil {
			if n < 0 {
				n = longueur(x.Chaine)
			}
			if float64(n) > m.Num {
				return echec(chemin, "chaîne plus longue que %s", m.Texte)
			}
		}
		if p := s.Membre("pattern"); p != nil {
			re, err := motif(p.S())
			if err != nil {
				return echec(chemin, "motif de schéma illisible : %v", err)
			}
			if !re.MatchString(x.Chaine) {
				return echec(chemin, "chaîne contraire au motif %s", p.S())
			}
		}
	case jsonv.Tableau:
		if err := v.tableau(s, x, chemin, prof); err != nil {
			return err
		}
	case jsonv.Objet:
		if err := v.objet(s, x, chemin, prof); err != nil {
			return err
		}
	}
	if a := s.Membre("allOf"); a != nil {
		for _, sous := range a.Elements {
			if err := v.valider(sous, x, chemin, prof+1); err != nil {
				return err
			}
		}
	}
	if a := s.Membre("anyOf"); a != nil {
		var premiere error
		ok := false
		for _, sous := range a.Elements {
			err := v.valider(sous, x, chemin, prof+1)
			if err == nil {
				ok = true
				break
			}
			if premiere == nil {
				premiere = err
			}
		}
		if !ok {
			return echec(chemin, "aucune branche de anyOf ne convient (%v)", premiere)
		}
	}
	if o := s.Membre("oneOf"); o != nil {
		n := 0
		var premiere error
		for _, sous := range o.Elements {
			err := v.valider(sous, x, chemin, prof+1)
			if err == nil {
				n++
			} else if premiere == nil {
				premiere = err
			}
		}
		if n == 0 {
			return echec(chemin, "aucune branche de oneOf ne convient (%v)", premiere)
		}
		if n > 1 {
			return echec(chemin, "plusieurs branches de oneOf conviennent")
		}
	}
	if n := s.Membre("not"); n != nil {
		if v.valider(n, x, chemin, prof+1) == nil {
			return echec(chemin, "valeur interdite par « not »")
		}
	}
	if si := s.Membre("if"); si != nil {
		if v.valider(si, x, chemin, prof+1) == nil {
			if alors := s.Membre("then"); alors != nil {
				if err := v.valider(alors, x, chemin, prof+1); err != nil {
					return err
				}
			}
		} else if sinon := s.Membre("else"); sinon != nil {
			if err := v.valider(sinon, x, chemin, prof+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func (v *validateur) ref(r string) (*jsonv.Valeur, *Embarque, error) {
	base, frag, _ := strings.Cut(r, "#")
	e := v.base
	if base != "" {
		var ok bool
		e, ok = parID[base]
		if !ok {
			return nil, nil, fmt.Errorf("référence de schéma inconnue : %s", r)
		}
	}
	s, err := resoudre(e.racine, frag)
	return s, e, err
}

func (v *validateur) tableau(s, x *jsonv.Valeur, chemin string, prof int) error {
	n := len(x.Elements)
	if m := s.Membre("minItems"); m != nil && float64(n) < m.Num {
		return echec(chemin, "moins de %s éléments", m.Texte)
	}
	if m := s.Membre("maxItems"); m != nil && float64(n) > m.Num {
		return echec(chemin, "plus de %s éléments", m.Texte)
	}
	debut := 0
	if p := s.Membre("prefixItems"); p != nil {
		for i, sous := range p.Elements {
			if i >= n {
				break
			}
			if err := v.valider(sous, x.Elements[i], chemin+"/"+strconv.Itoa(i), prof+1); err != nil {
				return err
			}
		}
		debut = len(p.Elements)
	}
	if it := s.Membre("items"); it != nil {
		for i := debut; i < n; i++ {
			if err := v.valider(it, x.Elements[i], chemin+"/"+strconv.Itoa(i), prof+1); err != nil {
				return err
			}
		}
	}
	if u := s.Membre("uniqueItems"); u != nil && u.Bool {
		for i := 0; i < n; i++ {
			for j := i + 1; j < n; j++ {
				if jsonv.Egales(x.Elements[i], x.Elements[j]) {
					return echec(chemin, "éléments %d et %d identiques", i, j)
				}
			}
		}
	}
	if c := s.Membre("contains"); c != nil {
		k := 0
		for _, e := range x.Elements {
			if v.valider(c, e, chemin, prof+1) == nil {
				k++
			}
		}
		min := 1.0
		if m := s.Membre("minContains"); m != nil {
			min = m.Num
		}
		if float64(k) < min {
			return echec(chemin, "« contains » non satisfait")
		}
		if m := s.Membre("maxContains"); m != nil && float64(k) > m.Num {
			return echec(chemin, "« maxContains » dépassé")
		}
	}
	return nil
}

func echapper(n string) string {
	return strings.ReplaceAll(strings.ReplaceAll(n, "~", "~0"), "/", "~1")
}

func (v *validateur) objet(s, x *jsonv.Valeur, chemin string, prof int) error {
	if r := s.Membre("required"); r != nil {
		for _, e := range r.Elements {
			if !x.A(e.S()) {
				return echec(chemin, "membre requis absent : %s", e.S())
			}
		}
	}
	props := s.Membre("properties")
	for _, nom := range x.Noms() {
		val := x.Membre(nom)
		if props != nil && props.A(nom) {
			if err := v.valider(props.Membre(nom), val, chemin+"/"+echapper(nom), prof+1); err != nil {
				return err
			}
			continue
		}
		if ap := s.Membre("additionalProperties"); ap != nil {
			if err := v.valider(ap, val, chemin+"/"+echapper(nom), prof+1); err != nil {
				return echec(chemin, "membre non admis : %s", nom)
			}
		}
	}
	if pn := s.Membre("propertyNames"); pn != nil {
		for _, nom := range x.Noms() {
			if err := v.valider(pn, jsonv.NouvelleChaine(nom), chemin, prof+1); err != nil {
				return err
			}
		}
	}
	if m := s.Membre("minProperties"); m != nil && float64(len(x.Noms())) < m.Num {
		return echec(chemin, "trop peu de membres")
	}
	if m := s.Membre("maxProperties"); m != nil && float64(len(x.Noms())) > m.Num {
		return echec(chemin, "trop de membres")
	}
	return nil
}
