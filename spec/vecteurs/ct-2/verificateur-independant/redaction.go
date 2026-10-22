// Politique de rédaction (CT-2 §10.2) et son application (§10.4) : règles
// dans l'ordre, sélection par portée et par outil, pointeur JSON (RFC 6901),
// détecteurs dans l'ordre du tableau, actions remplacer, pseudonyme,
// supprimer ; marquage redacted par comparaison des sérialisations avant et
// après (EX-10.16) ; décompte des correspondances par règle et détecteur
// (EX-10.17).

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Les six portées de 10.2.2.
var Portees = []string{"arguments", "resultat", "requete", "reponse", "prompt_systeme", "contexte"}

// EtiquetteClePseudoTest dérive la clé de pseudonymisation de test (annexe B).
const EtiquetteClePseudoTest = "noortrace/vecteurs/v0/cle-pseudonyme/test"

// ClePseudoTestHex est la valeur imprimée par CT-2 (10.9 et annexe B).
const ClePseudoTestHex = "0x139011dc372b3ce979a162b0dee18753e67e1477ea4db3c55f929829c2ca3808"

// VariableClePseudoTest est la variable nommée par politique-pseudonyme-test.json.
const VariableClePseudoTest = "NOORTRACE_VECTEURS_CLE_PSEUDO"

// Detecteur est un détecteur de règle.
type Detecteur struct {
	Type  string // iban, avs, email, telephone, carte, regex, champ
	Nom   string // regex : clé de named_patterns
	Label string // champ : étiquette
}

// TypeJeton rend le <type> du jeton : nom du détecteur, nom du motif ou
// étiquette du champ (10.2.3).
func (d Detecteur) TypeJeton() string {
	switch d.Type {
	case "regex":
		return d.Nom
	case "champ":
		return d.Label
	}
	return d.Type
}

// Regle est une règle de rédaction.
type Regle struct {
	ID         string
	Portees    []string
	ToutOutil  bool
	Outils     []string
	Chemin     *string
	Detecteurs []Detecteur
	Action     string // remplacer, pseudonyme, supprimer
}

// Politique est un document de rédaction chargé.
type Politique struct {
	Nom      string
	Motifs   map[string]*regexp.Regexp
	Cle      []byte // clé HMAC résolue, ou nil
	RefCle   string // description de la référence de secret
	Regles   []Regle
	Document *Value
	Jetons   *regexp.Regexp // jetons de la politique (EX-10.9)
}

// DecoderSecret décode la valeur résolue d'une référence de secret selon son
// encoding (15.2, EX-10.12) : hex (0x facultatif, longueur paire), base64
// (RFC 4648 § 4, avec remplissage), utf8.
func DecoderSecret(valeur, encoding string) ([]byte, error) {
	switch encoding {
	case "hex":
		h := strings.TrimPrefix(valeur, "0x")
		if h == "" || len(h)%2 != 0 {
			return nil, fmt.Errorf("secret hex de longueur impaire ou vide")
		}
		return hex.DecodeString(h)
	case "base64":
		if valeur == "" {
			return nil, fmt.Errorf("secret base64 vide")
		}
		return base64.StdEncoding.Strict().DecodeString(valeur)
	case "utf8":
		return []byte(valeur), nil
	}
	return nil, fmt.Errorf("encoding de secret inconnu : %q", encoding)
}

// ChargerPolitique lit un document de politique de rédaction et rend la
// politique et la liste des manquements (forme, EX-10.6). La clé de
// pseudonymisation est résolue : variable d'environnement si elle est
// définie (texte hexadécimal, avec ou sans 0x), sinon, pour la variable des
// vecteurs, la clé de test dérivée de l'annexe B.
func ChargerPolitique(doc *Value) (*Politique, []string) {
	var mq []string
	if !EstObjet(doc) {
		return nil, []string{"le document n'est pas un objet"}
	}
	p := &Politique{Motifs: map[string]*regexp.Regexp{}, Document: doc}
	if v, ok := EntierDe(doc.Get("version")); !ok || v != 0 {
		mq = append(mq, "version doit valoir 0")
	}
	p.Nom = chaineDe(doc, "name")
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,127}$`).MatchString(p.Nom) {
		mq = append(mq, fmt.Sprintf("name %q hors motif", p.Nom))
	}
	if np := doc.Get("named_patterns"); np != nil {
		if !EstObjet(np) {
			mq = append(mq, "named_patterns n'est pas un objet")
		} else {
			for _, m := range np.Obj {
				motif := chaineDe(m.Val, "pattern")
				if raison := ErreurMotifCommun(motif); raison != "" {
					mq = append(mq, fmt.Sprintf("motif nommé %q hors du sous-ensemble commun (EX-10.6) : %s", m.Key, raison))
					continue
				}
				p.Motifs[m.Key] = regexp.MustCompile(motif)
			}
		}
	}
	if pk := doc.Get("pseudonym_key"); pk != nil && !pk.IsNull() {
		env := chaineDe(pk, "env")
		encoding := chaineDe(pk, "encoding")
		switch {
		case !dansEnum(encoding, []string{"hex", "base64", "utf8"}):
			mq = append(mq, fmt.Sprintf("pseudonym_key : encoding %q absent ou inconnu (10.2.1, 15.2)", encoding))
		case env != "":
			p.RefCle = "env:" + env
			if val, ok := os.LookupEnv(env); ok {
				b, err := DecoderSecret(val, encoding)
				if err != nil {
					mq = append(mq, fmt.Sprintf("pseudonym_key : %v", err))
				}
				p.Cle = b
			} else if env == VariableClePseudoTest {
				p.Cle = SHA256([]byte(EtiquetteClePseudoTest))
			} else {
				mq = append(mq, fmt.Sprintf("pseudonym_key : variable %s non définie", env))
			}
		default:
			mq = append(mq, "pseudonym_key : seule la forme {\"env\": …, \"encoding\": …} est résolue par ce vérificateur")
		}
		if p.Cle != nil && len(p.Cle) < 32 {
			mq = append(mq, "pseudonym_key : moins de 32 octets après décodage (EX-10.12)")
		}
	}
	regles := doc.Get("rules")
	if !EstTableau(regles) || len(regles.Arr) == 0 {
		mq = append(mq, "rules absent ou vide")
		return p, mq
	}
	ids := map[string]bool{}
	for i, rv := range regles.Arr {
		r := Regle{ID: chaineDe(rv, "id")}
		if ids[r.ID] {
			mq = append(mq, fmt.Sprintf("règle %d : id %q en double", i, r.ID))
		}
		ids[r.ID] = true
		if sc := rv.Get("scopes"); EstTableau(sc) {
			for _, s := range sc.Arr {
				r.Portees = append(r.Portees, s.Str)
			}
		}
		t := rv.Get("tools")
		switch {
		case EstChaine(t) && t.Str == "*":
			r.ToutOutil = true
		case EstTableau(t):
			for _, x := range t.Arr {
				r.Outils = append(r.Outils, x.Str)
			}
		default:
			mq = append(mq, fmt.Sprintf("règle %s : tools invalide", r.ID))
		}
		if c := rv.Get("path"); c != nil {
			if !EstChaine(c) {
				mq = append(mq, fmt.Sprintf("règle %s : path n'est pas une chaîne", r.ID))
			} else {
				s := c.Str
				r.Chemin = &s
			}
		}
		champ := false
		if ds := rv.Get("detectors"); EstTableau(ds) {
			for _, dv := range ds.Arr {
				d := Detecteur{Type: chaineDe(dv, "type"), Nom: chaineDe(dv, "name"), Label: chaineDe(dv, "label")}
				switch d.Type {
				case "iban", "avs", "email", "telephone", "carte":
				case "regex":
					if p.Motifs[d.Nom] == nil {
						mq = append(mq, fmt.Sprintf("règle %s : motif nommé %q inconnu (EX-10.6)", r.ID, d.Nom))
					}
				case "champ":
					champ = true
					if r.Chemin == nil {
						mq = append(mq, fmt.Sprintf("règle %s : détecteur champ sans path (EX-10.6)", r.ID))
					}
				default:
					mq = append(mq, fmt.Sprintf("règle %s : détecteur %q inconnu", r.ID, d.Type))
				}
				r.Detecteurs = append(r.Detecteurs, d)
			}
		}
		if len(r.Detecteurs) == 0 {
			mq = append(mq, fmt.Sprintf("règle %s : aucun détecteur", r.ID))
		}
		r.Action = chaineDe(rv, "action", "kind")
		switch r.Action {
		case "remplacer":
		case "pseudonyme":
			if p.Cle == nil {
				mq = append(mq, fmt.Sprintf("règle %s : pseudonyme sans pseudonym_key (EX-10.6)", r.ID))
			}
		case "supprimer":
			if r.Chemin == nil || len(r.Detecteurs) != 1 || !champ {
				mq = append(mq, fmt.Sprintf("règle %s : supprimer exige path et le seul détecteur champ (EX-10.6)", r.ID))
			}
		default:
			mq = append(mq, fmt.Sprintf("règle %s : action %q inconnue", r.ID, r.Action))
		}
		p.Regles = append(p.Regles, r)
	}
	// Types de jetons de la politique (EX-10.9) : les cinq détecteurs nommés,
	// chaque nom de motif et chaque étiquette champ employés, prompt-systeme.
	types := []string{"iban", "avs", "carte", "email", "telephone"}
	vus := map[string]bool{}
	for _, t := range types {
		vus[t] = true
	}
	for _, r := range p.Regles {
		for _, d := range r.Detecteurs {
			if t := d.TypeJeton(); !vus[t] {
				vus[t] = true
				types = append(types, t)
			}
		}
	}
	if !vus["prompt-systeme"] {
		types = append(types, "prompt-systeme")
	}
	var alt []string
	for _, t := range types {
		alt = append(alt, regexp.QuoteMeta(t))
	}
	p.Jetons = regexp.MustCompile(`\[(?:REDIGE:(?:` + strings.Join(alt, "|") + `)|PSEUDO:(?:` + strings.Join(alt, "|") + `):[0-9a-f]{12})\]`)
	// EX-10.6 : aucun motif nommé ne fait correspondre un jeton possible.
	for nom, re := range p.Motifs {
		for _, t := range types {
			for _, jeton := range []string{"[REDIGE:" + t + "]", "[PSEUDO:" + t + ":000000000000]"} {
				if re.MatchString(jeton) {
					mq = append(mq, fmt.Sprintf("motif nommé %q fait correspondre le jeton %s (EX-10.6)", nom, jeton))
				}
			}
		}
	}
	return p, mq
}

// AliasDe rend l'alias d'un nom annoncé (découpage au premier « __ »), ou "".
func AliasDe(outil string) string {
	if i := strings.Index(outil, "__"); i > 0 {
		return outil[:i]
	}
	return ""
}

// Applicable dit si une règle s'applique à une pièce de portée donnée,
// rattachée à l'outil annoncé donné ("" sans outil) (EX-10.14, 10.2.1).
func (r Regle) Applicable(portee, outil string) bool {
	if !dansEnum(portee, r.Portees) {
		return false
	}
	if r.ToutOutil {
		return true
	}
	switch portee {
	case "requete", "reponse", "prompt_systeme":
		return false // seule la valeur "*" rend la règle applicable
	}
	if outil == "" {
		return false
	}
	for _, t := range r.Outils {
		if t == outil {
			return true
		}
		if strings.HasSuffix(t, "__*") && AliasDe(outil) == strings.TrimSuffix(t, "__*") && AliasDe(outil) != "" {
			return true
		}
	}
	return false
}

// Decompte est une ligne de décompte (EX-10.17) : règle, détecteur, nombre.
type Decompte struct {
	Regle     string
	Detecteur string // type du détecteur ; regex et champ : « regex:<nom> », « champ:<étiquette> »
	Nombre    int
}

// Jeton rend le jeton de remplacement d'une correspondance.
func (p *Politique) Jeton(action string, d Detecteur, valeur string) string {
	t := d.TypeJeton()
	if action == "pseudonyme" {
		return "[PSEUDO:" + t + ":" + Pseudonyme(p.Cle, t, valeur) + "]"
	}
	return "[REDIGE:" + t + "]"
}

// EstJeton dit si une valeur est exactement un jeton de la politique
// (EX-10.9, EX-10.11).
func (p *Politique) EstJeton(v *Value) bool {
	if v == nil || v.Kind != KindString || p.Jetons == nil {
		return false
	}
	loc := p.Jetons.FindStringIndex(v.Str)
	return loc != nil && loc[0] == 0 && loc[1] == len(v.Str)
}

// Pseudonyme calcule les 12 chiffres hexadécimaux d'EX-10.12 :
// HMAC-SHA-256(K, UTF-8(t) ‖ 0x00 ‖ UTF-8(V)), six premiers octets.
func Pseudonyme(cle []byte, t, v string) string {
	m := hmac.New(sha256.New, cle)
	m.Write([]byte(t))
	m.Write([]byte{0})
	m.Write([]byte(v))
	return hex.EncodeToString(m.Sum(nil)[:6])
}

// Resultat de l'application d'une politique à une pièce.
type ResultatRedaction struct {
	Valeur    *Value     // valeur rédigée (pièce JSON) ou chaîne (pièce texte)
	Decomptes []Decompte // par règle et détecteur, nombres non nuls additionnés sur les passages
	Notes     []string   // pointeurs non résolus
	Passages  int        // nombre de passages, celui qui ne change rien compris
}

// Appliquer applique la politique à la valeur d'une pièce de portée donnée
// (EX-10.14) : passages successifs (chaque passage applique les règles
// retenues dans l'ordre) jusqu'à un passage qui ne change rien. Pour une
// pièce texte, v est une chaîne. La valeur d'entrée n'est pas modifiée.
func (p *Politique) Appliquer(portee, outil string, v *Value) ResultatRedaction {
	res := ResultatRedaction{Valeur: Copier(v)}
	type cle struct {
		regle string
		rang  int
	}
	index := map[cle]int{}
	for passage := 0; ; passage++ {
		if passage > 64 {
			res.Notes = append(res.Notes, "rédaction : plus de 64 passages, arrêt")
			break
		}
		res.Passages++
		change := false
		for _, r := range p.Regles {
			if !r.Applicable(portee, outil) {
				continue
			}
			racine, decomptes, note := p.appliquerRegle(r, res.Valeur)
			if note != "" {
				if passage == 0 {
					res.Notes = append(res.Notes, note)
				}
				continue
			}
			res.Valeur = racine
			for rang, d := range decomptes {
				if d.Nombre == 0 {
					continue
				}
				change = true
				k := cle{r.ID, rang}
				if i, ok := index[k]; ok {
					res.Decomptes[i].Nombre += d.Nombre
				} else {
					index[k] = len(res.Decomptes)
					res.Decomptes = append(res.Decomptes, d)
				}
			}
		}
		if !change {
			break
		}
	}
	return res
}

// appliquerRegle rend la nouvelle racine, le décompte par détecteur (dans
// l'ordre du tableau detectors), ou une note si le pointeur ne résout pas.
func (p *Politique) appliquerRegle(r Regle, racine *Value) (*Value, []Decompte, string) {
	chemin := ""
	if r.Chemin != nil {
		chemin = *r.Chemin
	}
	jetons, err := DecouperPointeur(chemin)
	if err != nil {
		return racine, nil, fmt.Sprintf("règle %s : pointeur %q invalide : %v", r.ID, chemin, err)
	}
	parent, cle, indice, cible := Resoudre(racine, jetons)
	if cible == nil {
		return racine, nil, fmt.Sprintf("règle %s : pointeur %q sans cible (règle sans effet)", r.ID, chemin)
	}
	var decomptes []Decompte
	for _, d := range r.Detecteurs {
		dc := Decompte{Regle: r.ID, Detecteur: d.Type}
		if d.Type == "regex" || d.Type == "champ" {
			dc.Detecteur = d.Type + ":" + d.TypeJeton()
		}
		if d.Type == "champ" {
			if cible == nil || p.EstJeton(cible) {
				// déjà un jeton, ou membre déjà supprimé : laissé tel quel (EX-10.11)
				decomptes = append(decomptes, dc)
				continue
			}
			var nouvelle *Value
			supprime := false
			switch r.Action {
			case "supprimer":
				if parent != nil && parent.Kind == KindObject {
					Retirer(parent, cle)
					supprime = true
				} else {
					nouvelle = Chaine("[REDIGE:" + d.Label + "]")
				}
			case "pseudonyme":
				// sur la chaîne elle-même si c'est une chaîne, sur son JCS intégral sinon
				valeur := ""
				if cible.Kind == KindString {
					valeur = cible.Str
				} else {
					c, _ := CanoniqueIntegral(cible)
					valeur = string(c)
				}
				nouvelle = Chaine(p.Jeton("pseudonyme", d, valeur))
			default:
				nouvelle = Chaine("[REDIGE:" + d.Label + "]")
			}
			dc.Nombre = 1
			decomptes = append(decomptes, dc)
			if supprime {
				cible = nil
				continue
			}
			switch {
			case parent == nil:
				racine = nouvelle
			case parent.Kind == KindObject:
				Definir(parent, cle, nouvelle)
			case parent.Kind == KindArray:
				parent.Arr[indice] = nouvelle
			}
			cible = nouvelle
			continue
		}
		if cible == nil {
			decomptes = append(decomptes, dc)
			continue
		}
		n := 0
		cible = p.parcourir(cible, r.Action, d, &n)
		switch {
		case parent == nil:
			racine = cible
		case parent.Kind == KindObject:
			Definir(parent, cle, cible)
		case parent.Kind == KindArray:
			parent.Arr[indice] = cible
		}
		dc.Nombre = n
		decomptes = append(decomptes, dc)
	}
	return racine, decomptes, ""
}

// parcourir soumet chaque chaîne de v (profondeur d'abord, membres dans
// l'ordre des unités UTF-16 de leurs noms) au détecteur de texte d.
func (p *Politique) parcourir(v *Value, action string, d Detecteur, n *int) *Value {
	switch v.Kind {
	case KindString:
		s, k := p.RedigerTexte(action, d, v.Str)
		*n += k
		if k == 0 {
			return v
		}
		return Chaine(s)
	case KindArray:
		for i := range v.Arr {
			v.Arr[i] = p.parcourir(v.Arr[i], action, d, n)
		}
	case KindObject:
		ordre := make([]int, len(v.Obj))
		for i := range ordre {
			ordre[i] = i
		}
		sort.SliceStable(ordre, func(a, b int) bool { return ComparerUTF16(v.Obj[ordre[a]].Key, v.Obj[ordre[b]].Key) < 0 })
		for _, i := range ordre {
			v.Obj[i].Val = p.parcourir(v.Obj[i].Val, action, d, n)
		}
	}
	return v
}

// RedigerTexte applique un détecteur de texte à une chaîne, segment par
// segment entre les jetons (EX-10.9), et rend la chaîne produite et le
// nombre de correspondances remplacées.
func (p *Politique) RedigerTexte(action string, d Detecteur, s string) (string, int) {
	var sb strings.Builder
	total := 0
	prec := 0
	var bornes [][]int
	if p.Jetons != nil {
		bornes = p.Jetons.FindAllStringIndex(s, -1)
	}
	segment := func(texte string) {
		runes := []rune(texte)
		var cs []Correspondance
		switch d.Type {
		case "iban":
			cs = DetecterIBAN(runes)
		case "avs":
			cs = DetecterAVS(runes)
		case "carte":
			cs = DetecterCarte(runes)
		case "email":
			cs = DetecterEmail(runes)
		case "telephone":
			cs = DetecterTelephone(runes)
		case "regex":
			if re := p.Motifs[d.Nom]; re != nil {
				cs = DetecterMotif(re, runes)
			}
		}
		k := 0
		for _, c := range cs {
			sb.WriteString(string(runes[k:c.Debut]))
			sb.WriteString(p.Jeton(action, d, c.Valeur))
			k = c.Fin
		}
		sb.WriteString(string(runes[k:]))
		total += len(cs)
	}
	for _, b := range bornes {
		segment(s[prec:b[0]])
		sb.WriteString(s[b[0]:b[1]])
		prec = b[1]
	}
	segment(s[prec:])
	if total == 0 {
		return s, 0
	}
	return sb.String(), total
}

// ---------------------------------------------------------------- RFC 6901

// DecouperPointeur découpe un pointeur JSON (RFC 6901 §3, §4 : « ~1 » décodé
// avant « ~0 »).
func DecouperPointeur(p string) ([]string, error) {
	if p == "" {
		return nil, nil
	}
	if !strings.HasPrefix(p, "/") {
		return nil, fmt.Errorf("un pointeur non vide commence par « / »")
	}
	parts := strings.Split(p[1:], "/")
	for i, t := range parts {
		if regexp.MustCompile(`~[^01]|~$`).MatchString(t) {
			return nil, fmt.Errorf("échappement « ~ » invalide dans %q", t)
		}
		parts[i] = strings.ReplaceAll(strings.ReplaceAll(t, "~1", "/"), "~0", "~")
	}
	return parts, nil
}

var reIndiceTableau = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

// Resoudre évalue un pointeur découpé ; rend le parent (nil pour la racine),
// la clé ou l'indice dans le parent, et la cible (nil si non résolu). Les
// noms de membres sont comparés octet par octet, sans normalisation.
func Resoudre(racine *Value, jetons []string) (parent *Value, cle string, indice int, cible *Value) {
	cible = racine
	for _, t := range jetons {
		if cible == nil {
			return nil, "", 0, nil
		}
		switch cible.Kind {
		case KindObject:
			parent, cle = cible, t
			cible = cible.Get(t)
		case KindArray:
			if !reIndiceTableau.MatchString(t) {
				return nil, "", 0, nil
			}
			i, err := strconv.Atoi(t)
			if err != nil || i >= len(cible.Arr) {
				return nil, "", 0, nil
			}
			parent, indice = cible, i
			cible = cible.Arr[i]
		default:
			return nil, "", 0, nil
		}
	}
	return parent, cle, indice, cible
}
