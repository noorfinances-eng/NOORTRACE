// Clés publiques de l'enregistreur : fichier cles.json d'un dossier (CT-1
// §11.2, schéma dossier-v0 #/$defs/cles) et fichier des clés de test des
// vecteurs (§13).

package main

import (
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"
)

// Cle est une clé Ed25519 d'enregistreur avec sa validité annoncée.
type Cle struct {
	KeyID     string
	PublicKey []byte
	ValidFrom time.Time
	ValidTo   *time.Time // nil : encore en service
	Source    string
	Graine    []byte // clés de test seulement, peut être nil
}

// JeuCles est l'ensemble des clés connues d'un dossier ou des vecteurs.
type JeuCles struct {
	OrgID     string
	JournalID string
	Cles      []*Cle
}

// Trouver rend la clé d'identifiant donné.
func (j *JeuCles) Trouver(keyID string) *Cle {
	if j == nil {
		return nil
	}
	for _, c := range j.Cles {
		if c.KeyID == keyID {
			return c
		}
	}
	return nil
}

// Couvre dit si l'instant t est dans [valid_from, valid_to] (bornes incluses).
func (c *Cle) Couvre(t time.Time) bool {
	if t.Before(c.ValidFrom) {
		return false
	}
	if c.ValidTo != nil && t.After(*c.ValidTo) {
		return false
	}
	return true
}

// Intervalle décrit la validité annoncée, pour les messages.
func (c *Cle) Intervalle() string {
	fin := "∞"
	if c.ValidTo != nil {
		fin = FormaterHorodatage(*c.ValidTo)
	}
	return fmt.Sprintf("[%s, %s]", FormaterHorodatage(c.ValidFrom), fin)
}

const dispositionHorodatage = "2006-01-02T15:04:05.000Z"

var reHorodatage = regexp.MustCompile(`^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{3}Z$`)

// ParseHorodatage analyse un horodatage RFC 3339 UTC à trois décimales (§3).
func ParseHorodatage(s string) (time.Time, bool) {
	if !reHorodatage.MatchString(s) {
		return time.Time{}, false
	}
	t, err := time.Parse(dispositionHorodatage, s)
	if err != nil || t.UTC().Format(dispositionHorodatage) != s {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// FormaterHorodatage écrit un instant au format de §3.
func FormaterHorodatage(t time.Time) string { return t.UTC().Format(dispositionHorodatage) }

var reIdentifiantCle = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// EstIdentifiantCle applique le motif de §3.
func EstIdentifiantCle(s string) bool { return reIdentifiantCle.MatchString(s) }

func longueurChaine(s string) int { return utf8.RuneCountInString(s) }

// ChargerCles lit un objet cles.json (schéma #/$defs/cles) ou le fichier des
// clés de test (même forme, tableau `recorder_keys` au lieu de `keys`, avec
// un champ `seed` facultatif). Rend le jeu et les manquements au schéma.
func ChargerCles(v *Value) (*JeuCles, []string) {
	var m []string
	add := func(format string, args ...any) { m = append(m, fmt.Sprintf(format, args...)) }
	if v == nil || v.Kind != KindObject {
		return nil, []string{"cles : objet attendu"}
	}
	jeu := &JeuCles{}
	tableau := v.Get("keys")
	nomTableau := "keys"
	if tableau == nil {
		tableau = v.Get("recorder_keys")
		nomTableau = "recorder_keys"
	}
	for _, k := range v.Keys() {
		switch k {
		case "version", "org_id", "journal_id", nomTableau:
		case "approvers", "nonces", "description", "name", "org_slug", "journal_name":
			// clés de test : champs annexes admis
		default:
			add("cles : clé inattendue %q", k)
		}
	}
	if ver := v.Get("version"); ver == nil || ver.Kind != KindNumber || ver.Num != "0" {
		add("cles.version : constante 0 attendue")
	}
	for _, k := range []string{"org_id", "journal_id"} {
		s := v.Get(k)
		if s == nil || s.Kind != KindString || !EstHex(s.Str, 32) {
			add("cles.%s : 32 octets hexadécimaux attendus", k)
			continue
		}
		if k == "org_id" {
			jeu.OrgID = s.Str
		} else {
			jeu.JournalID = s.Str
		}
	}
	if tableau == nil || tableau.Kind != KindArray {
		add("cles.keys : tableau attendu")
		return jeu, m
	}
	if len(tableau.Arr) < 1 {
		add("cles.keys : au moins une clé attendue")
	}
	vus := map[string]bool{}
	pubsVues := map[string]int{}
	for i, kv := range tableau.Arr {
		chemin := fmt.Sprintf("cles.%s[%d]", nomTableau, i)
		if kv.Kind != KindObject {
			add("%s : objet attendu", chemin)
			continue
		}
		for _, k := range kv.Keys() {
			switch k {
			case "key_id", "algorithm", "public_key", "valid_from", "valid_to", "source", "seed":
			default:
				add("%s : clé inattendue %q", chemin, k)
			}
		}
		for _, k := range []string{"key_id", "algorithm", "public_key", "valid_from", "valid_to", "source"} {
			if !kv.Has(k) {
				add("%s.%s : obligatoire", chemin, k)
			}
		}
		c := &Cle{}
		if s := kv.Get("key_id"); s != nil {
			if s.Kind != KindString || !EstIdentifiantCle(s.Str) {
				add("%s.key_id : identifiant de clé attendu", chemin)
			} else {
				c.KeyID = s.Str
				if vus[c.KeyID] {
					add("%s.key_id : %q en double", chemin, c.KeyID)
				}
				vus[c.KeyID] = true
			}
		}
		if s := kv.Get("algorithm"); s != nil && (s.Kind != KindString || s.Str != "ed25519") {
			add("%s.algorithm : constante \"ed25519\" attendue", chemin)
		}
		if s := kv.Get("public_key"); s != nil {
			if s.Kind != KindString || !EstHex(s.Str, 32) {
				add("%s.public_key : 32 octets hexadécimaux attendus", chemin)
			} else {
				c.PublicKey, _ = OctetsHex(s.Str, 32)
				if j, deja := pubsVues[s.Str]; deja {
					add("%s.public_key : déjà portée par %s[%d] (deux identifiants pour une même clé)", chemin, nomTableau, j)
				} else {
					pubsVues[s.Str] = i
				}
			}
		}
		if s := kv.Get("valid_from"); s != nil {
			t, ok := time.Time{}, false
			if s.Kind == KindString {
				t, ok = ParseHorodatage(s.Str)
			}
			if !ok {
				add("%s.valid_from : horodatage attendu", chemin)
			} else {
				c.ValidFrom = t
			}
		}
		if s := kv.Get("valid_to"); s != nil && !s.IsNull() {
			t, ok := time.Time{}, false
			if s.Kind == KindString {
				t, ok = ParseHorodatage(s.Str)
			}
			if !ok {
				add("%s.valid_to : horodatage ou null attendu", chemin)
			} else {
				c.ValidTo = &t
				if t.Before(c.ValidFrom) {
					add("%s : valid_to antérieur à valid_from", chemin)
				}
			}
		}
		if s := kv.Get("source"); s != nil {
			if s.Kind != KindString || longueurChaine(s.Str) < 1 || longueurChaine(s.Str) > 256 {
				add("%s.source : chaîne de 1 à 256 caractères attendue", chemin)
			} else {
				c.Source = s.Str
			}
		}
		if s := kv.Get("seed"); s != nil {
			if s.Kind != KindString || !EstHex(s.Str, 32) {
				add("%s.seed : 32 octets hexadécimaux attendus", chemin)
			} else {
				c.Graine, _ = OctetsHex(s.Str, 32)
			}
		}
		jeu.Cles = append(jeu.Cles, c)
	}
	return jeu, m
}
