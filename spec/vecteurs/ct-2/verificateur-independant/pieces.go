// Pièces (CT-1 §5.4, CT-2 §8) : octets stockés et hachés, référence
// { sha256, length, redacted[, media_type] }, et confrontation d'une pièce
// recalculée à la pièce attendue d'un vecteur (« réf+bytes » de l'annexe B).

package main

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Piece est une pièce recalculée.
type Piece struct {
	Octets    []byte
	Redigee   bool
	MediaType string // "" : absent (pièce JSON implicite)
}

// SHA256Hex rend le sha256 de la pièce, en 0x minuscule.
func (p *Piece) SHA256Hex() string { return Hex0x(SHA256(p.Octets)) }

// PieceJSON sérialise une valeur en JCS intégral (8.1).
func PieceJSON(v *Value, redigee bool, mediaType string) (*Piece, error) {
	b, err := CanoniqueIntegral(v)
	if err != nil {
		return nil, err
	}
	return &Piece{Octets: b, Redigee: redigee, MediaType: mediaType}, nil
}

// PieceRedigeeJSON applique la politique (portée, outil) à une valeur, puis
// sérialise en JCS intégral ; redacted selon EX-10.16.
func PieceRedigeeJSON(pol *Politique, portee, outil string, v *Value) (*Piece, ResultatRedaction, error) {
	avant, err := CanoniqueIntegral(v)
	if err != nil {
		return nil, ResultatRedaction{}, err
	}
	res := ResultatRedaction{Valeur: Copier(v)}
	if pol != nil {
		res = pol.Appliquer(portee, outil, v)
	}
	apres, err := CanoniqueIntegral(res.Valeur)
	if err != nil {
		return nil, res, err
	}
	return &Piece{Octets: apres, Redigee: string(apres) != string(avant)}, res, nil
}

// PieceRedigeeTexte applique la politique à un texte (racine chaîne, 10.2.1)
// et rend la pièce text/plain : octets UTF-8 du texte rédigé (8.2).
func PieceRedigeeTexte(pol *Politique, portee, outil, texte string) (*Piece, ResultatRedaction) {
	res := ResultatRedaction{Valeur: Chaine(texte)}
	if pol != nil {
		res = pol.Appliquer(portee, outil, Chaine(texte))
	}
	out := texte
	if EstChaine(res.Valeur) {
		out = res.Valeur.Str
	} else if b, err := CanoniqueIntegral(res.Valeur); err == nil {
		out = string(b) // une règle champ/supprimer a remplacé la racine (cas limite)
	}
	return &Piece{Octets: []byte(out), Redigee: out != texte, MediaType: "text/plain"}, res
}

// texteOuAbsent présente une valeur attendue lue dans un vecteur.
func texteOuAbsent(v *Value) string {
	if v == nil {
		return "(absent)"
	}
	switch v.Kind {
	case KindString:
		return v.Str
	case KindBool:
		return strconv.FormatBool(v.Bool)
	case KindNull:
		return "null"
	case KindNumber:
		return v.Num
	}
	return doitIntegral(v)
}

// comparerPiece confronte une pièce recalculée (ou son absence, p == nil) à
// la pièce attendue att (objet réf+bytes, ou null). Rend vrai si tout
// concorde.
func comparerPiece(rap *Rapport, famille, vecteur, nom string, att *Value, p *Piece, errCalcul error) bool {
	if errCalcul != nil {
		return rap.Comparer(famille, vecteur, "pièce « "+nom+" »", texteOuAbsent(att), "calcul impossible : "+errCalcul.Error())
	}
	if att == nil || att.IsNull() {
		obt := "absente"
		if p != nil {
			obt = string(p.Octets)
		}
		return rap.Comparer(famille, vecteur, "pièce « "+nom+" » (null dans l'attendu)", "absente", obt)
	}
	if p == nil {
		return rap.Comparer(famille, vecteur, "pièce « "+nom+" »", texteOuAbsent(att), "absente")
	}
	ok := true
	// cohérence interne de l'attendu : sha256 et length de ses propres octets
	if b := att.Get("bytes"); EstChaine(b) {
		ok = rap.Comparer(famille, vecteur, nom+" · cohérence de l'attendu : sha256(bytes) = sha256", chaineDe(att, "sha256"), Hex0x(SHA256([]byte(b.Str)))) && ok
		if n, okn := EntierDe(att.Get("length")); okn {
			ok = rap.Comparer(famille, vecteur, nom+" · cohérence de l'attendu : longueur(bytes) = length", fmt.Sprint(n), fmt.Sprint(len(b.Str))) && ok
		}
		ok = rap.Comparer(famille, vecteur, nom+" · octets", b.Str, string(p.Octets)) && ok
	}
	ok = rap.Comparer(famille, vecteur, nom+" · sha256", chaineDe(att, "sha256"), p.SHA256Hex()) && ok
	ok = rap.Comparer(famille, vecteur, nom+" · length", texteOuAbsent(att.Get("length")), fmt.Sprint(len(p.Octets))) && ok
	ok = rap.Comparer(famille, vecteur, nom+" · redacted", texteOuAbsent(att.Get("redacted")), strconv.FormatBool(p.Redigee)) && ok
	mt := "(absent)"
	if p.MediaType != "" {
		mt = p.MediaType
	}
	ok = rap.Comparer(famille, vecteur, nom+" · media_type", texteOuAbsent(att.Get("media_type")), mt) && ok
	return ok
}

// comparerValeur confronte deux valeurs JSON par leur JCS intégral.
func comparerValeur(rap *Rapport, famille, vecteur, grandeur string, att, obt *Value) bool {
	a, o := "(absent)", "(absent)"
	if att != nil {
		a = doitIntegral(att)
	}
	if obt != nil {
		o = doitIntegral(obt)
	}
	return rap.Comparer(famille, vecteur, grandeur, a, o)
}

// horsPerimetre consigne une valeur attendue que ce vérificateur ne peut pas
// recalculer, avec la raison : ni concordante ni discordante.
func horsPerimetre(rap *Rapport, famille, vecteur, grandeur, attendu, raison string) {
	rap.Comparaisons = append(rap.Comparaisons, Comparaison{Famille: famille, Vecteur: vecteur, Grandeur: grandeur,
		Attendu: attendu, Obtenu: "non recalculé", HorsPerimetre: true, Note: raison})
}

// TypeDeMedia rend le type de média d'un Content-Type (EX-8.7) : en
// minuscules, sans paramètres ; application/octet-stream sans en-tête ou si
// le résultat ne respecte pas le motif type_mime de CT-1 (127 caractères au
// plus).
func TypeDeMedia(contentType string) string {
	t := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	if t == "" || len(t) > 127 || !reTypeMime.MatchString(t) {
		return "application/octet-stream"
	}
	return t
}

// EstTypeJSON : application/json ou un type de suffixe +json (5.3.1 pas 5).
func EstTypeJSON(media string) bool {
	return media == "application/json" || (strings.HasSuffix(media, "+json") && reTypeMime.MatchString(media))
}

// PieceBrute construit la pièce non JSON d'EX-8.7 : texte UTF-8 rédigé
// (racine chaîne) quel que soit le type de média, sinon forme « non
// rédigeable » si une règle s'applique à la portée, sinon les octets reçus.
func PieceBrute(pol *Politique, portee string, octets []byte, contentType *Value) *Piece {
	ct := ""
	if EstChaine(contentType) {
		ct = contentType.Str
	}
	media := TypeDeMedia(ct)
	if utf8.Valid(octets) {
		if pol != nil {
			res := pol.Appliquer(portee, "", Chaine(string(octets)))
			if EstChaine(res.Valeur) && res.Valeur.Str != string(octets) {
				return &Piece{Octets: []byte(res.Valeur.Str), Redigee: true, MediaType: media}
			}
		}
		return &Piece{Octets: octets, MediaType: media}
	}
	applicable := false
	if pol != nil {
		for _, r := range pol.Regles {
			if r.Applicable(portee, "") {
				applicable = true
			}
		}
	}
	if !applicable {
		return &Piece{Octets: octets, MediaType: media}
	}
	cv := Nul()
	if contentType != nil {
		cv = Copier(contentType)
	}
	p, _ := PieceJSON(Objet("noortrace_non_redigeable", Objet("content_type", cv, "length", Entier(int64(len(octets))), "reason", Chaine("non_utf8"))), true, "")
	return p
}
