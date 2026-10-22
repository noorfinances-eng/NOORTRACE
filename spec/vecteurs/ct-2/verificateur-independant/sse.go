// Analyseur SSE commun (CT-2 §5.4.1, EX-5.14), d'après la section « Parsing
// an event stream » du HTML Living Standard : marque d'ordre d'octets initiale
// retirée ; fins de ligne CRLF, LF ou CR ; une ligne vide distribue
// l'événement ; une ligne commençant par « : » est ignorée ; « champ: valeur »
// avec un seul espace initial retiré ; une ligne sans « : » est un nom de
// champ à valeur vide ; event fixe le type ; chaque data est ajouté au tampon
// suivi de « \n », le dernier « \n » retiré à la distribution ; id et retry
// lus et ignorés ; type par défaut « message » ; un tampon data vide ne
// distribue rien ; un data en attente sans ligne vide finale n'est pas
// distribué.
//
// L'analyseur est incrémental : Ecrire accepte des fragments d'octets
// arbitraires (un CR en fin de fragment suivi d'un LF au fragment suivant
// forme une seule fin de ligne ; un caractère UTF-8 coupé entre deux
// fragments est recollé, la ligne n'étant décodée qu'entière).

package main

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// EvenementSSE est un événement distribué.
type EvenementSSE struct {
	Type string
	Data string
}

// AnalyseurSSE analyse un flux text/event-stream fragment par fragment.
type AnalyseurSSE struct {
	debut        []byte // octets initiaux en attente de la décision sur la BOM
	bomTraitee   bool
	ligne        []byte
	crPrecedent  bool
	typeEv       string
	data         strings.Builder
	Evenements   []EvenementSSE
	Commentaires int
	Lignes       int
}

var bomUTF8 = []byte{0xEF, 0xBB, 0xBF}

// Ecrire analyse un fragment.
func (a *AnalyseurSSE) Ecrire(b []byte) {
	if !a.bomTraitee {
		a.debut = append(a.debut, b...)
		n := len(a.debut)
		if n > 3 {
			n = 3
		}
		if string(a.debut[:n]) != string(bomUTF8[:n]) {
			a.bomTraitee = true
			reste := a.debut
			a.debut = nil
			a.octets(reste)
			return
		}
		if len(a.debut) < 3 {
			return
		}
		a.bomTraitee = true
		reste := a.debut[3:]
		a.debut = nil
		a.octets(reste)
		return
	}
	a.octets(b)
}

func (a *AnalyseurSSE) octets(b []byte) {
	for _, c := range b {
		if a.crPrecedent {
			a.crPrecedent = false
			if c == '\n' {
				continue
			}
		}
		switch c {
		case '\r':
			a.crPrecedent = true
			a.traiterLigne()
		case '\n':
			a.traiterLigne()
		default:
			a.ligne = append(a.ligne, c)
		}
	}
}

// Fin termine le flux : une ligne incomplète et un événement sans ligne vide
// finale sont abandonnés. Rend les événements distribués.
func (a *AnalyseurSSE) Fin() []EvenementSSE {
	if !a.bomTraitee && len(a.debut) > 0 {
		// flux plus court qu'une BOM complète : ce ne sont pas des octets de BOM
		a.bomTraitee = true
		reste := a.debut
		a.debut = nil
		a.octets(reste)
	}
	a.ligne = nil
	a.data.Reset()
	a.typeEv = ""
	return a.Evenements
}

// decoderUTF8 décode en remplaçant chaque octet invalide par U+FFFD.
func decoderUTF8(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		sb.WriteRune(r)
		b = b[n:]
	}
	return sb.String()
}

func (a *AnalyseurSSE) traiterLigne() {
	ligne := decoderUTF8(a.ligne)
	a.ligne = a.ligne[:0]
	a.Lignes++
	if ligne == "" {
		a.distribuer()
		return
	}
	if strings.HasPrefix(ligne, ":") {
		a.Commentaires++
		return
	}
	champ, valeur := ligne, ""
	if i := strings.IndexByte(ligne, ':'); i >= 0 {
		champ, valeur = ligne[:i], ligne[i+1:]
		valeur = strings.TrimPrefix(valeur, " ")
	}
	switch champ {
	case "event":
		a.typeEv = valeur
	case "data":
		a.data.WriteString(valeur)
		a.data.WriteByte('\n')
	case "id", "retry":
		// lus et ignorés (EX-5.14)
	}
}

func (a *AnalyseurSSE) distribuer() {
	if a.data.Len() == 0 {
		a.typeEv = ""
		return
	}
	d := strings.TrimSuffix(a.data.String(), "\n")
	t := a.typeEv
	if t == "" {
		t = "message"
	}
	a.Evenements = append(a.Evenements, EvenementSSE{Type: t, Data: d})
	a.data.Reset()
	a.typeEv = ""
}

// AnalyserSSE analyse un flux complet.
func AnalyserSSE(b []byte) ([]EvenementSSE, *AnalyseurSSE) {
	a := &AnalyseurSSE{}
	a.Ecrire(b)
	return a.Fin(), a
}

// EvenementsTexte rend une forme textuelle non ambiguë d'une suite
// d'événements (type et data cités), pour les comparer.
func EvenementsTexte(evs []EvenementSSE) string {
	var b strings.Builder
	for _, e := range evs {
		b.WriteString(strconv.Quote(e.Type))
		b.WriteByte(' ')
		b.WriteString(strconv.Quote(e.Data))
		b.WriteByte('\n')
	}
	return b.String()
}
