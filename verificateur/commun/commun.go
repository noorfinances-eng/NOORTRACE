// Paquet commun : types partagés par tous les paquets du vérificateur
// (statuts, raisons, vérifications, avertissements, textes bilingues) et
// règles transverses de CT-6 §6 (raisons admises, ordre des raisons, statut
// d'une vérification à portée multiple, format des instants d'EX-6.11).
package commun

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Statut d'une vérification ou d'un contrôle (CT-6 EX-6.1).
type Statut string

const (
	Reussi     Statut = "reussi"
	Echoue     Statut = "echoue"
	NonExecute Statut = "non_execute"
)

// Raison d'un statut non_execute : liste fermée de CT-6 §6.2, plus la valeur
// provisoire AConstruire, réservée aux paquets dont l'implémentation reste à
// écrire (contrôles 4, 5 et 8). AConstruire ne sort jamais dans un rapport :
// le moteur rend une erreur interne (code 2) dès qu'il la rencontre.
type Raison string

const (
	Aucune               Raison = ""
	PartieAbsente        Raison = "partie_absente"
	AncreAbsente         Raison = "ancre_absente"
	HorsPerimetreVersion Raison = "hors_perimetre_version"
	PieceHorsDossier     Raison = "piece_hors_dossier"
	PrerequisEnEchec     Raison = "prerequis_en_echec"
	AConstruire          Raison = "a_construire"
)

// Admise dit si la raison est admise (table 6.2) : elle n'empêche pas un
// verdict valide.
func (r Raison) Admise() bool {
	switch r {
	case PartieAbsente, AncreAbsente, HorsPerimetreVersion, PieceHorsDossier:
		return true
	}
	return false
}

// rangRaison donne l'ordre d'EX-6.5 : ce qui invalide avant ce qui borne, ce
// qui tient au dossier avant ce qui tient aux ancres. AConstruire passe en
// tête : elle signale un défaut du binaire, pas du dossier.
func rangRaison(r Raison) int {
	switch r {
	case AConstruire:
		return 0
	case PrerequisEnEchec:
		return 1
	case HorsPerimetreVersion:
		return 2
	case PartieAbsente:
		return 3
	case AncreAbsente:
		return 4
	case PieceHorsDossier:
		return 5
	}
	return 6
}

// PremiereRaison rend, parmi les raisons données, la première dans l'ordre
// d'EX-6.5 (EX-5.5 pour une vérification, EX-6.5 pour un contrôle).
func PremiereRaison(raisons ...Raison) Raison {
	meilleure := Aucune
	for _, r := range raisons {
		if r == Aucune {
			continue
		}
		if meilleure == Aucune || rangRaison(r) < rangRaison(meilleure) {
			meilleure = r
		}
	}
	return meilleure
}

// Texte bilingue : chaque texte du rapport existe en français et en anglais
// (CT-6 EX-8.3).
type Texte struct {
	Fr string
	En string
}

// T construit un texte bilingue.
func T(fr, en string) Texte { return Texte{Fr: fr, En: en} }

// Vide dit si le texte est vide dans les deux langues.
func (t Texte) Vide() bool { return t.Fr == "" && t.En == "" }

// Langue choisit le texte d'une langue (« fr » ou « en »).
func (t Texte) Langue(l string) string {
	if l == "en" {
		return t.En
	}
	return t.Fr
}

// Joindre concatène deux textes bilingues avec un séparateur propre à chaque
// langue.
func (t Texte) Joindre(sepFr, sepEn string, autre Texte) Texte {
	if t.Vide() {
		return autre
	}
	if autre.Vide() {
		return t
	}
	return Texte{Fr: t.Fr + sepFr + autre.Fr, En: t.En + sepEn + autre.En}
}

// Verification : résultat d'une vérification élémentaire (D-1, E-7, T-2…),
// tel qu'il entre dans `checks` du rapport (CT-6 §8.6).
type Verification struct {
	// ID : identifiant de la vérification (« E-7 », « T-2 », « AT-3 »).
	ID string
	// Controles : contrôles servis (vide pour D-1 et D-2).
	Controles []int
	// Statut : reussi, echoue ou non_execute.
	Statut Statut
	// Raison : vide sauf pour non_execute.
	Raison Raison
	// Detail : texte libre qui précise le résultat ; vide = null dans le
	// rapport JSON.
	Detail Texte
}

// Nouvelle construit une vérification.
func Nouvelle(id string, statut Statut, raison Raison, detail Texte, controles ...int) Verification {
	if statut != NonExecute {
		raison = Aucune
	}
	return Verification{ID: id, Controles: controles, Statut: statut, Raison: raison, Detail: detail}
}

// Avertissement : signal AV-… qui ne change aucun statut (CT-6 §9.7, §10.7,
// §11.6, §5.5).
type Avertissement struct {
	// ID : identifiant, par exemple « AV-O-3 ».
	ID string
	// Verification : identifiant de la vérification qui le lève (champ
	// `check` du rapport), ou vide pour null.
	Verification string
	// Detail : texte de l'avertissement.
	Detail Texte
}

// Resultat est le résultat élémentaire d'une règle appliquée à un objet
// (un événement, un certificat, une entrée) : sert à agréger une vérification
// qui porte sur plusieurs objets.
type Resultat struct {
	Statut Statut
	Raison Raison
}

// Agreger rend le statut d'une vérification qui porte sur plusieurs objets
// (CT-6 §11.4, appliqué aussi aux vérifications de CT-1 qui portent sur
// chaque événement) : echoue si l'un échoue, sinon non_execute si l'un n'est
// pas exécuté (avec la première raison d'EX-6.5), sinon reussi.
func Agreger(resultats []Resultat) (Statut, Raison) {
	statut := Reussi
	var raisons []Raison
	for _, r := range resultats {
		switch r.Statut {
		case Echoue:
			return Echoue, Aucune
		case NonExecute:
			statut = NonExecute
			raisons = append(raisons, r.Raison)
		}
	}
	if statut == NonExecute {
		return NonExecute, PremiereRaison(raisons...)
	}
	return Reussi, Aucune
}

// FormaterInstant écrit un instant selon EX-6.11 : RFC 3339 en UTC,
// `AAAA-MM-JJThh:mm:ssZ`, fraction de seconde seulement si elle est non
// nulle, sans zéro final.
func FormaterInstant(t time.Time) string {
	t = t.UTC()
	base := fmt.Sprintf("%04d-%02d-%02dT%02d:%02d:%02d", t.Year(), int(t.Month()), t.Day(), t.Hour(), t.Minute(), t.Second())
	ns := t.Nanosecond()
	if ns == 0 {
		return base + "Z"
	}
	frac := fmt.Sprintf("%09d", ns)
	frac = strings.TrimRight(frac, "0")
	return base + "." + frac + "Z"
}

// FormaterSecondes écrit des secondes UNIX selon EX-6.11.
func FormaterSecondes(s int64) string {
	return FormaterInstant(time.Unix(s, 0))
}

// LireHorodatage lit un horodatage de CT-1 §3
// (`AAAA-MM-JJThh:mm:ss.mmmZ`) et refuse une date qui n'existe pas dans le
// calendrier grégorien proleptique (jamais de renormalisation).
func LireHorodatage(s string) (time.Time, bool) {
	if len(s) != 24 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' || s[16] != ':' || s[19] != '.' || s[23] != 'Z' {
		return time.Time{}, false
	}
	champ := func(a, b int) (int, bool) {
		v := 0
		for i := a; i < b; i++ {
			c := s[i]
			if c < '0' || c > '9' {
				return 0, false
			}
			v = v*10 + int(c-'0')
		}
		return v, true
	}
	an, ok1 := champ(0, 4)
	mo, ok2 := champ(5, 7)
	jo, ok3 := champ(8, 10)
	he, ok4 := champ(11, 13)
	mi, ok5 := champ(14, 16)
	se, ok6 := champ(17, 19)
	ms, ok7 := champ(20, 23)
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) {
		return time.Time{}, false
	}
	if mo < 1 || mo > 12 || jo < 1 || he > 23 || mi > 59 || se > 59 {
		return time.Time{}, false
	}
	t := time.Date(an, time.Month(mo), jo, he, mi, se, ms*1_000_000, time.UTC)
	if t.Year() != an || int(t.Month()) != mo || t.Day() != jo {
		return time.Time{}, false
	}
	return t, true
}

// JoindreListe joint des éléments par « , » et, devant le dernier, par
// `dernier` (« et », « and », « ni sur »…), comme EX-6.8 le fait pour
// `{approbateurs}`.
func JoindreListe(elements []string, sep, dernier string) string {
	switch len(elements) {
	case 0:
		return ""
	case 1:
		return elements[0]
	}
	return strings.Join(elements[:len(elements)-1], sep) + dernier + elements[len(elements)-1]
}

// Entier écrit un entier en décimal sans séparateur (EX-6.11).
func Entier(n int64) string { return strconv.FormatInt(n, 10) }

// ListeIDs joint des identifiants par « , ».
func ListeIDs(ids []string) string { return strings.Join(ids, ", ") }

// Pluriel rend `un` si n vaut 1, `plusieurs` sinon.
func Pluriel(n int, un, plusieurs string) string {
	if n == 1 {
		return un
	}
	return plusieurs
}

// Bornes des textes du rapport (CT-6 EX-15.1 : un dossier
// fait de petites valeurs produisait un rapport de plusieurs centaines de
// mégaoctets, un détail par élément).
const (
	// DetailsMax : nombre d'éléments qu'une liste de détails écrit un à un ;
	// au-delà, le rapport écrit le nombre des éléments omis.
	DetailsMax = 64
	// LongueurDetailMax : longueur, en caractères, d'un détail, d'un résumé
	// ou d'un avertissement du rapport ; au-delà, le texte est tronqué et la
	// troncature est écrite.
	LongueurDetailMax = 4096
)

// Borner rend les DetailsMax premiers éléments d'une liste de détails et, si
// la liste est plus longue, un dernier élément qui dit le nombre des éléments
// omis, dans la langue demandée (« fr » ou « en »).
func Borner(elements []string, langue string) []string {
	if len(elements) <= DetailsMax {
		return elements
	}
	out := append([]string{}, elements[:DetailsMax]...)
	n := len(elements) - DetailsMax
	if langue == "en" {
		return append(out, fmt.Sprintf("… and %d more", n))
	}
	return append(out, fmt.Sprintf("… et %d autre(s)", n))
}

// BornerFr et BornerEn : Borner en français et en anglais.
func BornerFr(elements []string) []string { return Borner(elements, "fr") }
func BornerEn(elements []string) []string { return Borner(elements, "en") }

// Tronquer coupe un texte à LongueurDetailMax caractères et le dit.
func Tronquer(s, langue string) string {
	if utf8.RuneCountInString(s) <= LongueurDetailMax {
		return s
	}
	r := []rune(s)[:LongueurDetailMax]
	if langue == "en" {
		return string(r) + fmt.Sprintf(" … (text truncated at %d characters)", LongueurDetailMax)
	}
	return string(r) + fmt.Sprintf(" … (texte tronqué à %d caractères)", LongueurDetailMax)
}

// BornerTexte applique Tronquer aux deux langues d'un texte bilingue.
func BornerTexte(t Texte) Texte { return Texte{Fr: Tronquer(t.Fr, "fr"), En: Tronquer(t.En, "en")} }

// Neutraliser écrit sous une forme visible, dans une chaîne destinée au
// rapport lisible ou à la sortie d'erreur, tout caractère qu'un terminal
// interpréterait ou qui changerait l'ordre de lecture : les caractères de
// commande U+0000 à U+001F et U+007F à U+009F (dont le retour chariot, le
// saut de ligne et l'échappement des séquences de terminal), les séparateurs
// de ligne U+2028 et U+2029, les marques de direction U+202A à U+202E et
// U+2066 à U+2069, et U+FEFF. Chacun est remplacé par son échappement JSON
// `\uXXXX` (RFC 8259 §7, hexadécimal minuscule), la même forme que dans le
// rapport JSON. Une suite d'octets qui n'est pas de l'UTF-8 valide est
// écrite octet par octet sous la forme `\xXX`. C'est le seul point
// d'échappement du binaire : toute ligne du rapport lisible y passe (revue de sécurité de l'étape 8 ;
// CT-6 EX-8.5, EX-8.6).
func Neutraliser(s string) string {
	propre := true
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c >= 0x7F {
			propre = false
			break
		}
	}
	if propre {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n <= 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
			i++
			continue
		case r < 0x20, r >= 0x7F && r <= 0x9F, r == 0x2028, r == 0x2029, r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069, r == 0xFEFF:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteString(s[i : i+n])
		}
		i += n
	}
	return b.String()
}

// ChaineNonVide dit si s est une chaîne non vide au sens de CT-1 §3
// (révision 0.5) : elle contient au moins un caractère qui n'est pas un
// blanc. Les blancs sont les points de code de la propriété Unicode
// White_Space (unicode.IsSpace : U+0009 à U+000D, U+0020, U+0085, U+00A0,
// U+1680, U+2000 à U+200A, U+2028, U+2029, U+202F, U+205F, U+3000) et
// U+FEFF. S'applique à la raison d'absence d'une partie (D-2) et à
// policy.redaction (E-4). Ce jeu diffère de celui de strings.TrimSpace, qui
// ne compte pas U+FEFF (identifiants de validateurs, CT-6 EX-12.2).
func ChaineNonVide(s string) bool {
	for _, r := range s {
		if !unicode.IsSpace(r) && r != '\uFEFF' {
			return true
		}
	}
	return false
}
