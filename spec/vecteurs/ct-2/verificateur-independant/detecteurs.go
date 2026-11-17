// Détecteurs exacts de la rédaction (CT-2 §10.3) : iban, avs, carte, email,
// telephone, regex (motif nommé). Chaque détecteur opère sur la chaîne telle
// qu'elle est (points de code, sans normalisation ni changement de casse,
// EX-10.8) et rend ses correspondances de gauche à droite, sans chevauchement,
// chaque recherche reprenant après la fin de la correspondance précédente,
// fin qui vaut frontière pour le candidat suivant (EX-10.9). Les positions
// sont des indices de points de code. Les jetons (EX-10.9) sont traités par
// l'appelant (redaction.go), qui applique un détecteur à chaque segment
// situé entre deux jetons.

package main

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// Correspondance est une sous-chaîne reconnue : [Debut, Fin) en points de
// code, et la valeur normalisée qui sert au pseudonyme (10.3.9).
type Correspondance struct {
	Debut, Fin int
	Valeur     string
}

func estChiffre(r rune) bool      { return r >= '0' && r <= '9' }
func estMajuscule(r rune) bool    { return r >= 'A' && r <= 'Z' }
func estLettreASCII(r rune) bool  { return estMajuscule(r) || (r >= 'a' && r <= 'z') }
func estAlnumASCII(r rune) bool   { return estChiffre(r) || estLettreASCII(r) }
func estAlnumIBAN(r rune) bool    { return estMajuscule(r) || estChiffre(r) }
func estSEP(r rune) bool          { return r == ' ' || r == '\u00A0' || r == '\u202F' }
func estSepCarte(r rune) bool     { return estSEP(r) || r == '-' }
func estSepTelephone(r rune) bool { return estSEP(r) || r == '-' || r == '.' }

// frontiereAvant : début de chaîne (ou de segment), fin de la correspondance
// précédente du même détecteur (depart, EX-10.9), ou point de code précédent
// qui n'est ni un chiffre ASCII ni une lettre ASCII (10.3.1).
func frontiereAvant(s []rune, p, depart int) bool {
	return p == 0 || p == depart || !estAlnumASCII(s[p-1])
}

// frontiereApres : fin de chaîne, ou point de code s[p] qui n'est ni un
// chiffre ASCII ni une lettre ASCII.
func frontiereApres(s []rune, p int) bool { return p >= len(s) || !estAlnumASCII(s[p]) }

// chercheur rend la première correspondance qui commence à depart ou après.
type chercheur func(s []rune, depart int) (Correspondance, bool)

// toutes enchaîne les recherches : chacune reprend à la fin de la précédente.
func toutes(s []rune, ch chercheur) []Correspondance {
	var out []Correspondance
	for depart := 0; depart <= len(s); {
		c, ok := ch(s, depart)
		if !ok {
			break
		}
		out = append(out, c)
		depart = c.Fin
	}
	return out
}

// ---------------------------------------------------------------- iban

// LongueursIBAN est la table de 10.3.2 (onze codes de pays).
var LongueursIBAN = map[string]int{
	"CH": 21, "LI": 21, "DE": 22, "FR": 27, "IT": 27, "AT": 20,
	"ES": 24, "NL": 18, "BE": 16, "GB": 22, "LU": 20,
}

// DetecterIBAN applique le détecteur iban (10.3.2).
func DetecterIBAN(s []rune) []Correspondance { return toutes(s, chercherIBAN) }

func chercherIBAN(s []rune, depart int) (Correspondance, bool) {
	for p := depart; p < len(s); p++ {
		if c, ok := candidatIBAN(s, p, depart); ok {
			return c, true
		}
	}
	return Correspondance{}, false
}

func candidatIBAN(s []rune, p, depart int) (Correspondance, bool) {
	if !frontiereAvant(s, p, depart) || p+4 > len(s) {
		return Correspondance{}, false
	}
	if !estMajuscule(s[p]) || !estMajuscule(s[p+1]) || !estChiffre(s[p+2]) || !estChiffre(s[p+3]) {
		return Correspondance{}, false
	}
	L, ok := LongueursIBAN[string(s[p:p+2])]
	if !ok {
		return Correspondance{}, false
	}
	n := append([]rune{}, s[p:p+4]...)
	i := p + 4
	for len(n) < L {
		if i >= len(s) {
			return Correspondance{}, false
		}
		if estSEP(s[i]) {
			// séparateur isolé, entre deux alphanumériques
			if i+1 >= len(s) || !estAlnumIBAN(s[i+1]) {
				return Correspondance{}, false
			}
			i++
		}
		if !estAlnumIBAN(s[i]) {
			return Correspondance{}, false
		}
		n = append(n, s[i])
		i++
	}
	if !frontiereApres(s, i) {
		return Correspondance{}, false
	}
	if ResteIBAN(string(n)) != 1 {
		return Correspondance{}, false
	}
	return Correspondance{Debut: p, Fin: i, Valeur: string(n)}, true
}

// ResteIBAN calcule le reste MOD 97-10 de 10.3.2 pas 3 sur la forme
// normalisée N : quatre premiers caractères déplacés à la fin, lettres
// remplacées par deux chiffres (A → 10 … Z → 35), réduction par blocs de neuf
// chiffres au plus, de gauche à droite.
func ResteIBAN(n string) int {
	if len(n) < 4 {
		return -1
	}
	r := n[4:] + n[:4]
	var d strings.Builder
	for _, c := range r {
		switch {
		case c >= '0' && c <= '9':
			d.WriteRune(c)
		case c >= 'A' && c <= 'Z':
			v := int(c) - 55
			d.WriteByte(byte('0' + v/10))
			d.WriteByte(byte('0' + v%10))
		default:
			return -1
		}
	}
	D := d.String()
	reste := uint64(0)
	for i := 0; i < len(D); i += 9 {
		j := i + 9
		if j > len(D) {
			j = len(D)
		}
		bloc := D[i:j]
		v := reste
		for _, c := range bloc {
			v = v*10 + uint64(c-'0')
		}
		reste = v % 97
	}
	return int(reste)
}

// ---------------------------------------------------------------- avs

// DetecterAVS applique le détecteur avs (10.3.3).
func DetecterAVS(s []rune) []Correspondance { return toutes(s, chercherAVS) }

func chercherAVS(s []rune, depart int) (Correspondance, bool) {
	for p := depart; p < len(s); p++ {
		if c, ok := candidatAVS(s, p, depart); ok {
			return c, true
		}
	}
	return Correspondance{}, false
}

func candidatAVS(s []rune, p, depart int) (Correspondance, bool) {
	if !frontiereAvant(s, p, depart) || p+3 > len(s) || s[p] != '7' || s[p+1] != '5' || s[p+2] != '6' {
		return Correspondance{}, false
	}
	chiffres := []rune{'7', '5', '6'}
	i := p + 3
	var sep rune
	for _, g := range []int{4, 4, 2} {
		if i < len(s) && (s[i] == '.' || estSEP(s[i])) {
			if sep != 0 && s[i] != sep {
				return Correspondance{}, false
			}
			sep = s[i]
			i++
		}
		for k := 0; k < g; k++ {
			if i >= len(s) || !estChiffre(s[i]) {
				return Correspondance{}, false
			}
			chiffres = append(chiffres, s[i])
			i++
		}
	}
	if !frontiereApres(s, i) {
		return Correspondance{}, false
	}
	if !CleAVSValide(string(chiffres)) {
		return Correspondance{}, false
	}
	return Correspondance{Debut: p, Fin: i, Valeur: string(chiffres)}, true
}

// CleAVSValide vérifie la clé de contrôle du numéro AVS à treize chiffres :
// S = Σ x_i · w_i (i = 1..12, w = 1 pour i impair, 3 pour i pair),
// clé = (10 − S mod 10) mod 10, égale à x13.
func CleAVSValide(n string) bool {
	if len(n) != 13 {
		return false
	}
	s := 0
	for i := 0; i < 12; i++ {
		x := int(n[i] - '0')
		if (i+1)%2 == 0 {
			x *= 3
		}
		s += x
	}
	return (10-s%10)%10 == int(n[12]-'0')
}

// ---------------------------------------------------------------- carte

// DetecterCarte applique le détecteur carte (10.3.4).
//
// Règle (complément du 2026-11-16 de la révision 0.11 de CT-2, décision du
// porteur) : « Une suite est une suite maximale de caractères de l'alphabet
// [0-9], SEP et -, commençant et finissant par un chiffre, dont les
// séparateurs sont isolés. [...] Les groupes de la suite sont ses suites
// maximales de chiffres [...]. Un candidat est une sous-suite de groupes
// consécutifs de la suite, du premier chiffre de son premier groupe au
// dernier chiffre de son dernier groupe, qui compte entre 12 et 19 chiffres
// et qui est précédée et suivie d'une frontière (le séparateur qui la borde à
// l'intérieur de la suite en est une). Les candidats d'une suite sont
// éprouvés au pas 3 dans cet ordre : par premier groupe, de gauche à droite,
// et, pour un même premier groupe, le plus long d'abord [...]. Le premier
// candidat qui passe le pas 3 est la correspondance, et la recherche reprend
// immédiatement après lui (EX-10.9), le reste de la suite compris ; si aucun
// ne passe, aucune correspondance ne commence dans la suite. »
// Pas 4 : « Correspondance : le candidat retenu, séparateurs intérieurs
// compris. Valeur pour le pseudonyme : N » (les chiffres seuls du candidat).
func DetecterCarte(s []rune) []Correspondance { return toutes(s, chercherCarte) }

func chercherCarte(s []rune, depart int) (Correspondance, bool) {
	for p := depart; p < len(s); {
		if !estChiffre(s[p]) {
			p++
			continue
		}
		// la suite maximale qui commence à p, découpée en groupes [debut, fin) ;
		// les groupes sont lus à mesure (au plus 19 au-delà du premier groupe
		// éprouvé), pour que le coût reste linéaire quand la recherche reprend
		// au milieu d'une longue suite (EX-10.23)
		var groupes [][2]int
		complete := false
		lire := func(h int) bool {
			for len(groupes) <= h && !complete {
				i := p
				if len(groupes) > 0 {
					i = groupes[len(groupes)-1][1] + 1 // après le séparateur
				}
				d := i
				for i < len(s) && estChiffre(s[i]) {
					i++
				}
				groupes = append(groupes, [2]int{d, i})
				// la suite continue sur un séparateur isolé suivi d'un chiffre
				complete = !(i+1 < len(s) && estSepCarte(s[i]) && estChiffre(s[i+1]))
			}
			return h < len(groupes)
		}
		for g := 0; lire(g); g++ {
			// frontière avant : celle de la suite pour le premier groupe ; pour
			// les suivants, le séparateur intérieur qui les précède
			if !frontiereAvant(s, groupes[g][0], depart) {
				continue
			}
			// sous-suites de premier groupe g : au plus 19 chiffres, la plus
			// longue d'abord (au plus huit candidats de 12 à 19 chiffres)
			var derniers []int
			n := 0
			for h := g; lire(h); h++ {
				n += groupes[h][1] - groupes[h][0]
				if n > 19 {
					break
				}
				if n >= 12 {
					derniers = append(derniers, h)
				}
			}
			for k := len(derniers) - 1; k >= 0; k-- {
				h := derniers[k]
				debut, fin := groupes[g][0], groupes[h][1]
				if !frontiereApres(s, fin) {
					continue
				}
				var chiffres []rune
				for _, r := range s[debut:fin] {
					if estChiffre(r) {
						chiffres = append(chiffres, r)
					}
				}
				if LuhnValide(string(chiffres)) {
					return Correspondance{Debut: debut, Fin: fin, Valeur: string(chiffres)}, true
				}
			}
		}
		// aucun candidat de la suite ne passe : la recherche reprend après elle
		p = groupes[len(groupes)-1][1]
	}
	return Correspondance{}, false
}

// LuhnValide applique Luhn (10.3.4 pas 3) : de droite à gauche, rang 1 tel
// quel, rang 2 doublé (moins 9 au-delà de 9), et ainsi de suite ; valide si la
// somme est multiple de 10.
func LuhnValide(n string) bool {
	if n == "" {
		return false
	}
	s := 0
	rang := 1
	for i := len(n) - 1; i >= 0; i-- {
		x := int(n[i] - '0')
		if x < 0 || x > 9 {
			return false
		}
		if rang%2 == 0 {
			x *= 2
			if x > 9 {
				x -= 9
			}
		}
		s += x
		rang++
	}
	return s%10 == 0
}

// ---------------------------------------------------------------- email

// alphabet de la partie locale (atext de la RFC 5322 et « . »), 10.3.5
func carLocal(r rune) bool {
	return estAlnumASCII(r) || strings.ContainsRune("!#$%&'*+/=?^_`{|}~-.", r)
}

// alphabet du domaine
func carDomaine(r rune) bool { return estAlnumASCII(r) || r == '.' || r == '-' }

var reLabelEmail = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
var reDernierLabel = regexp.MustCompile(`^[A-Za-z]{2,}$`)

// DetecterEmail applique le détecteur email (10.3.5) : chaque « @ » est un
// point de départ ; lectures bornées (64 points de code à gauche, 256 à
// droite), coût linéaire.
//
// Règle (complément du 2026-11-16 de la révision 0.11 de CT-2, décision du
// porteur) : « la partie locale : soit W la suite maximale, immédiatement à
// gauche du @, de caractères de [A-Za-z0-9!#$%&'*+/=?^_`{|}~.-], sans
// dépasser vers la gauche le début de la chaîne (ou du segment, EX-10.9) ni
// la fin de la correspondance précédente de ce détecteur, lue sur 64
// caractères au plus [...] ; la partie locale L est la plus longue fin de W
// qui est une Dot-string [...] ; sans une telle fin (W vide ou finissant par
// un .), aucun candidat à ce @ ; le domaine : soit S la suite maximale,
// immédiatement à droite du @, de caractères de [A-Za-z0-9.-], lue sur 256
// caractères au plus. [...] Le domaine D est le plus long préfixe de S qui
// est un domaine valide et qui est, soit S entière si elle compte au plus 255
// caractères, soit suivi dans S d'un . ou d'un - ; sans un tel préfixe, aucun
// candidat à ce @. » Pas 2 : « Correspondance : L @ D » ; aucune frontière
// n'est exigée avant L (mention contraire réservée par 10.3.1).
func DetecterEmail(s []rune) []Correspondance { return toutes(s, chercherEmail) }

func chercherEmail(s []rune, depart int) (Correspondance, bool) {
	for a := depart; a < len(s); a++ {
		if s[a] != '@' {
			continue
		}
		// W : suite maximale à gauche, bornée par depart, lue sur 64 au plus
		g := a
		for g > depart && a-g < 64 && carLocal(s[g-1]) {
			g--
		}
		// L : plus longue fin Dot-string de W
		l := finDotString(s[g:a])
		if l < 0 {
			continue
		}
		local := string(s[g+l : a])
		// S : suite maximale à droite, lue sur 256 au plus
		d := a + 1
		for d < len(s) && d-a-1 < 256 && carDomaine(s[d]) {
			d++
		}
		S := s[a+1 : d]
		// D : plus long préfixe admissible de S
		lg := -1
		for e := len(S); e >= 1; e-- {
			admissible := (e == len(S) && len(S) <= 255) || (e < len(S) && (S[e] == '.' || S[e] == '-'))
			if admissible && domaineValide(string(S[:e])) {
				lg = e
				break
			}
		}
		if lg < 0 {
			continue
		}
		domaine := string(S[:lg])
		return Correspondance{Debut: g + l, Fin: a + 1 + lg, Valeur: local + "@" + strings.ToLower(domaine)}, true
	}
	return Correspondance{}, false
}

// finDotString rend l'indice, dans w, du début de la plus longue fin de w qui
// est une Dot-string (non vide, ni « . » initial, ni « . » final, ni « .. »),
// ou -1 s'il n'y en a pas (w vide ou finissant par un « . »).
func finDotString(w []rune) int {
	if len(w) == 0 || w[len(w)-1] == '.' {
		return -1
	}
	k := 0
	for i := len(w) - 1; i > 0; i-- {
		if w[i] == '.' && w[i-1] == '.' {
			k = i + 1
			break
		}
	}
	if w[k] == '.' {
		k++
	}
	return k
}

// domaineValide : au moins deux labels séparés par « . », chacun de 1 à 63
// caractères de [A-Za-z0-9-] ne commençant ni ne finissant par « - », le
// dernier fait d'au moins deux lettres ASCII (10.3.5).
func domaineValide(domaine string) bool {
	labels := strings.Split(domaine, ".")
	if len(labels) < 2 || !reDernierLabel.MatchString(labels[len(labels)-1]) {
		return false
	}
	for _, l := range labels {
		if !reLabelEmail.MatchString(l) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------- telephone

// DetecterTelephone applique le détecteur telephone (10.3.6).
//
// Règle (complément du 2026-11-16 de la révision 0.11 de CT-2, décision du
// porteur) : « Le candidat va de p à q (exclu), où q est la plus grande des
// positions prises par fin au cours du parcours telle que le caractère à q
// est une frontière et que le nombre de chiffres de [p, q), groupe compris
// s'il précède q, est entre 8 et 15 ; sans une telle position, aucun
// candidat à p. [...] le parcours peut donc s'arrêter dès que ce nombre
// dépasse 15. »
func DetecterTelephone(s []rune) []Correspondance { return toutes(s, chercherTelephone) }

func chercherTelephone(s []rune, depart int) (Correspondance, bool) {
	for p := depart; p < len(s); p++ {
		if s[p] != '+' || !frontiereAvant(s, p, depart) {
			continue
		}
		if p+1 >= len(s) || s[p+1] < '1' || s[p+1] > '9' {
			continue
		}
		// n : chiffres lus depuis p, groupe compris une fois lu ; q : plus
		// grande position fin admissible trouvée jusqu'ici (-1 : aucune)
		i, n, q := p+2, 1, -1
		noter := func(fin int) {
			if n >= 8 && n <= 15 && frontiereApres(s, fin) {
				q = fin
			}
		}
		noter(i)
		groupe := false
	boucle:
		for i < len(s) && n <= 15 {
			r := s[i]
			switch {
			case estChiffre(r):
				i++
				n++
				noter(i) // fin passe derrière le chiffre
			case estSepTelephone(r):
				if estSepTelephone(s[i-1]) {
					break boucle // deux séparateurs consécutifs
				}
				i++
			case r == '(':
				if groupe {
					break boucle
				}
				j := i + 1
				for j < len(s) && estChiffre(s[j]) {
					j++
				}
				if j == i+1 || j >= len(s) || s[j] != ')' {
					break boucle
				}
				groupe = true
				n += j - i - 1 // compté pour les positions fin qui le suivent
				i = j + 1      // le groupe est lu sans déplacer fin
			default:
				break boucle
			}
		}
		if q < 0 {
			continue
		}
		var chiffres []rune
		for _, r := range s[p+1 : q] {
			if estChiffre(r) {
				chiffres = append(chiffres, r)
			}
		}
		return Correspondance{Debut: p, Fin: q, Valeur: "+" + string(chiffres)}, true
	}
	return Correspondance{}, false
}

// ---------------------------------------------------------------- regex

// DetecterMotif applique un motif nommé (EX-10.10) : correspondances
// successives sans chevauchement, de gauche à droite (sémantique
// leftmost-first de RE2), les correspondances vides ignorées. Révision 0.11
// de CT-2 (EX-10.9) : la position qui suit une correspondance remplacée est
// un début de chaîne pour les ancres et frontières du motif (^, \b, \B) ;
// le reste est examiné comme une chaîne à part entière, et aucun candidat ne
// commence dans une correspondance déjà trouvée.
func DetecterMotif(re *regexp.Regexp, s []rune) []Correspondance {
	var out []Correspondance
	for depart := 0; depart < len(s); {
		texte := string(s[depart:])
		var loc []int
		for _, l := range re.FindAllStringIndex(texte, -1) {
			if l[0] != l[1] {
				loc = l
				break
			}
		}
		if loc == nil {
			break
		}
		debut := depart + utf8.RuneCountInString(texte[:loc[0]])
		fin := debut + utf8.RuneCountInString(texte[loc[0]:loc[1]])
		out = append(out, Correspondance{Debut: debut, Fin: fin, Valeur: texte[loc[0]:loc[1]]})
		depart = fin
	}
	return out
}
