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

// DetecterCarte applique le détecteur carte (10.3.4). Un candidat est la
// suite maximale qui commence et finit par un chiffre, dont les séparateurs
// (SEP et « - ») sont isolés et suivis d'un chiffre ; elle doit être précédée
// et suivie d'une frontière et compter de 12 à 19 chiffres. Une suite qui
// échoue n'est pas raccourcie : la recherche reprend après elle.
func DetecterCarte(s []rune) []Correspondance { return toutes(s, chercherCarte) }

func chercherCarte(s []rune, depart int) (Correspondance, bool) {
	for p := depart; p < len(s); {
		if !estChiffre(s[p]) {
			p++
			continue
		}
		debut := p
		i, fin := p, p
		var chiffres []rune
		for i < len(s) {
			if estChiffre(s[i]) {
				chiffres = append(chiffres, s[i])
				i++
				fin = i
				continue
			}
			if estSepCarte(s[i]) && i+1 < len(s) && estChiffre(s[i+1]) {
				i++
				continue
			}
			break
		}
		p = fin
		if !frontiereAvant(s, debut, depart) || !frontiereApres(s, fin) || len(chiffres) < 12 || len(chiffres) > 19 {
			continue
		}
		if !LuhnValide(string(chiffres)) {
			continue
		}
		return Correspondance{Debut: debut, Fin: fin, Valeur: string(chiffres)}, true
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
func DetecterEmail(s []rune) []Correspondance { return toutes(s, chercherEmail) }

func chercherEmail(s []rune, depart int) (Correspondance, bool) {
	for a := depart; a < len(s); a++ {
		if s[a] != '@' {
			continue
		}
		// partie locale : suite maximale à gauche, sans dépasser depart, lue sur 65
		g := a
		for g > depart && a-g <= 64 && carLocal(s[g-1]) {
			g--
		}
		if a-g > 64 || a == g {
			continue
		}
		local := string(s[g:a])
		if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
			continue
		}
		// domaine : suite maximale à droite, lue sur 256
		d := a + 1
		for d < len(s) && d-a-1 <= 255 && carDomaine(s[d]) {
			d++
		}
		if d-a-1 > 255 {
			continue
		}
		fin := d
		if fin > a+1 && (s[fin-1] == '.' || s[fin-1] == '-') {
			fin-- // le point final d'une phrase n'appartient pas au domaine
		}
		domaine := string(s[a+1 : fin])
		labels := strings.Split(domaine, ".")
		if len(labels) < 2 || !reDernierLabel.MatchString(labels[len(labels)-1]) {
			continue
		}
		valide := true
		for _, l := range labels {
			if !reLabelEmail.MatchString(l) {
				valide = false
				break
			}
		}
		if !valide {
			continue
		}
		return Correspondance{Debut: g, Fin: fin, Valeur: local + "@" + strings.ToLower(domaine)}, true
	}
	return Correspondance{}, false
}

// ---------------------------------------------------------------- telephone

// DetecterTelephone applique le détecteur telephone (10.3.6).
func DetecterTelephone(s []rune) []Correspondance { return toutes(s, chercherTelephone) }

func chercherTelephone(s []rune, depart int) (Correspondance, bool) {
	for p := depart; p < len(s); p++ {
		if s[p] != '+' || !frontiereAvant(s, p, depart) {
			continue
		}
		if p+1 >= len(s) || s[p+1] < '1' || s[p+1] > '9' {
			continue
		}
		i, fin := p+2, p+2
		groupe := false
	boucle:
		for i < len(s) {
			r := s[i]
			switch {
			case estChiffre(r):
				i++
				fin = i
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
				i = j + 1 // le groupe est lu sans déplacer fin
			default:
				break boucle
			}
		}
		if !frontiereApres(s, fin) {
			continue
		}
		var chiffres []rune
		for _, r := range s[p+1 : fin] {
			if estChiffre(r) {
				chiffres = append(chiffres, r)
			}
		}
		if len(chiffres) < 8 || len(chiffres) > 15 {
			continue
		}
		return Correspondance{Debut: p, Fin: fin, Valeur: "+" + string(chiffres)}, true
	}
	return Correspondance{}, false
}

// ---------------------------------------------------------------- regex

// DetecterMotif applique un motif nommé (EX-10.10) : correspondances
// successives sans chevauchement (FindAllStringIndex, sémantique
// leftmost-first de RE2), les correspondances vides ignorées.
func DetecterMotif(re *regexp.Regexp, s []rune) []Correspondance {
	texte := string(s)
	idx := make([]int, len(texte)+1)
	k := 0
	for b := range texte {
		idx[b] = k
		k++
	}
	idx[len(texte)] = k
	var out []Correspondance
	for _, loc := range re.FindAllStringIndex(texte, -1) {
		if loc[0] == loc[1] {
			continue
		}
		out = append(out, Correspondance{Debut: idx[loc[0]], Fin: idx[loc[1]], Valeur: texte[loc[0]:loc[1]]})
	}
	return out
}
