package horodatage

// genTime à sa pleine précision (EX-9.13, EX-9.15 règle 1) : la fraction
// de seconde d'un GeneralizedTime n'a pas de longueur bornée ; elle est
// gardée telle qu'écrite pour les comparaisons et pour gen_time et
// upper_bound (EX-9.19).

import (
	"fmt"
	"math/big"
	"strings"
	"time"
)

// instant : un instant UTC de précision arbitraire.
type instant struct {
	// t : l'instant tronqué à la nanoseconde.
	t time.Time
	// frac : chiffres de la fraction de seconde, sans zéro final ("" sans
	// fraction).
	frac string
}

// lireGenTime applique la règle 1 d'EX-9.15 : `AAAAMMJJhhmmss[.f…]Z`,
// fraction sans zéro final, date existante, années 0000 à 9999.
func lireGenTime(b []byte) (instant, bool) {
	if len(b) < 15 || b[len(b)-1] != 'Z' {
		return instant{}, false
	}
	an, ok := chiffres(b[0:4])
	if !ok {
		return instant{}, false
	}
	t, ok := dateHeure(an, b[4:14])
	if !ok {
		return instant{}, false
	}
	reste := b[14 : len(b)-1]
	frac := ""
	if len(reste) > 0 {
		if reste[0] != '.' || len(reste) < 2 {
			return instant{}, false
		}
		for _, c := range reste[1:] {
			if c < '0' || c > '9' {
				return instant{}, false
			}
		}
		frac = string(reste[1:])
		if frac[len(frac)-1] == '0' {
			return instant{}, false
		}
	}
	return nouvelInstant(t, frac), true
}

// nouvelInstant construit un instant à partir de la seconde et de la
// fraction.
func nouvelInstant(seconde time.Time, frac string) instant {
	ns := 0
	for i := 0; i < 9; i++ {
		ns *= 10
		if i < len(frac) {
			ns += int(frac[i] - '0')
		}
	}
	return instant{t: seconde.Add(time.Duration(ns)), frac: frac}
}

// comparer rend -1, 0 ou 1 selon que l'instant précède, égale ou suit u.
func (a instant) comparer(u time.Time) int {
	if c := a.t.Compare(u); c != 0 {
		return c
	}
	if len(a.frac) > 9 && strings.Trim(a.frac[9:], "0") != "" {
		return 1
	}
	return 0
}

// texte : format d'EX-6.11, fraction conservée.
func (a instant) texte() string {
	t := a.t.UTC()
	s := fmt.Sprintf("%04d-%02d-%02dT%02d:%02d:%02d", t.Year(), int(t.Month()), t.Day(), t.Hour(), t.Minute(), t.Second())
	if a.frac != "" {
		s += "." + a.frac
	}
	return s + "Z"
}

// plusMicros ajoute une durée en microsecondes (genTime + accuracy).
func (a instant) plusMicros(us int64) instant {
	f := a.frac
	for len(f) < 6 {
		f += "0"
	}
	premiers := 0
	for _, c := range f[:6] {
		premiers = premiers*10 + int(c-'0')
	}
	total := int64(premiers) + us%1_000_000
	secondes := us/1_000_000 + total/1_000_000
	total %= 1_000_000
	frac := strings.TrimRight(fmt.Sprintf("%06d", total)+f[6:], "0")
	base := a.t.Add(-time.Duration(a.t.Nanosecond())).Add(time.Duration(secondes) * time.Second)
	return nouvelInstant(base, frac)
}

// limiteGenTime : genTime + accuracy ne dépasse pas cet instant
// (EX-9.15, règle 2).
var limiteGenTime = time.Date(9999, 12, 31, 23, 59, 59, 999_999_000, time.UTC)

// precision : accuracy bornée par la règle 2 d'EX-9.15.
type precision struct {
	s, ms, us *int64
}

func (p precision) micros() int64 {
	var t int64
	if p.s != nil {
		t += *p.s * 1_000_000
	}
	if p.ms != nil {
		t += *p.ms * 1_000
	}
	if p.us != nil {
		t += *p.us
	}
	return t
}

// borner applique la règle 2 d'EX-9.15 à une accuracy lue sans limite de
// taille par T-1.
func borner(p *precisionLue) (precision, *defaut) {
	var out precision
	champ := func(b []byte, min, max int64, nom string) (*int64, *defaut) {
		if b == nil {
			return nil, nil
		}
		v := valeurEntier(b)
		if v.Cmp(big.NewInt(min)) < 0 || v.Cmp(big.NewInt(max)) > 0 {
			return nil, defF("accuracy.%s hors de %d…%d (EX-9.15)", "accuracy.%s outside %d…%d (EX-9.15)", nom, min, max)
		}
		n := v.Int64()
		return &n, nil
	}
	var d *defaut
	if out.s, d = champ(p.s, 0, 86400, "seconds"); d != nil {
		return out, d
	}
	if out.ms, d = champ(p.ms, 1, 999, "millis"); d != nil {
		return out, d
	}
	if out.us, d = champ(p.us, 1, 999, "micros"); d != nil {
		return out, d
	}
	return out, nil
}
