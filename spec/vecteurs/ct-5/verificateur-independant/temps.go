// Instants : millisecondes UNIX et format RFC 3339 UTC à la milliseconde
// (horodatages de CT-1, instants des traces de CT-5 §8.10).

package main

import (
	"fmt"
	"regexp"
	"strconv"
	"time"
)

var reInstant = regexp.MustCompile(`^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,3}))?Z$`)

// Ms rend les millisecondes UNIX d'un instant RFC 3339 UTC, avec ou sans
// fraction (1 à 3 chiffres) ; refuse une date inexistante.
func Ms(texte string) (int64, error) {
	m := reInstant.FindStringSubmatch(texte)
	if m == nil {
		return 0, fmt.Errorf("instant RFC 3339 UTC attendu, reçu %q", texte)
	}
	n := func(s string) int { v, _ := strconv.Atoi(s); return v }
	a, mo, j, h, mi, s := n(m[1]), n(m[2]), n(m[3]), n(m[4]), n(m[5]), n(m[6])
	t := time.Date(a, time.Month(mo), j, h, mi, s, 0, time.UTC)
	if t.Year() != a || int(t.Month()) != mo || t.Day() != j || t.Hour() != h || t.Minute() != mi || t.Second() != s {
		return 0, fmt.Errorf("instant invalide : %s", texte)
	}
	frac := m[7]
	for len(frac) < 3 {
		frac += "0"
	}
	return t.Unix()*1000 + int64(n(frac)), nil
}

// Iso rend l'instant RFC 3339 UTC à la milliseconde (format toISOString).
func Iso(ms int64) string {
	return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z")
}
