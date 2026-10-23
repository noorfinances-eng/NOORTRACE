// Horodatages (CT-1 §3) : RFC 3339, UTC, exactement trois décimales, suffixe
// Z ; la date doit exister dans le calendrier grégorien proleptique.
// Toute comparaison porte sur l'instant décodé, en millisecondes.

package main

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"time"
)

var reHorodatage = regexp.MustCompile(`^([0-9]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])\.([0-9]{3})Z$`)

// Instant est un instant en millisecondes depuis 1970-01-01T00:00:00.000Z.
type Instant int64

// LireInstant décode un horodatage CT-1 ; une date inexistante (30 février)
// est refusée, jamais décalée.
func LireInstant(s string) (Instant, error) {
	if !reHorodatage.MatchString(s) {
		return 0, fmt.Errorf("horodatage hors du format CT-1 §3 : %q", s)
	}
	t, err := time.Parse("2006-01-02T15:04:05.000Z07:00", s)
	if err != nil {
		return 0, fmt.Errorf("horodatage %q : %v", s, err)
	}
	if t.UTC().Format("2006-01-02T15:04:05.000Z") != s {
		return 0, fmt.Errorf("horodatage %q : date inexistante", s)
	}
	return Instant(t.UnixMilli()), nil
}

// String écrit l'instant au format CT-1 §3.
func (i Instant) String() string {
	return time.UnixMilli(int64(i)).UTC().Format("2006-01-02T15:04:05.000Z")
}

// SHA256Etiquette rend SHA-256 des octets UTF-8 d'une étiquette (constantes
// synthétiques de CT-3 annexe A.2).
func SHA256Etiquette(e string) []byte {
	s := sha256.Sum256([]byte(e))
	return s[:]
}
