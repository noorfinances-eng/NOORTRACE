// Lecture d'une archive de paquet réviseur (CT-8 §13.4) de deux façons
// indépendantes : une lecture brute des blocs de 512 octets selon EX-13.14
// et EX-13.31 (PR-3), écrite ici, et la lecture de archive/tar de la
// bibliothèque standard. EX-A.24 exige que les deux s'accordent sur chaque
// entrée que archive/tar rend.

package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Hex0x rend « 0x » suivi de l'écriture hexadécimale minuscule.
func Hex0x(b []byte) string { return "0x" + hex.EncodeToString(b) }

// SHA256Hex rend le SHA-256 d'octets, en « 0x… ».
func SHA256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return Hex0x(h[:])
}

// EntreeTar est une entrée lue par la lecture brute.
type EntreeTar struct {
	Offset   int    // octet de l'en-tête dans l'archive
	Entete   []byte // les 512 octets de l'en-tête
	Name     string // champ name, jusqu'au premier NUL
	Prefix   string // champ prefix, jusqu'au premier NUL
	Mode     int64
	UID, GID int64
	Size     int64
	Mtime    int64
	Typeflag byte
	Linkname string
	Uname    string
	Gname    string
	Devmajor []byte // champ brut
	Devminor []byte // champ brut
	Donnees  []byte
}

// NomComplet rend le nom complet d'EX-13.32 (PR-5) : prefix, « / », name
// quand prefix n'est pas vide ; name sinon.
func (e EntreeTar) NomComplet() string {
	if e.Prefix != "" {
		return e.Prefix + "/" + e.Name
	}
	return e.Name
}

// champTexte rend le texte d'un champ jusqu'au premier NUL, et dit si le
// champ n'a que des NUL après ce premier NUL (EX-13.31).
func champTexte(b []byte) (string, bool) {
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return string(b), true
	}
	for _, c := range b[i:] {
		if c != 0 {
			return string(b[:i]), false
		}
	}
	return string(b[:i]), true
}

// champOctal lit un champ numérique de la forme exacte d'EX-13.31 :
// chiffres octaux sur la largeur du champ moins un, suivis de NUL.
func champOctal(b []byte) (int64, bool) {
	if b[len(b)-1] != 0 {
		return 0, false
	}
	var n int64
	for _, c := range b[:len(b)-1] {
		if c < '0' || c > '7' {
			return 0, false
		}
		n = n*8 + int64(c-'0')
	}
	return n, true
}

func toutNul(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// SommeControle rend la somme des 512 octets de l'en-tête, le champ chksum
// (octets 148 à 155) compté comme huit espaces (EX-13.14).
func SommeControle(h []byte) int64 {
	var s int64
	for i, c := range h {
		if i >= 148 && i < 156 {
			s += ' '
		} else {
			s += int64(c)
		}
	}
	return s
}

// LireBrut lit les blocs dans l'ordre depuis l'octet 0 et applique les
// règles de PR-3 (EX-13.31). Il rend les entrées lues et, en cas d'échec,
// le premier défaut.
func LireBrut(a []byte) ([]EntreeTar, error) {
	var out []EntreeTar
	pos := 0
	for {
		if pos+512 > len(a) {
			return out, fmt.Errorf("archive sans fin : bloc à l'octet %d incomplet ou absent", pos)
		}
		h := a[pos : pos+512]
		if toutNul(h) {
			if !toutNul(a[pos:]) {
				return out, fmt.Errorf("octets non nuls après le bloc de fin de l'octet %d", pos)
			}
			if len(out) == 0 {
				return out, errors.New("aucune entrée")
			}
			if len(out) > 10001 {
				return out, fmt.Errorf("%d entrées, au plus 10 001", len(out))
			}
			return out, nil
		}
		e := EntreeTar{Offset: pos, Entete: h}
		if string(h[257:263]) != "ustar\x00" {
			return out, fmt.Errorf("en-tête de l'octet %d : magic %q", pos, h[257:263])
		}
		if string(h[263:265]) != "00" {
			return out, fmt.Errorf("en-tête de l'octet %d : version %q", pos, h[263:265])
		}
		ck := h[148:156]
		v, ok := champOctal(ck[:7])
		if !ok || ck[7] != ' ' {
			return out, fmt.Errorf("en-tête de l'octet %d : chksum %q hors de la forme d'EX-13.14", pos, ck)
		}
		if v != SommeControle(h) {
			return out, fmt.Errorf("en-tête de l'octet %d : chksum %d au lieu de %d", pos, v, SommeControle(h))
		}
		num := []struct {
			nom  string
			d, f int
			dst  *int64
		}{{"mode", 100, 108, &e.Mode}, {"uid", 108, 116, &e.UID}, {"gid", 116, 124, &e.GID}, {"size", 124, 136, &e.Size}, {"mtime", 136, 148, &e.Mtime}}
		for _, c := range num {
			n, ok := champOctal(h[c.d:c.f])
			if !ok {
				return out, fmt.Errorf("en-tête de l'octet %d : champ %s %q hors de la forme d'EX-13.31", pos, c.nom, h[c.d:c.f])
			}
			*c.dst = n
		}
		txt := []struct {
			nom  string
			d, f int
			dst  *string
		}{{"name", 0, 100, &e.Name}, {"linkname", 157, 257, &e.Linkname}, {"uname", 265, 297, &e.Uname}, {"gname", 297, 329, &e.Gname}, {"prefix", 345, 500, &e.Prefix}}
		for _, c := range txt {
			s, ok := champTexte(h[c.d:c.f])
			if !ok {
				return out, fmt.Errorf("en-tête de l'octet %d : champ %s non nul après son premier NUL", pos, c.nom)
			}
			*c.dst = s
		}
		for _, c := range []struct {
			nom  string
			d, f int
		}{{"devmajor", 329, 337}, {"devminor", 337, 345}} {
			if _, ok := champTexte(h[c.d:c.f]); !ok {
				return out, fmt.Errorf("en-tête de l'octet %d : champ %s non nul après son premier NUL", pos, c.nom)
			}
		}
		e.Devmajor, e.Devminor = h[329:337], h[337:345]
		if !toutNul(h[500:512]) {
			return out, fmt.Errorf("en-tête de l'octet %d : octets 500 à 511 non nuls", pos)
		}
		e.Typeflag = h[156]
		pos += 512
		bour := (e.Size + 511) / 512 * 512
		if int64(pos)+bour > int64(len(a)) {
			return out, fmt.Errorf("entrée %q : données hors de l'archive", e.NomComplet())
		}
		e.Donnees = a[pos : pos+int(e.Size)]
		if !toutNul(a[pos+int(e.Size) : pos+int(bour)]) {
			return out, fmt.Errorf("entrée %q : bourrage non nul", e.NomComplet())
		}
		pos += int(bour)
		out = append(out, e)
	}
}

// EntreeLib est une entrée rendue par archive/tar.
type EntreeLib struct {
	Hdr     *tar.Header
	Donnees []byte
}

// LireLib lit l'archive par archive/tar ; il rend les entrées lues avant
// la première erreur, et cette erreur.
func LireLib(a []byte) ([]EntreeLib, error) {
	r := tar.NewReader(bytes.NewReader(a))
	var out []EntreeLib
	for {
		h, err := r.Next()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		d, err := io.ReadAll(r)
		if err != nil {
			return out, err
		}
		out = append(out, EntreeLib{h, d})
	}
}

// AccordLectures compare chaque entrée que archive/tar rend à l'entrée de
// même rang de la lecture brute : nom, type, taille, mode, propriétaires,
// noms de propriétaires, date, lien, périphériques, données. Il rend la
// liste des écarts.
func AccordLectures(brut []EntreeTar, lib []EntreeLib) []string {
	var ecarts []string
	for i, l := range lib {
		if i >= len(brut) {
			ecarts = append(ecarts, fmt.Sprintf("entrée %d (%q) rendue par archive/tar, absente de la lecture brute", i, l.Hdr.Name))
			continue
		}
		b := brut[i]
		h := l.Hdr
		add := func(champ string, x, y any) {
			if fmt.Sprint(x) != fmt.Sprint(y) {
				ecarts = append(ecarts, fmt.Sprintf("entrée %d, %s : archive/tar %v, lecture brute %v", i, champ, x, y))
			}
		}
		add("nom", h.Name, b.NomComplet())
		add("type", string(rune(h.Typeflag)), string(rune(b.Typeflag)))
		add("taille", h.Size, b.Size)
		add("mode", fmt.Sprintf("%o", h.Mode), fmt.Sprintf("%o", b.Mode))
		add("uid", h.Uid, b.UID)
		add("gid", h.Gid, b.GID)
		add("uname", h.Uname, b.Uname)
		add("gname", h.Gname, b.Gname)
		add("date", h.ModTime.Unix(), b.Mtime)
		add("lien", h.Linkname, b.Linkname)
		dmaj, _ := champTexte(b.Devmajor)
		dmin, _ := champTexte(b.Devminor)
		add("devmajor", h.Devmajor, octalOuZero(dmaj))
		add("devminor", h.Devminor, octalOuZero(dmin))
		add("format", h.Format.String(), tar.FormatUSTAR.String())
		if !bytes.Equal(l.Donnees, b.Donnees) {
			ecarts = append(ecarts, fmt.Sprintf("entrée %d (%q) : données différentes", i, h.Name))
		}
	}
	return ecarts
}

func octalOuZero(s string) int64 {
	var n int64
	for _, c := range strings.TrimSpace(s) {
		if c < '0' || c > '7' {
			return -1
		}
		n = n*8 + int64(c-'0')
	}
	return n
}

// Decouper rend le découpage nom/préfixe d'EX-13.14 d'un nom complet :
// prefix vide pour un nom de 100 octets au plus ; sinon le plus long début
// qui s'arrête avant un « / » et tient en 155 octets, le reste devant être
// non vide et tenir en 100 octets.
func Decouper(nom string) (prefix, name string, ok bool) {
	if len(nom) <= 100 {
		return "", nom, true
	}
	i := len(nom) - 1
	if i > 155 {
		i = 155
	}
	for ; i > 0; i-- {
		if nom[i] == '/' {
			break
		}
	}
	if i == 0 {
		return "", "", false
	}
	p, r := nom[:i], nom[i+1:]
	if len(r) == 0 || len(r) > 100 {
		return "", "", false
	}
	return p, r, true
}

// LongueurArchive rend L d'EX-13.14 pour des tailles de fichiers données.
func LongueurArchive(tailles []int64) int64 {
	var s int64
	for _, t := range tailles {
		s += 512 + 512*((t+511)/512)
	}
	s += 1024
	return 10240 * ((s + 10239) / 10240)
}
