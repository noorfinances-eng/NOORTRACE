// Vérifications PR-1 à PR-12 d'un paquet réviseur (CT-8 §13.8, EX-13.30 à
// EX-13.34), état du paquet, avertissements (13.9, EX-13.35) et code de
// retour (EX-13.26), recalculés sur les octets de l'archive sans rien
// écrire.
//
// Ce qui n'est pas recalculé ici, et pourquoi (EX-A.24) : PR-10 est jouée
// en mémoire (la relecture d'un fichier extrait égale les octets que PR-8 a
// comparés au manifeste ; aucun fichier n'est écrit) ; PR-11 n'a d'objet que
// pour un paquet complet, et les vecteurs sont allégés ; PR-12 (AT-1 à AT-4
// de CT-1 §11.4 et CT-7 EX-7.16) relève des vérificateurs de ct-1 et de
// ct-7 ; les codes de dossier relèvent de CT-6, que ce module n'exécute pas.

package main

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// VerifPR est le résultat d'une vérification PR-n.
type VerifPR struct {
	ID     string
	Status string // reussi, echoue, non_execute ; "" : hors périmètre
	Reason string // "" pour null
	Detail string
}

// ResultatPaquet est la vérification recalculée d'une archive.
type ResultatPaquet struct {
	Taille    int
	SHA256    string
	Checks    []VerifPR
	Etat      string // intact ou non_conforme
	Entrees   []EntreeTar
	Manifeste *Value
	MSHA256   string
	Lib       []EntreeLib
	ErrLib    error
	ErrBrut   error
}

const racinePaquet = "paquet-reviseur"

var reComposant = regexp.MustCompile(`^[A-Za-z0-9_@+-][A-Za-z0-9._@+-]{0,99}$`)

// ImprimableASCII dit si une chaîne n'a que des octets de 0x20 à 0x7e.
func ImprimableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// DefautNom rend le premier défaut d'un nom complet selon PR-5 (EX-13.32),
// hors unicité, ou "".
func DefautNom(n string) string {
	switch {
	case !ImprimableASCII(n):
		return "caractère hors de l'ASCII imprimable"
	case strings.HasPrefix(n, "/"):
		return "nom absolu"
	}
	comp := strings.Split(n, "/")
	for _, c := range comp {
		if c == ".." {
			return "composant .."
		}
	}
	if comp[0] != racinePaquet {
		return "premier composant différent de paquet-reviseur"
	}
	if len(comp) < 2 || len(comp) > 17 {
		return fmt.Sprintf("%d composants", len(comp))
	}
	for _, c := range comp[1:] {
		if !reComposant.MatchString(c) {
			return fmt.Sprintf("composant %q hors du motif", c)
		}
	}
	if len(n) > 255 {
		return "plus de 255 octets"
	}
	return ""
}

// RoleEmplacement rend le rôle de la table de 13.2 pour un chemin relatif à
// paquet-reviseur/, ou "" si l'emplacement n'est pas prévu (EX-13.2).
func RoleEmplacement(p string) string {
	c := strings.Split(p, "/")
	switch {
	case len(c) == 1 && (p == "LISEZMOI.md" || p == "README.md"):
		return "instructions"
	case len(c) == 3 && c[0] == "dossiers":
		return "dossier"
	case len(c) == 2 && c[0] == "ancres":
		return "ancres"
	case len(c) == 2 && c[0] == "entetes":
		return "entetes"
	case p == "attestation/attestation-signee.json" || p == "attestation/jeu-approbateurs.json":
		return "attestation"
	case len(c) == 2 && c[0] == "pieces":
		return "pieces"
	case len(c) >= 2 && c[0] == "verificateur":
		return "verificateur"
	}
	return ""
}

// EvaluerPaquet applique EX-13.25, pas 2 à 5, à une archive : PR-1 à PR-9
// sur ses octets, puis PR-10 à PR-12 comme dit en tête.
func EvaluerPaquet(a []byte, empreinte string, schema *Schema) ResultatPaquet {
	r := ResultatPaquet{Taille: len(a), SHA256: SHA256Hex(a)}
	r.Lib, r.ErrLib = LireLib(a)
	ids := []string{"PR-1", "PR-2", "PR-3", "PR-4", "PR-5", "PR-6", "PR-7", "PR-8", "PR-9", "PR-10", "PR-11", "PR-12"}
	for _, id := range ids {
		r.Checks = append(r.Checks, VerifPR{ID: id})
	}
	echec := -1
	fixer := func(i int, ok bool, detail string) bool {
		if ok {
			r.Checks[i].Status = "reussi"
		} else {
			r.Checks[i].Status = "echoue"
			echec = i
		}
		r.Checks[i].Detail = detail
		return ok
	}
	etapes := []func(int) bool{
		// PR-1
		func(i int) bool {
			L := len(a)
			return fixer(i, L >= 1024 && L <= 536870912 && L%512 == 0, fmt.Sprintf("%d octets, %d blocs", L, L/512))
		},
		// PR-2
		func(i int) bool {
			if empreinte == "" {
				r.Checks[i].Status, r.Checks[i].Reason = "non_execute", "empreinte_non_fournie"
				return true
			}
			e := strings.ToLower(empreinte)
			if !strings.HasPrefix(e, "0x") {
				e = "0x" + e
			}
			return fixer(i, e == r.SHA256, "SHA-256 "+r.SHA256)
		},
		// PR-3
		func(i int) bool {
			r.Entrees, r.ErrBrut = LireBrut(a)
			if r.ErrBrut != nil {
				return fixer(i, false, r.ErrBrut.Error())
			}
			return fixer(i, true, fmt.Sprintf("%d entrées ustar bien formées", len(r.Entrees)))
		},
		// PR-4
		func(i int) bool {
			for _, e := range r.Entrees {
				if e.Typeflag != '0' || e.Linkname != "" {
					return fixer(i, false, fmt.Sprintf("%s : type %q, lien %q", e.NomComplet(), e.Typeflag, e.Linkname))
				}
			}
			return fixer(i, true, "fichiers ordinaires seulement")
		},
		// PR-5
		func(i int) bool {
			vus := map[string]bool{}
			minus := map[string]bool{}
			for _, e := range r.Entrees {
				n := e.NomComplet()
				if d := DefautNom(n); d != "" {
					return fixer(i, false, n+" : "+d)
				}
				if vus[n] {
					return fixer(i, false, n+" : nom en double")
				}
				if minus[strings.ToLower(n)] {
					return fixer(i, false, n+" : nom en double après passage en minuscules")
				}
				vus[n], minus[strings.ToLower(n)] = true, true
			}
			for n := range vus {
				for m := range vus {
					if strings.HasPrefix(m, n+"/") {
						return fixer(i, false, n+" : répertoire d'un autre nom")
					}
				}
			}
			return fixer(i, true, fmt.Sprintf("%d noms relatifs sous paquet-reviseur/, uniques", len(r.Entrees)))
		},
		// PR-6
		func(i int) bool {
			var tailles []int64
			for k, e := range r.Entrees {
				h := e.Entete
				n := e.NomComplet()
				if k > 0 && !(r.Entrees[k-1].NomComplet() < n) {
					return fixer(i, false, n+" : ordre des noms")
				}
				switch {
				case string(h[100:108]) != "0000644\x00":
					return fixer(i, false, fmt.Sprintf("%s : mode %q", n, h[100:108]))
				case string(h[108:116]) != "0000000\x00" || string(h[116:124]) != "0000000\x00":
					return fixer(i, false, n+" : propriétaire non nul")
				case !toutNul(h[265:345]):
					return fixer(i, false, n+" : uname, gname, devmajor ou devminor non vide")
				case e.Mtime != r.Entrees[0].Mtime:
					return fixer(i, false, n+" : date différente de la première entrée")
				}
				p, nm, ok := Decouper(n)
				if !ok || p != e.Prefix || nm != e.Name {
					return fixer(i, false, n+" : découpage nom/préfixe différent d'EX-13.14")
				}
				tailles = append(tailles, e.Size)
			}
			if L := LongueurArchive(tailles); L != int64(len(a)) {
				return fixer(i, false, fmt.Sprintf("longueur %d au lieu de %d", len(a), L))
			}
			date := time.Unix(r.Entrees[0].Mtime, 0).UTC().Format("2006-01-02T15:04:05.000Z")
			return fixer(i, true, "ordre des noms, mode 0644, propriétaire 0/0, date "+date+" pour toutes les entrées")
		},
		// PR-7
		func(i int) bool {
			var m *EntreeTar
			for k := range r.Entrees {
				if r.Entrees[k].NomComplet() == racinePaquet+"/MANIFESTE.json" {
					m = &r.Entrees[k]
				}
			}
			if m == nil {
				return fixer(i, false, "MANIFESTE.json absent")
			}
			if len(m.Donnees) > 16<<20 {
				return fixer(i, false, "manifeste de plus de 16 Mio")
			}
			v, err := AnalyserJSON(m.Donnees)
			if err != nil {
				return fixer(i, false, "manifeste : "+err.Error())
			}
			if errs := schema.Valider(v); len(errs) > 0 {
				return fixer(i, false, "manifeste non conforme au schéma : "+errs[0])
			}
			files := v.Get("files").Arr
			for k, f := range files {
				p := f.Get("path").Str
				if p == "MANIFESTE.json" {
					return fixer(i, false, "files liste MANIFESTE.json")
				}
				if k > 0 && !(files[k-1].Get("path").Str < p) {
					return fixer(i, false, "files non strictement croissant à "+p)
				}
			}
			dossiers := map[string]bool{}
			for _, d := range v.Get("dossiers").Arr {
				if dossiers[d.Get("path").Str] {
					return fixer(i, false, "chemin de dossier en double : "+d.Get("path").Str)
				}
				dossiers[d.Get("path").Str] = true
			}
			t, err := time.Parse("2006-01-02T15:04:05.000Z", v.Get("created_at").Str)
			if err != nil || t.Unix() != r.Entrees[0].Mtime {
				return fixer(i, false, "created_at différent de la date des entrées")
			}
			r.Manifeste, r.MSHA256 = v, SHA256Hex(m.Donnees)
			return fixer(i, true, fmt.Sprintf("manifeste conforme : %d fichiers, %d dossier(s)", len(files), len(v.Get("dossiers").Arr)))
		},
		// PR-8
		func(i int) bool {
			archive := map[string]EntreeTar{}
			for _, e := range r.Entrees {
				n := strings.TrimPrefix(e.NomComplet(), racinePaquet+"/")
				if n != "MANIFESTE.json" {
					archive[n] = e
				}
			}
			var ecarts []string
			declares := map[string]bool{}
			for _, f := range r.Manifeste.Get("files").Arr {
				p := f.Get("path").Str
				declares[p] = true
				e, ok := archive[p]
				if !ok {
					ecarts = append(ecarts, p+" : déclaré, absent de l'archive")
					continue
				}
				if sz, _ := f.Get("size").Entier(); sz != e.Size {
					ecarts = append(ecarts, fmt.Sprintf("%s : %d octets au lieu de %d", p, e.Size, sz))
				}
				if h := SHA256Hex(e.Donnees); h != f.Get("sha256").Str {
					ecarts = append(ecarts, fmt.Sprintf("%s : SHA-256 %s au lieu de %s", p, h, f.Get("sha256").Str))
				}
			}
			for _, e := range r.Entrees {
				n := strings.TrimPrefix(e.NomComplet(), racinePaquet+"/")
				if n != "MANIFESTE.json" && !declares[n] {
					ecarts = append(ecarts, n+" : présent, non déclaré")
				}
			}
			return fixer(i, len(ecarts) == 0, strings.Join(ecarts, " ; "))
		},
		// PR-9
		func(i int) bool {
			m := r.Manifeste
			roles := map[string]string{}
			for _, f := range m.Get("files").Arr {
				p, role := f.Get("path").Str, f.Get("role").Str
				roles[p] = role
				if RoleEmplacement(p) != role {
					return fixer(i, false, fmt.Sprintf("%s : rôle %s, emplacement %q", p, role, RoleEmplacement(p)))
				}
			}
			if roles["LISEZMOI.md"] == "" || roles["README.md"] == "" {
				return fixer(i, false, "LISEZMOI.md ou README.md absent")
			}
			declares := map[string]bool{}
			designes := map[string]bool{}
			for _, d := range m.Get("dossiers").Arr {
				p := d.Get("path").Str
				declares[p] = true
				if roles[p+"/dossier.json"] != "dossier" {
					return fixer(i, false, p+" : dossier.json absent")
				}
				for _, cle := range []string{"anchors", "bitcoin_headers"} {
					x := d.Get(cle)
					if x.EstNull() {
						continue
					}
					attendu := map[string]string{"anchors": "ancres", "bitcoin_headers": "entetes"}[cle]
					if roles[x.Str] != attendu {
						return fixer(i, false, fmt.Sprintf("%s : %s %s n'est pas un fichier de rôle %s", p, cle, x.Str, attendu))
					}
					designes[x.Str] = true
				}
			}
			att := m.Get("attestation")
			nAtt := 0
			for p, role := range roles {
				switch role {
				case "dossier":
					c := strings.Split(p, "/")
					if !declares[c[0]+"/"+c[1]] {
						return fixer(i, false, p+" : sous aucun dossier déclaré")
					}
				case "ancres", "entetes":
					if !designes[p] {
						return fixer(i, false, p+" : désigné par aucun dossier")
					}
				case "attestation":
					nAtt++
					if att.EstNull() {
						return fixer(i, false, p+" : attestation nulle")
					}
				case "verificateur":
					if m.Get("verifier").EstNull() {
						return fixer(i, false, p+" : vérificateur nul")
					}
				}
			}
			if !att.EstNull() && (roles[att.Get("signed").Str] != "attestation" || roles[att.Get("approver_set").Str] != "attestation" || nAtt != 2) {
				return fixer(i, false, "fichiers d'attestation différents des deux que nomme attestation")
			}
			if v := m.Get("verifier"); !v.EstNull() {
				for _, cle := range []string{"tool", "dossier_verifier"} {
					if roles[v.Get(cle).Str] != "verificateur" {
						return fixer(i, false, "verifier."+cle+" absent")
					}
				}
			}
			return fixer(i, true, "cohérence interne")
		},
		// PR-10 : jouée en mémoire (voir l'en-tête).
		func(i int) bool {
			return fixer(i, true, "extraction jouée en mémoire : relecture égale à PR-8")
		},
		// PR-11
		func(i int) bool {
			if r.Manifeste.Get("verifier").EstNull() {
				r.Checks[i].Status, r.Checks[i].Reason, r.Checks[i].Detail = "non_execute", "sans_objet", "aucun vérificateur joint"
				return true
			}
			r.Checks[i].Detail = "paquet complet : comparaison à l'outil exécuté hors périmètre"
			return true
		},
		// PR-12
		func(i int) bool {
			if r.Manifeste.Get("attestation").EstNull() {
				r.Checks[i].Status, r.Checks[i].Reason, r.Checks[i].Detail = "non_execute", "sans_objet", "aucune attestation jointe"
				return true
			}
			r.Checks[i].Detail = "AT-1 à AT-4 : vérificateurs de ct-1 et de ct-7"
			return true
		},
	}
	for i, f := range etapes {
		if echec >= 0 {
			r.Checks[i].Status, r.Checks[i].Reason, r.Checks[i].Detail = "non_execute", "prerequis_en_echec", "une vérification précédente a échoué"
			continue
		}
		f(i) // un échec de PR-2 arrête aussi tout : rien d'autre n'est lu (EX-13.31)
	}
	r.Etat = "intact"
	for _, c := range r.Checks[:9] {
		if c.Status == "echoue" {
			r.Etat = "non_conforme"
		}
	}
	return r
}

// Avertissements rend AV-PR-1 à AV-PR-4 dans l'ordre de la table de 13.9.
// pr12 est le statut de PR-12 (hors périmètre ici : il est fourni).
func Avertissements(r ResultatPaquet, ancresOption bool, pr11, pr12 string) []string {
	if r.Etat != "intact" {
		return nil
	}
	var out []string
	if pr11 == "echoue" {
		out = append(out, "AV-PR-1")
	}
	if pr12 == "echoue" {
		out = append(out, "AV-PR-2")
	}
	avec, sans := false, false
	for _, d := range r.Manifeste.Get("dossiers").Arr {
		if d.Get("anchors").EstNull() {
			sans = true
		} else {
			avec = true
		}
	}
	if !ancresOption && avec {
		out = append(out, "AV-PR-3")
	}
	if !ancresOption && sans {
		out = append(out, "AV-PR-4")
	}
	return out
}

// CodeRetour rend le code d'EX-13.26 : 4 pour un paquet non conforme ;
// sinon, d'après les codes des dossiers, priorité 1, puis 2, 3, 0.
func CodeRetour(etat string, codesDossiers []int64) int64 {
	if etat != "intact" {
		return 4
	}
	vu := map[int64]bool{}
	for _, c := range codesDossiers {
		vu[c] = true
	}
	for _, c := range []int64{1, 2, 3} {
		if vu[c] {
			return c
		}
	}
	return 0
}
