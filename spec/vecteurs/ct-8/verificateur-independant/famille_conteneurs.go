// Famille « conteneurs » (CT-8 §4, annexe A.3). Ce module n'analyse pas le
// YAML (la bibliothèque standard de Go n'en a pas d'analyseur) : les
// vérifications CO-1 à CO-14 elles-mêmes ne sont pas rejouées. Il recalcule
// ce que le texte fixe sans analyse YAML : images.json égal au bloc de 4.1 ;
// valide-rapide.yaml et valide-production.yaml égaux aux blocs de 4.2 et
// 4.3 et à leurs SHA-256 ; valide-production-condenses.yaml égal à
// production.yaml dont chaque image noortrace/* est complétée par
// « @sha256: » suivi de 32 fois « ab » ; le SHA-256 de chaque fichier et
// `all_images_by_digest` (lu ligne à ligne sur les clés `image:`) ; pour
// chaque cas, la vérification qui échoue et son code selon la table d'A.3,
// toutes les autres réussies (« échoue à une seule vérification ») ; la
// chaîne de remplacement de la table présente dans le fichier.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"regexp"
	"strings"
)

var reImage = regexp.MustCompile(`(?m)^(\s+image:\s*)(\S+)\s*$`)

// imagesParCondense dit si chaque valeur de clé image: porte @sha256:.
func imagesParCondense(yaml string) bool {
	m := reImage.FindAllStringSubmatch(yaml, -1)
	if len(m) == 0 {
		return false
	}
	for _, x := range m {
		if !strings.Contains(x[2], "@sha256:") {
			return false
		}
	}
	return true
}

func sha256Nu(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// FamilleConteneurs confronte la famille conteneurs/ au texte.
func FamilleConteneurs(c *Contexte) {
	const f = "conteneurs"
	rep := c.Chemin("conteneurs")
	// 4.1 : description des images.
	if s, err := c.Texte.Section("### 4.1 "); err == nil {
		if bl, err := BlocApres(s, "<!-- schema: conteneurs -->"); err == nil {
			if b, ok := c.LireFichier(filepath.Join(rep, "images.json")); ok {
				c.Rap.Constater(f, "images.json", "égal au bloc de 4.1 (A.3, EX-A.17)", string(b) == bl, "")
				if v, err := AnalyserJSON(b); err == nil {
					c.ValiderSchema(f, "images.json", "conteneurs-v0", "", v)
				}
			}
		}
	}
	// 4.2 et 4.3 : fichiers de référence.
	refs := map[string]string{}
	for _, x := range []struct{ sec, cas string }{{"### 4.2 ", "valide-rapide"}, {"### 4.3 ", "valide-production"}} {
		s, err := c.Texte.Section(x.sec)
		if err != nil {
			c.Rap.Erreur("%v", err)
			continue
		}
		bl, err := BlocApres(s, "Contenu exact")
		if err != nil {
			c.Rap.Erreur("%s : %v", x.sec, err)
			continue
		}
		refs[x.cas] = bl
		sha := regexp.MustCompile("SHA-256\\s+`([0-9a-f]{64})`").FindStringSubmatch(joindre(s))
		b, ok := c.LireFichier(filepath.Join(rep, x.cas+".yaml"))
		if !ok {
			continue
		}
		c.Rap.Constater(f, x.cas, "fichier égal au bloc de "+strings.TrimSpace(strings.TrimPrefix(x.sec, "###")), string(b) == bl, "")
		if sha != nil {
			c.Rap.Comparer(f, x.cas, "SHA-256 imprimé en "+strings.TrimSpace(strings.TrimPrefix(x.sec, "###")), sha[1], sha256Nu(b))
		}
	}
	if p, ok := refs["valide-production"]; ok {
		cond := reImage.ReplaceAllStringFunc(p, func(l string) string {
			m := reImage.FindStringSubmatch(l)
			if strings.HasPrefix(m[2], "noortrace/") {
				return m[1] + m[2] + "@sha256:" + strings.Repeat("ab", 32)
			}
			return l
		})
		if b, ok := c.LireFichier(filepath.Join(rep, "valide-production-condenses.yaml")); ok {
			c.Rap.Constater(f, "valide-production-condenses", "production.yaml, chaque image noortrace/* complétée par @sha256: et 32 fois ab (A.3)", string(b) == cond, "")
		}
	}

	// Table d'A.3.
	secA3, err := c.Texte.Section("### A.3 ")
	if err != nil {
		c.Rap.Erreur("%v", err)
		return
	}
	tab, err := TableEntete(secA3, "Cas", "Base")
	if err != nil {
		c.Rap.Erreur("A.3 : %v", err)
		return
	}
	type ligne struct{ base, rempl, echec string }
	table := map[string]ligne{}
	var ordre []string
	for _, l := range tab.Lignes {
		n := SansCode(l[0])
		table[n] = ligne{l[1], l[2], l[3]}
		ordre = append(ordre, n)
	}
	var noms []string
	for _, nf := range Fichiers(rep, ".attendu.json") {
		cas := strings.TrimSuffix(nf, ".attendu.json")
		noms = append(noms, cas)
		v, b, ok := c.LireJSON(filepath.Join(rep, nf))
		if !ok {
			continue
		}
		c.Forme(f, cas, b)
		c.ValiderSchema(f, cas, "conteneurs-v0", "#/$defs/cas", v)
		y, ok := c.LireFichier(filepath.Join(rep, cas+".yaml"))
		if !ok {
			continue
		}
		att := v.Get("attendu")
		c.Rap.Comparer(f, cas, "file", cas+".yaml", v.Get("file").Str)
		c.Rap.Comparer(f, cas, "attendu.file", cas+".yaml", att.Get("file").Str)
		c.Rap.Comparer(f, cas, "sha256 du fichier", att.Get("sha256").Str, sha256Nu(y))
		var echecs []string
		var codes []string
		for _, ch := range att.Get("checks").Arr {
			if ch.Get("status").Str == "echoue" {
				echecs = append(echecs, ch.Get("id").Str)
				for _, x := range ch.Get("findings").Arr {
					codes = append(codes, x.Get("code").Str)
				}
			}
		}
		if contient(codes, "yaml_invalide") {
			// Le texte ne dit pas ce que vaut all_images_by_digest d'un
			// fichier qui ne s'analyse pas.
			c.Rap.HorsPerimetre(f, cas, "all_images_by_digest (clés image:)", TexteValeur(att.Get("all_images_by_digest")),
				"fichier qui ne s'analyse pas (CO-1 yaml_invalide) : valeur que le texte de CT-8 ne fixe pas")
		} else {
			c.Rap.Comparer(f, cas, "all_images_by_digest (clés image:)", TexteValeur(att.Get("all_images_by_digest")), TexteValeur(VBool(imagesParCondense(string(y)))))
		}
		verdict := "conforme"
		if len(echecs) > 0 {
			verdict = "non_conforme"
		}
		c.Rap.Comparer(f, cas, "verdict (conforme si et seulement si CO-1 à CO-14 réussies)", att.Get("verdict").Str, verdict)
		if strings.HasPrefix(cas, "valide-") {
			c.Rap.Comparer(f, cas, "vérifications en échec (cas valide)", "[]", Liste(echecs))
			c.Rap.HorsPerimetre(f, cas, "CO-1 à CO-14 sur le YAML", "conforme", "analyse YAML non rejouée : la bibliothèque standard de Go n'a pas d'analyseur YAML")
			continue
		}
		l, ok := table[cas]
		if !ok {
			c.Rap.Comparer(f, cas, "cas présent dans la table d'A.3", "présent", "absent")
			continue
		}
		champs := strings.Fields(SansCode(l.echec))
		c.Rap.Comparer(f, cas, "A.3 : seule vérification en échec", "["+champs[0]+"]", Liste(echecs))
		if len(champs) > 1 {
			c.Rap.Constater(f, cas, "A.3 : code "+champs[1], contient(codes, champs[1]), Liste(codes))
		}
		base := map[string]string{"rapide": "valide-rapide", "production": "valide-production"}[l.base]
		if ref, ok := refs[base]; ok {
			c.Rap.Constater(f, cas, "A.3 : fichier différent de sa base ("+l.base+")", string(y) != ref, "")
		}
		for _, m := range reCodeLibre.FindAllStringSubmatch(l.rempl, -1) {
			tok := m[1]
			if strings.Contains(tok, "…") || !strings.ContainsAny(tok, ":/[{") {
				continue
			}
			c.Rap.Constater(f, cas, "A.3 : remplacement « "+tok+" » présent", presentYAML(string(y), tok), "")
		}
		c.Rap.HorsPerimetre(f, cas, "CO-1 à CO-14 sur le YAML", att.Get("verdict").Str, "analyse YAML non rejouée : la bibliothèque standard de Go n'a pas d'analyseur YAML")
	}
	var invalides []string
	for _, n := range noms {
		if !strings.HasPrefix(n, "valide-") {
			invalides = append(invalides, n)
		}
	}
	c.Rap.Comparer(f, "ct-8/conteneurs", "cas invalides = lignes de la table d'A.3", Liste(ordre), Liste(trierCas(invalides, ordre)))
}

var reCodeLibre = regexp.MustCompile("`([^`]+)`")

var reFlux = regexp.MustCompile(`^([A-Za-z_]+): \[([^\]]*)\]$`)

// presentYAML dit si un fragment de la table d'A.3 figure dans le fichier,
// tel quel ou, pour une liste en forme courte « clé: [a, b] », dans la forme
// en blocs équivalente (« clé: » puis une ligne « - a », « - b »).
func presentYAML(y, tok string) bool {
	if strings.Contains(y, tok) {
		return true
	}
	m := reFlux.FindStringSubmatch(tok)
	if m == nil {
		return false
	}
	lignes := strings.Split(y, "\n")
	for i, l := range lignes {
		if strings.TrimSpace(l) != m[1]+":" {
			continue
		}
		ok := true
		for k, el := range strings.Split(m[2], ",") {
			if i+1+k >= len(lignes) || strings.TrimSpace(lignes[i+1+k]) != "- "+strings.TrimSpace(el) {
				ok = false
			}
		}
		if ok {
			return true
		}
	}
	return false
}
