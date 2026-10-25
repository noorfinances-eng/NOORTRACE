// Famille « format » : forme des fichiers des vecteurs (EX-A.1) et index
// INDEX.md.
//
// Les réponses JSON-RPC brutes (bloc-, recu-, certificat-) sont « écrites
// telles que reçues » (CP-6) et les copies de chain/config/alloc-dev.json
// sont « le document de genèse publié » (RG-17) : elles ne suivent pas
// JSON.stringify et sont contrôlées par leur SHA-256 ailleurs.

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// FamilleFormat vérifie EX-A.1 sur chaque fichier JSON des vecteurs.
func (c *Ctx) FamilleFormat() {
	f := c.R.F("format")
	var fichiers []string
	filepath.WalkDir(c.Racine, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && d.Name() == "verificateur-independant" {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".json") {
			fichiers = append(fichiers, p)
		}
		return nil
	})
	sort.Strings(fichiers)
	for _, p := range fichiers {
		rel, _ := filepath.Rel(c.Racine, p)
		rel = filepath.ToSlash(rel)
		b, err := os.ReadFile(p)
		if err != nil {
			f.Erreur(rel, "lecture", err, "EX-A.1")
			continue
		}
		v, err := ParseJSON(b)
		if err != nil {
			f.Erreur(rel, "analyse", err, "EX-A.1")
			continue
		}
		if v.Kind == KindObject && v.Get("jsonrpc") != nil {
			_, err := resultatRPC(v)
			f.Vrai(rel, "réponse JSON-RPC brute complète", err == nil && v.Get("id") != nil, "", "CP-6")
			continue
		}
		if filepath.Base(p) == "alloc-dev.json" {
			f.Comparer(rel, "copie octet pour octet de chain/config/alloc-dev.json (SHA-256)", c.Constantes.Get("genesis").Get("sha256").S(), Hex0x(Sha256(b)), "RG-17")
			continue
		}
		s, err := Stringify2(v)
		if err != nil {
			f.Erreur(rel, "JSON.stringify", err, "EX-A.1")
			continue
		}
		f.Vrai(rel, "octets = JSON.stringify(valeur, null, 2) + saut de ligne", string(b) == s+"\n", "", "EX-A.1")
	}
	// INDEX.md : chaque cas de chaque famille y figure.
	idx, err := os.ReadFile(filepath.Join(c.Racine, "INDEX.md"))
	if err != nil {
		f.Erreur("INDEX.md", "lecture", err, "A.3")
		return
	}
	texte := string(idx)
	var familles []string
	for fam := range c.casParFamille {
		familles = append(familles, fam)
	}
	sort.Strings(familles)
	for _, fam := range familles {
		manque := []string{}
		for _, id := range c.casParFamille[fam] {
			if !strings.Contains(texte, "| `"+id+"` |") {
				manque = append(manque, id)
			}
		}
		f.Vrai("INDEX.md", "chaque cas de la famille "+fam+" a sa ligne", len(manque) == 0, strings.Join(manque, ", "), "A.3")
	}
	f.Hors("INDEX.md", "texte des lignes « Attendu »", "document généré, résumé des attendus des fichiers de famille, qui sont confrontés eux-mêmes")
}
