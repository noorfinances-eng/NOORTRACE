// Parcours des vecteurs de CT-8 (spec/vecteurs/ct-8), famille par famille
// (annexe A). Le module lit, à côté des vecteurs, la spécification
// (../../CT-8-deploiement-et-exploitation.md), les schémas
// (../../schemas/*.schema.json) et, pour les mesures de 9.2 et les entrées
// du paquet (EX-A.11), les vecteurs de ct-1, ct-4, ct-5, ct-6 et ct-7 ; il
// n'écrit rien.

package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Contexte rassemble ce que les familles lisent.
type Contexte struct {
	Racine  string // spec/vecteurs/ct-8
	Spec    string // spec/
	Texte   *Texte
	Schemas map[string]*Schema
	Rap     *Rapport
}

// Chemin rend un chemin sous spec/vecteurs/ct-8.
func (c *Contexte) Chemin(p ...string) string {
	return filepath.Join(append([]string{c.Racine}, p...)...)
}

// LireFichier lit un fichier ; une erreur est consignée.
func (c *Contexte) LireFichier(chemin string) ([]byte, bool) {
	b, err := os.ReadFile(chemin)
	if err != nil {
		c.Rap.Erreur("%s : illisible (%v)", chemin, err)
		return nil, false
	}
	return b, true
}

// LireJSON lit et analyse un fichier JSON.
func (c *Contexte) LireJSON(chemin string) (*Value, []byte, bool) {
	b, ok := c.LireFichier(chemin)
	if !ok {
		return nil, nil, false
	}
	v, err := AnalyserJSON(b)
	if err != nil {
		c.Rap.Erreur("%s : %v", chemin, err)
		return nil, nil, false
	}
	return v, b, true
}

// ValiderSchema confronte une valeur à un schéma ou à l'un de ses $defs.
func (c *Contexte) ValiderSchema(famille, vecteur, schema, ref string, v *Value) {
	s := c.Schemas[schema]
	if s == nil {
		c.Rap.Erreur("schéma %s non chargé", schema)
		return
	}
	sous := s.Racine
	if ref != "" {
		var err error
		if sous, err = s.Sous(ref); err != nil {
			c.Rap.Erreur("%s : %v", schema, err)
			return
		}
	}
	errs := s.ValiderContre(sous, v)
	detail := ""
	if len(errs) > 0 {
		detail = strings.Join(errs, " ; ")
	}
	c.Rap.Constater(famille, vecteur, "conforme à "+schema+ref, len(errs) == 0, detail)
}

// Forme confronte les octets d'un fichier à JSON.stringify(valeur, null, 2)
// suivi d'un saut de ligne (EX-A.1).
func (c *Contexte) Forme(famille, vecteur string, octets []byte) {
	ok, detail := FormeVecteur(octets)
	c.Rap.Constater(famille, vecteur, "forme EX-A.1 (JSON.stringify, deux espaces, saut de ligne final)", ok, detail)
}

// Fichiers rend les noms d'un répertoire qui finissent par suffixe, triés.
func Fichiers(rep, suffixe string) []string {
	es, err := os.ReadDir(rep)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range es {
		if !e.IsDir() && strings.HasSuffix(e.Name(), suffixe) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// schemasCT8 sont les schémas que lisent les familles recalculées.
var schemasCT8 = []string{"conteneurs-v0", "controle-prealable-v0", "dimensionnement-v0", "paquet-reviseur-v0", "proces-verbal-exploitation-v0"}

// VerifierVecteurs parcourt toutes les familles.
func VerifierVecteurs(racine string) *Rapport {
	rap := NouveauRapport(racine)
	abs, err := filepath.Abs(racine)
	if err != nil {
		rap.Erreur("racine %s : %v", racine, err)
		return rap
	}
	c := &Contexte{Racine: abs, Spec: filepath.Join(abs, "..", ".."), Rap: rap, Schemas: map[string]*Schema{}}
	t, err := LireTexte(filepath.Join(c.Spec, "CT-8-deploiement-et-exploitation.md"))
	if err != nil {
		rap.Erreur("spécification CT-8 illisible : %v", err)
		return rap
	}
	c.Texte = t
	for _, n := range schemasCT8 {
		b, ok := c.LireFichier(filepath.Join(c.Spec, "schemas", n+".schema.json"))
		if !ok {
			return rap
		}
		s, err := ChargerSchema(n, b)
		if err != nil {
			rap.Erreur("%v", err)
			return rap
		}
		c.Schemas[n] = s
	}
	FamilleDisposition(c)
	FamilleCoefficients(c)
	FamilleDimensionnement(c)
	FamilleControle(c)
	FamillePaquets(c)
	FamilleConteneurs(c)
	FamilleObservation(c)
	FamilleJournaux(c)
	FamilleConsultations(c)
	FamilleProcesVerbaux(c)
	return rap
}
